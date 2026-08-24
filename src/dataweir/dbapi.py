"""DB-API 2.0 (PEP 249) wrapper — the integration surface.

``guard()`` takes any DB-API connection and returns one that looks and behaves
identically, except that every ``execute()`` is evaluated against policy first
and every row fetched is counted afterwards.

Because it wraps the cursor rather than the ORM, it sees the SQL the database
actually receives — not what the agent claims it is doing. That holds for
sqlite3, psycopg, pymysql, and for SQLAlchemy sessions built on a guarded
connection.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from .decision import Action, Decision
from .engine import Guardrail
from .errors import ResultTruncated
from .policy import Mode, Policy

OnOverflow = Literal["truncate", "raise", "allow"]

#: Rows retained from each result set for content inspection.
SAMPLE_ROWS = 25


class GuardedCursor:
    """A DB-API cursor that enforces policy on execute and counts on fetch."""

    def __init__(
        self,
        cursor: Any,
        guardrail: Guardrail,
        agent_id: str,
        session_id: str,
        dialect: str | None = None,
        on_overflow: OnOverflow = "truncate",
    ) -> None:
        self._cursor = cursor
        self._guardrail = guardrail
        self._agent_id = agent_id
        self._session_id = session_id
        self._dialect = dialect
        self._on_overflow = on_overflow
        self._decision: Decision | None = None
        self._fetched = 0
        self._sample: list[Sequence[Any]] = []
        self._flushed = True

    # -- introspection ---------------------------------------------------

    @property
    def decision(self) -> Decision | None:
        """The decision for the statement currently loaded in this cursor."""
        return self._decision

    @property
    def rows_fetched(self) -> int:
        return self._fetched

    def __getattr__(self, name: str) -> Any:
        # description, rowcount, lastrowid, arraysize, connection, ...
        return getattr(self._cursor, name)

    def __iter__(self) -> GuardedCursor:
        return self

    def __next__(self) -> Any:
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def __enter__(self) -> GuardedCursor:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- execution -------------------------------------------------------

    def execute(self, operation: str, parameters: Any = None, /, *args: Any, **kwargs: Any) -> Any:
        self._flush()
        decision = self._guardrail.evaluate(
            self._agent_id,
            operation,
            params=parameters,
            session_id=self._session_id,
            dialect=self._dialect,
        )
        self._begin(decision)
        sql = decision.effective_sql or operation
        if parameters is None:
            return self._cursor.execute(sql, *args, **kwargs)
        return self._cursor.execute(sql, parameters, *args, **kwargs)

    def executemany(self, operation: str, seq_of_parameters: Any, /, **kwargs: Any) -> Any:
        self._flush()
        batch = list(seq_of_parameters)
        decision = self._guardrail.evaluate(
            self._agent_id,
            operation,
            params=batch[0] if batch else None,
            session_id=self._session_id,
            dialect=self._dialect,
        )
        self._begin(decision)
        sql = decision.effective_sql or operation
        result = self._cursor.executemany(sql, batch, **kwargs)
        # Each parameter set is one write; account for them all.
        self._fetched = len(batch)
        return result

    def executescript(self, script: str) -> Any:
        """sqlite3 convenience method. Evaluated as the multi-statement it is."""
        self._flush()
        decision = self._guardrail.evaluate(
            self._agent_id,
            script,
            session_id=self._session_id,
            dialect=self._dialect,
        )
        self._begin(decision)
        return self._cursor.executescript(script)

    # -- fetching --------------------------------------------------------

    def fetchone(self) -> Any:
        if self._exhausted_by_ceiling():
            return None
        row = self._cursor.fetchone()
        if row is None:
            self._flush()
            return None
        kept = self._consume([row])
        return kept[0] if kept else None

    def fetchmany(self, size: int | None = None) -> list[Any]:
        rows = self._cursor.fetchmany() if size is None else self._cursor.fetchmany(size)
        kept = self._consume(list(rows))
        if not rows:
            self._flush()
        return kept

    def fetchall(self) -> list[Any]:
        rows = list(self._cursor.fetchall())
        kept = self._consume(rows)
        self._flush()
        return kept

    def close(self) -> None:
        self._flush()
        self._cursor.close()

    # -- internals -------------------------------------------------------

    def _begin(self, decision: Decision) -> None:
        self._decision = decision
        self._fetched = 0
        self._sample = []
        self._flushed = False

    def _enforcing(self) -> bool:
        return self._guardrail.policy.mode_for(self._agent_id) is Mode.ENFORCE

    def _ceiling(self) -> int | None:
        if self._decision is None:
            return None
        limit = self._decision.row_limit
        if limit is None or limit < 0:
            return None
        return limit

    def _exhausted_by_ceiling(self) -> bool:
        ceiling = self._ceiling()
        if ceiling is None or not self._enforcing() or self._on_overflow == "allow":
            return False
        return self._fetched >= ceiling

    def _consume(self, rows: list[Any]) -> list[Any]:
        if not rows:
            return rows

        ceiling = self._ceiling()
        kept = rows

        if ceiling is not None and self._enforcing() and self._on_overflow != "allow":
            room = max(0, ceiling - self._fetched)
            if len(rows) > room:
                if self._on_overflow == "raise":
                    self._fetched += len(rows)
                    self._flush()
                    raise ResultTruncated(ceiling, self._decision)
                kept = rows[:room]

        if len(self._sample) < SAMPLE_ROWS:
            self._sample.extend(kept[: SAMPLE_ROWS - len(self._sample)])

        # Count what the database actually produced, not what the agent was
        # allowed to keep — the ceiling check needs to see the overrun.
        self._fetched += len(rows)
        return kept

    def _flush(self) -> None:
        if self._flushed or self._decision is None:
            return
        self._flushed = True
        self._guardrail.record_result(
            self._decision,
            self._fetched,
            sample=self._sample or None,
            session_id=self._session_id,
        )


class GuardedConnection:
    """A DB-API connection whose cursors are guarded."""

    def __init__(
        self,
        connection: Any,
        guardrail: Guardrail,
        agent_id: str,
        session_id: str,
        dialect: str | None = None,
        on_overflow: OnOverflow = "truncate",
    ) -> None:
        self._connection = connection
        self._guardrail = guardrail
        self._agent_id = agent_id
        self._session_id = session_id
        self._dialect = dialect
        self._on_overflow = on_overflow
        self._cursors: list[GuardedCursor] = []

    @property
    def guardrail(self) -> Guardrail:
        return self._guardrail

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def session_stats(self) -> dict[str, Any]:
        """Counters for this connection's session — rows drawn, blocks, warns."""
        return dict(self._guardrail.monitor.session(self._agent_id, self._session_id).snapshot())

    def cursor(self, *args: Any, **kwargs: Any) -> GuardedCursor:
        guarded = GuardedCursor(
            self._connection.cursor(*args, **kwargs),
            self._guardrail,
            self._agent_id,
            self._session_id,
            dialect=self._dialect,
            on_overflow=self._on_overflow,
        )
        self._cursors.append(guarded)
        return guarded

    def execute(self, operation: str, parameters: Any = None, /, *args: Any) -> GuardedCursor:
        """sqlite3-style shortcut: open a cursor and execute on it."""
        cursor = self.cursor()
        cursor.execute(operation, parameters, *args)
        return cursor

    def commit(self) -> Any:
        self._flush_all()
        return self._connection.commit()

    def rollback(self) -> Any:
        self._flush_all()
        return self._connection.rollback()

    def close(self) -> Any:
        self._flush_all()
        return self._connection.close()

    def _flush_all(self) -> None:
        for cursor in self._cursors:
            cursor._flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)

    def __enter__(self) -> GuardedConnection:
        self._connection.__enter__()
        return self

    def __exit__(self, *exc: Any) -> Any:
        self._flush_all()
        return self._connection.__exit__(*exc)


def guard(
    connection: Any,
    policy: Policy,
    agent: str,
    session_id: str | None = None,
    dialect: str | None = None,
    guardrail: Guardrail | None = None,
    on_overflow: OnOverflow = "truncate",
) -> GuardedConnection:
    """Wrap a DB-API connection so every query passes through policy.

    Args:
        connection: any PEP 249 connection (sqlite3, psycopg, pymysql, ...).
        policy: the loaded :class:`~dataweir.policy.Policy`.
        agent: the agent identity this connection acts as. Must have a policy
            entry unless the policy's ``default`` is ``allow``.
        session_id: groups queries for budget accounting. One per agent task.
        dialect: sqlglot dialect name for parsing (``postgres``, ``mysql``,
            ``sqlite``...). Improves analysis accuracy; optional.
        guardrail: reuse an existing engine so sessions, baselines and the audit
            chain are shared across connections.
        on_overflow: what to do when a result exceeds its row ceiling in enforce
            mode — ``truncate`` (default), ``raise``, or ``allow``.

    Returns:
        A :class:`GuardedConnection`. Use it exactly like the original.
    """
    engine = guardrail or Guardrail(policy)
    return GuardedConnection(
        connection,
        engine,
        agent_id=agent,
        session_id=session_id or engine.new_session_id(),
        dialect=dialect,
        on_overflow=on_overflow,
    )


__all__ = ["GuardedConnection", "GuardedCursor", "guard", "Action"]
