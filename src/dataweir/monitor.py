"""Session accounting and volume-anomaly detection.

This is the "monitor" half of the tool. The policy engine answers *may this
query run*; the monitor answers *does this look like the last thousand times*,
and *has this agent now pulled more than its share*.

Baselines are kept per query **shape** (literals stripped), so a report that
normally returns 40 rows is measured against its own history rather than against
some global average.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from .policy import AnomalyConfig, Budgets


def fingerprint(sql: str, dialect: str | None = None) -> str:
    """A stable id for a query's *shape*, ignoring its literal values.

    ``SELECT * FROM t WHERE id = 1`` and ``... WHERE id = 99`` share a
    fingerprint, so their row counts accumulate into one baseline.
    """
    try:
        statement = sqlglot.parse_one(sql, read=dialect)
    except Exception:
        normalized = " ".join(sql.lower().split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    if statement is None:  # pragma: no cover - defensive
        return hashlib.sha256(sql.encode("utf-8")).hexdigest()[:16]

    def strip(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Literal):
            return exp.Literal.string("?")
        return node

    normalized_sql = statement.transform(strip).sql(dialect=dialect, normalize=True).lower()
    return hashlib.sha256(normalized_sql.encode("utf-8")).hexdigest()[:16]


@dataclass
class Baseline:
    """Running mean and variance for one query shape (Welford's algorithm)."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    max_seen: int = 0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        self.max_seen = max(self.max_seen, int(value))

    @property
    def stdev(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))

    def zscore(self, value: float) -> float:
        deviation = self.stdev
        if deviation <= 0:
            # No spread yet: treat any growth over the established level as
            # proportional deviation rather than dividing by zero.
            if self.mean <= 0:
                return 0.0
            return (value - self.mean) / max(self.mean, 1.0)
        return (value - self.mean) / deviation


@dataclass
class _RateWindow:
    """Sliding 60-second counter."""

    events: deque[tuple[float, int]] = field(default_factory=deque)

    def add(self, amount: int, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self.events.append((now, amount))
        self._trim(now)

    def total(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        self._trim(now)
        return sum(amount for _, amount in self.events)

    def _trim(self, now: float) -> None:
        cutoff = now - 60.0
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()


@dataclass
class SessionState:
    """Everything counted for one agent session."""

    agent_id: str
    session_id: str
    started_at: float = field(default_factory=time.time)
    queries: int = 0
    rows: int = 0
    sensitive_rows: int = 0
    blocked: int = 0
    warned: int = 0
    flagged: int = 0
    """Findings raised after rows came back (volume, content, ceilings)."""

    def snapshot(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "queries": self.queries,
            "rows": self.rows,
            "sensitive_rows": self.sensitive_rows,
            "blocked": self.blocked,
            "warned": self.warned,
            "flagged": self.flagged,
            "duration_s": round(time.time() - self.started_at, 3),
        }


@dataclass
class BudgetCheck:
    """The result of testing a projected draw against the budgets."""

    ok: bool
    code: str | None = None
    detail: str = ""
    subject: str = ""


class Monitor:
    """Per-session counters plus per-shape baselines. Thread-safe."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._baselines: dict[tuple[str, str], Baseline] = {}
        self._row_rate: dict[str, _RateWindow] = {}
        self._query_rate: dict[str, _RateWindow] = {}
        self._lock = threading.RLock()

    # -- sessions --------------------------------------------------------

    def session(self, agent_id: str, session_id: str) -> SessionState:
        key = f"{agent_id}:{session_id}"
        with self._lock:
            state = self._sessions.get(key)
            if state is None:
                state = SessionState(agent_id=agent_id, session_id=session_id)
                self._sessions[key] = state
            return state

    def sessions(self) -> list[SessionState]:
        with self._lock:
            return list(self._sessions.values())

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._baselines.clear()
            self._row_rate.clear()
            self._query_rate.clear()

    # -- budgets ---------------------------------------------------------

    def check_budgets(
        self,
        agent_id: str,
        session_id: str,
        budgets: Budgets,
        projected_rows: int = 0,
    ) -> BudgetCheck:
        """Test the budgets *before* running a query.

        ``projected_rows`` is the ceiling the query could return, so an agent
        that is already at 4,900 of 5,000 rows cannot fire off one more
        unbounded read and find out afterwards.
        """
        if budgets.is_empty:
            return BudgetCheck(ok=True)

        key = f"{agent_id}:{session_id}"
        state = self.session(agent_id, session_id)

        with self._lock:
            if budgets.queries_per_minute is not None:
                window = self._query_rate.setdefault(key, _RateWindow())
                if window.total() + 1 > budgets.queries_per_minute:
                    return BudgetCheck(
                        False,
                        "DW007",
                        f"{window.total()} queries in the last 60s exceeds the "
                        f"{budgets.queries_per_minute}/min ceiling",
                        "queries_per_minute",
                    )

            if (
                budgets.rows_per_session is not None
                and state.rows + projected_rows > budgets.rows_per_session
            ):
                return BudgetCheck(
                    False,
                    "DW006",
                    f"{state.rows} rows drawn this session; this query could add "
                    f"{projected_rows}, over the {budgets.rows_per_session}-row budget",
                    "rows_per_session",
                )

            if budgets.rows_per_minute is not None:
                window = self._row_rate.setdefault(key, _RateWindow())
                if window.total() + projected_rows > budgets.rows_per_minute:
                    return BudgetCheck(
                        False,
                        "DW007",
                        f"{window.total()} rows in the last 60s; this query could add "
                        f"{projected_rows}, over the {budgets.rows_per_minute}/min ceiling",
                        "rows_per_minute",
                    )

        return BudgetCheck(ok=True)

    def check_sensitive_budget(
        self, agent_id: str, session_id: str, budgets: Budgets, projected: int
    ) -> BudgetCheck:
        if budgets.sensitive_rows_per_session is None or projected <= 0:
            return BudgetCheck(ok=True)
        state = self.session(agent_id, session_id)
        if state.sensitive_rows + projected > budgets.sensitive_rows_per_session:
            return BudgetCheck(
                False,
                "DW006",
                f"{state.sensitive_rows} classified rows drawn this session; this query "
                f"could add {projected}, over the "
                f"{budgets.sensitive_rows_per_session}-row ceiling",
                "sensitive_rows_per_session",
            )
        return BudgetCheck(ok=True)

    # -- recording -------------------------------------------------------

    def record_query(self, agent_id: str, session_id: str) -> None:
        key = f"{agent_id}:{session_id}"
        state = self.session(agent_id, session_id)
        with self._lock:
            state.queries += 1
            self._query_rate.setdefault(key, _RateWindow()).add(1)

    def record_rows(
        self, agent_id: str, session_id: str, rows: int, sensitive: bool = False
    ) -> None:
        if rows <= 0:
            return
        key = f"{agent_id}:{session_id}"
        state = self.session(agent_id, session_id)
        with self._lock:
            state.rows += rows
            if sensitive:
                state.sensitive_rows += rows
            self._row_rate.setdefault(key, _RateWindow()).add(rows)

    # -- anomalies -------------------------------------------------------

    def baseline(self, agent_id: str, shape: str) -> Baseline:
        with self._lock:
            return self._baselines.setdefault((agent_id, shape), Baseline())

    def observe(self, agent_id: str, shape: str, rows: int) -> None:
        with self._lock:
            self._baselines.setdefault((agent_id, shape), Baseline()).update(rows)

    def check_anomaly(
        self, agent_id: str, shape: str, rows: int, config: AnomalyConfig
    ) -> tuple[bool, str]:
        """Compare a result size against this query shape's own history.

        Returns ``(is_anomalous, explanation)``. Learning happens in
        :meth:`observe`, which the engine calls after every successful read —
        including anomalous ones, so a genuine step-change settles into the new
        normal rather than alerting forever.
        """
        if not config.enabled:
            return False, ""
        if rows < config.absolute_floor:
            return False, ""

        baseline = self.baseline(agent_id, shape)
        if baseline.count < config.min_observations:
            return False, ""

        score = baseline.zscore(rows)
        if score >= config.row_zscore:
            return True, (
                f"{rows} rows against a baseline of {baseline.mean:.0f} "
                f"(sd {baseline.stdev:.0f}, n={baseline.count}, "
                f"previous max {baseline.max_seen}); deviation score {score:.1f} "
                f"exceeds the {config.row_zscore} threshold"
            )
        return False, ""
