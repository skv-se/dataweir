"""The policy engine.

:class:`Guardrail` is the whole decision surface. Everything else in dataweir
either feeds it (analyze, policy) or carries out what it decides (dbapi, audit).

Two entry points, in order:

* :meth:`Guardrail.evaluate` runs **before** the database sees the query.
* :meth:`Guardrail.record_result` runs **after** rows come back, because volume
  and content are only knowable then.
"""

from __future__ import annotations

import re
import uuid
import warnings
from collections.abc import Callable, Iterable, Sequence
from typing import Any

import sqlglot

from .analyze import Operation, StatementFacts, analyze
from .audit import AuditSink, build_sink, redact_params
from .decision import Action, Decision, Finding, Verdict
from .errors import AccessDenied
from .monitor import Monitor, fingerprint
from .policy import AgentPolicy, Grant, Mode, Policy, Severity

DecisionHook = Callable[[Decision], None]

#: How many returned cells to scan for instruction-shaped content per query.
RESULT_SCAN_CELL_LIMIT = 2000


class Guardrail:
    """Evaluates data operations against a :class:`~dataweir.policy.Policy`."""

    def __init__(
        self,
        policy: Policy,
        monitor: Monitor | None = None,
        sink: AuditSink | None = None,
        on_decision: DecisionHook | None = None,
    ) -> None:
        self.policy = policy
        self.monitor = monitor or Monitor()
        self.sink = (
            sink
            if sink is not None
            else build_sink(policy.audit.path, policy.audit.hash_chain, policy.audit.enabled)
        )
        self.on_decision = on_decision
        self._injection_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in policy.injection_patterns
        ]

    # -- public API ------------------------------------------------------

    def evaluate(
        self,
        agent_id: str,
        sql: str,
        params: Any = None,
        session_id: str | None = None,
        dialect: str | None = None,
    ) -> Decision:
        """Decide whether ``sql`` may run, before it runs.

        In ``enforce`` mode a BLOCK verdict raises
        :class:`~dataweir.errors.AccessDenied`. In ``monitor`` mode nothing is
        raised and nothing is rewritten — the query runs exactly as written and
        the verdict is recorded as ``observed``.
        """
        session_id = session_id or "default"
        mode = self.policy.mode_for(agent_id)
        decision = Decision(agent_id=agent_id, mode=mode, sql=sql)

        agent = self.policy.agent(agent_id)
        facts = analyze(sql, dialect=dialect)
        decision.operation = facts.operation.value
        decision.tables = sorted(facts.tables)

        if agent is None:
            if self.policy.default == "deny":
                decision.add(
                    Finding(
                        "DW016",
                        f"no policy entry for agent {agent_id!r}; "
                        "deny-by-default applies to unknown identities",
                        subject=agent_id,
                    )
                )
                return self._finish(decision, facts, session_id, params, agent, None)
            # `default: allow` means exactly that: an unrecognised agent gets an
            # implicit grant over everything. The DWS001 scan check calls this
            # out as critical, which is the right place for that argument.
            agent = AgentPolicy(
                id=agent_id,
                grants=(
                    Grant(
                        tables=("*",),
                        operations=frozenset(Operation),
                    ),
                ),
            )

        if not facts.parsed:
            decision.add(
                Finding("DW014", f"could not parse statement: {facts.parse_error}", subject="sql")
            )
            return self._finish(decision, facts, session_id, params, agent, None)

        self._check_shape(decision, facts)
        applicable = self._check_access(decision, facts, agent)
        self._check_columns(decision, facts, agent, applicable)
        ceiling = self._check_volume(decision, facts, agent, applicable)
        self._check_budgets(decision, agent, session_id, ceiling)

        return self._finish(decision, facts, session_id, params, agent, ceiling)

    def record_result(
        self,
        decision: Decision,
        rows: int,
        sample: Iterable[Sequence[Any]] | None = None,
        session_id: str | None = None,
    ) -> Decision:
        """Account for what actually came back.

        Row ceilings, volume anomalies and instruction-shaped content in the
        data can only be judged here. Findings raised at this point are recorded
        and surfaced to the caller; the rows have already left the database, so
        this stage reports rather than prevents.
        """
        session_id = session_id or "default"
        agent = self.policy.agent(decision.agent_id)
        decision.rows_returned = rows
        post: list[Finding] = []

        if decision.row_limit is not None and decision.row_limit >= 0 and rows > decision.row_limit:
            post.append(
                Finding(
                    "DW005",
                    f"{rows} rows returned against a {decision.row_limit}-row ceiling",
                    subject=",".join(decision.tables),
                )
            )

        if agent is not None and decision.sql:
            shape = fingerprint(decision.sql)
            anomalous, explanation = self._check_anomaly(decision, agent, shape, rows)
            if anomalous:
                post.append(Finding("DW009", explanation, subject=shape))
            self.monitor.observe(decision.agent_id, shape, rows)

        if sample is not None and self.policy.inspect_results:
            hit = self._scan_for_injection(sample)
            if hit is not None:
                column_hint, snippet = hit
                post.append(
                    Finding(
                        "DW013",
                        f"returned data contains instruction-shaped text: {snippet!r}",
                        subject=column_hint,
                    )
                )

        sensitive = any(kind == "sensitive" for kind in decision.classified_columns.values())
        self.monitor.record_rows(decision.agent_id, session_id, rows, sensitive=sensitive)

        if post:
            decision.findings.extend(post)
            self.monitor.session(decision.agent_id, session_id).flagged += len(post)

        # The row count is the whole point of a data-activity monitor, and it is
        # only known here — so a result record is written whenever rows moved,
        # not only when something went wrong. Set `audit.log_results: false` to
        # keep the log to decisions alone.
        if self.policy.audit.log_results and (rows > 0 or post):
            self._write_audit(
                decision,
                event="result",
                extra={"session_id": session_id, "post_execution": bool(post)},
            )

        if post and self.on_decision is not None:
            self.on_decision(decision)

        return decision

    def new_session_id(self) -> str:
        return uuid.uuid4().hex[:16]

    # -- pre-execution checks --------------------------------------------

    def _check_shape(self, decision: Decision, facts: StatementFacts) -> None:
        if facts.statement_count > 1:
            decision.add(
                Finding(
                    "DW010",
                    f"{facts.statement_count} statements submitted in a single call",
                    subject="sql",
                )
            )
        if facts.touches_catalog:
            decision.add(
                Finding(
                    "DW011",
                    "statement reads a schema/catalog object",
                    subject=",".join(sorted(facts.qualified_tables)),
                )
            )
        if facts.operation is Operation.DDL:
            decision.add(
                Finding(
                    "DW012",
                    "statement alters schema (CREATE/DROP/ALTER/TRUNCATE)",
                    subject=",".join(sorted(facts.tables)),
                )
            )

    def _check_access(
        self, decision: Decision, facts: StatementFacts, agent: AgentPolicy
    ) -> dict[str, Grant]:
        """Match each table to a grant. Returns table -> governing grant."""
        applicable: dict[str, Grant] = {}

        for table in sorted(facts.tables):
            table_grants = [grant for grant in agent.grants if grant.covers_table(table)]
            if not table_grants:
                decision.add(
                    Finding(
                        "DW002",
                        f"agent {agent.id!r} has no grant covering table {table!r}",
                        subject=table,
                    )
                )
                continue

            allowed = [g for g in table_grants if g.covers_operation(facts.operation)]
            if not allowed:
                permitted = sorted({op.value for grant in table_grants for op in grant.operations})
                decision.add(
                    Finding(
                        "DW001",
                        f"{facts.operation.value.upper()} on {table!r} is not granted "
                        f"(granted: {', '.join(permitted) or 'none'})",
                        subject=table,
                    )
                )
                continue

            # Most restrictive wins: lowest ceiling governs.
            applicable[table] = min(
                allowed, key=lambda g: g.max_rows if g.max_rows is not None else 1 << 62
            )

        return applicable

    def _check_columns(
        self,
        decision: Decision,
        facts: StatementFacts,
        agent: AgentPolicy,
        applicable: dict[str, Grant],
    ) -> None:
        classification = self.policy.classification

        for qualified in sorted(facts.columns):
            table, _, column = qualified.partition(".")
            grant = applicable.get(table)

            if grant is not None:
                if _matches_any(grant.deny_columns, table, column):
                    decision.add(
                        Finding(
                            "DW003",
                            f"column {qualified!r} is explicitly denied for this agent",
                            subject=qualified,
                        )
                    )
                elif grant.columns != ("*",) and not _matches_any(grant.columns, table, column):
                    decision.add(
                        Finding(
                            "DW003",
                            f"column {qualified!r} is outside the grant's column allow-list",
                            subject=qualified,
                        )
                    )

            kind = classification.classify(qualified)
            if kind is not None:
                decision.classified_columns[qualified] = kind
                if kind == "sensitive":
                    decision.add(
                        Finding(
                            "DW008",
                            f"reads column {qualified!r} classified as sensitive",
                            subject=qualified,
                        )
                    )

        # A `SELECT *` sidesteps column-level policy: it pulls whatever exists,
        # including columns added to the table after the policy was written.
        for table in sorted(facts.star_tables):
            grant = applicable.get(table)
            if grant is not None and (grant.deny_columns or grant.columns != ("*",)):
                decision.add(
                    Finding(
                        "DW003",
                        f"SELECT * on {table!r} would reach columns the grant restricts",
                        subject=table,
                    )
                )
            elif _table_has_classified_columns(self.policy, table):
                decision.add(
                    Finding(
                        "DW015",
                        f"SELECT * on {table!r}, which has classified columns",
                        subject=table,
                    )
                )

    def _check_volume(
        self,
        decision: Decision,
        facts: StatementFacts,
        agent: AgentPolicy,
        applicable: dict[str, Grant],
    ) -> int | None:
        if facts.operation is not Operation.SELECT:
            # An unfiltered UPDATE or DELETE rewrites the whole table, so it is
            # always worth a finding regardless of what the grant says.
            if facts.operation in (Operation.UPDATE, Operation.DELETE) and not facts.has_where:
                decision.add(
                    Finding(
                        "DW017",
                        f"{facts.operation.value.upper()} with no WHERE clause "
                        "affects every row in the table",
                        subject=",".join(sorted(facts.tables)),
                    )
                )
            return None

        if not facts.has_where and any(grant.require_where for grant in applicable.values()):
            decision.add(
                Finding(
                    "DW017",
                    "grant requires a WHERE clause; this SELECT has none",
                    subject=",".join(sorted(facts.tables)),
                )
            )

        ceilings = [grant.max_rows for grant in applicable.values() if grant.max_rows is not None]
        ceiling = min(ceilings) if ceilings else None

        # The ceiling that actually applies is the tighter of what policy allows
        # and what the statement asked for. A result larger than that means
        # something downstream is not honouring either one.
        effective = ceiling
        if facts.limit is not None and facts.limit >= 0:
            effective = facts.limit if ceiling is None else min(ceiling, facts.limit)
        decision.row_limit = effective

        if not facts.is_bounded:
            detail = "SELECT has no LIMIT"
            if ceiling is not None:
                detail += f"; the grant's {ceiling}-row ceiling will be applied"
            decision.add(Finding("DW004", detail, subject=",".join(sorted(facts.tables))))
        elif ceiling is not None and facts.limit is not None and facts.limit > ceiling:
            decision.add(
                Finding(
                    "DW004",
                    f"LIMIT {facts.limit} exceeds the grant's {ceiling}-row ceiling",
                    subject=",".join(sorted(facts.tables)),
                )
            )

        return ceiling

    def _check_budgets(
        self,
        decision: Decision,
        agent: AgentPolicy,
        session_id: str,
        ceiling: int | None,
    ) -> None:
        projected = ceiling if ceiling and ceiling > 0 else 0
        check = self.monitor.check_budgets(
            decision.agent_id, session_id, agent.budgets, projected_rows=projected
        )
        if not check.ok and check.code:
            decision.add(Finding(check.code, check.detail, subject=check.subject))

        if decision.classified_columns:
            sensitive = self.monitor.check_sensitive_budget(
                decision.agent_id, session_id, agent.budgets, projected
            )
            if not sensitive.ok and sensitive.code:
                decision.add(Finding(sensitive.code, sensitive.detail, subject=sensitive.subject))

    def _check_anomaly(
        self, decision: Decision, agent: AgentPolicy, shape: str, rows: int
    ) -> tuple[bool, str]:
        return self.monitor.check_anomaly(decision.agent_id, shape, rows, agent.anomaly)

    # -- verdict and side effects ----------------------------------------

    def _finish(
        self,
        decision: Decision,
        facts: StatementFacts,
        session_id: str,
        params: Any,
        agent: AgentPolicy | None,
        ceiling: int | None,
    ) -> Decision:
        decision.verdict = self._verdict(decision)
        decision.action = self._apply_mode(decision, facts, ceiling)

        self.monitor.record_query(decision.agent_id, session_id)
        state = self.monitor.session(decision.agent_id, session_id)
        if decision.action is Action.BLOCKED:
            state.blocked += 1
        elif decision.action in (Action.WARNED, Action.OBSERVED):
            state.warned += 1

        self._write_audit(
            decision,
            event="decision",
            extra={
                "session_id": session_id,
                "params": redact_params(params, self.policy.audit.redact_params),
            },
        )

        if self.on_decision is not None:
            self.on_decision(decision)

        if decision.action is Action.BLOCKED:
            raise AccessDenied(decision)

        if decision.action in (Action.WARNED, Action.OBSERVED) and decision.mode is Mode.WARN:
            warnings.warn(f"dataweir: {decision.reason()}", DataweirWarning, stacklevel=4)

        return decision

    def _verdict(self, decision: Decision) -> Verdict:
        if not decision.findings:
            return Verdict.ALLOW
        worst = decision.max_severity
        if worst.rank >= self.policy.block_severity.rank:
            return Verdict.BLOCK
        if worst.rank >= Severity.MEDIUM.rank:
            return Verdict.WARN
        return Verdict.ALLOW

    def _apply_mode(self, decision: Decision, facts: StatementFacts, ceiling: int | None) -> Action:
        mode = decision.mode

        if mode is Mode.MONITOR:
            # Monitor mode changes nothing about the query. That is the point:
            # it is safe to install in front of a running agent.
            if decision.verdict is Verdict.BLOCK:
                return Action.OBSERVED
            return Action.WARNED if decision.verdict is Verdict.WARN else Action.ALLOWED

        if mode is Mode.WARN:
            if decision.verdict is Verdict.BLOCK:
                return Action.OBSERVED
            return Action.WARNED if decision.verdict is Verdict.WARN else Action.ALLOWED

        # enforce
        if decision.verdict is Verdict.BLOCK:
            return Action.BLOCKED

        rewritten = self._maybe_apply_ceiling(decision, facts, ceiling)
        if rewritten:
            return Action.REWRITTEN
        return Action.WARNED if decision.verdict is Verdict.WARN else Action.ALLOWED

    def _maybe_apply_ceiling(
        self, decision: Decision, facts: StatementFacts, ceiling: int | None
    ) -> bool:
        """Add or lower a LIMIT so an allowed read cannot become a bulk export."""
        if ceiling is None or ceiling <= 0:
            return False
        if facts.operation is not Operation.SELECT:
            return False
        if facts.limit is not None and 0 <= facts.limit <= ceiling:
            return False

        try:
            statement = sqlglot.parse_one(decision.sql, read=facts.dialect)
            if statement is None or not hasattr(statement, "limit"):
                return False
            decision.effective_sql = statement.limit(ceiling).sql(dialect=facts.dialect)
        except Exception:
            # If the statement cannot be safely rewritten, leave it alone; the
            # post-execution row-ceiling check still applies.
            return False
        return True

    # -- result inspection -----------------------------------------------

    def _scan_for_injection(self, sample: Iterable[Sequence[Any]]) -> tuple[str, str] | None:
        scanned = 0
        for row_index, row in enumerate(sample):
            cells = row.values() if isinstance(row, dict) else row
            try:
                iterator = enumerate(cells)
            except TypeError:  # pragma: no cover - non-iterable row
                continue
            for col_index, cell in iterator:
                if not isinstance(cell, str) or len(cell) < 8:
                    continue
                scanned += 1
                if scanned > RESULT_SCAN_CELL_LIMIT:
                    return None
                for pattern in self._injection_patterns:
                    match = pattern.search(cell)
                    if match:
                        start = max(0, match.start() - 20)
                        snippet = cell[start : match.end() + 40]
                        return f"row {row_index}, column {col_index}", snippet
        return None

    # -- audit -----------------------------------------------------------

    def _write_audit(
        self, decision: Decision, event: str, extra: dict[str, Any] | None = None
    ) -> None:
        record: dict[str, Any] = {"event": event, **decision.to_dict()}
        if self.policy.audit.include_sql:
            record["sql"] = decision.effective_sql or decision.sql
            if decision.effective_sql:
                record["original_sql"] = decision.sql
        record["policy"] = self.policy.name
        if extra:
            record.update({k: v for k, v in extra.items() if v is not None})
        self.sink.write(record)


class DataweirWarning(UserWarning):
    """Emitted in ``warn`` mode instead of blocking."""


def _matches_any(patterns: tuple[str, ...], table: str, column: str) -> bool:
    import fnmatch

    qualified = f"{table}.{column}".lower()
    for pattern in patterns:
        candidate = pattern.lower()
        if fnmatch.fnmatch(qualified, candidate):
            return True
        if "." not in candidate and fnmatch.fnmatch(column.lower(), candidate):
            return True
    return False


def _table_has_classified_columns(policy: Policy, table: str) -> bool:
    """True when the classification list names anything on this table.

    Used to decide whether `SELECT *` is worth flagging: a wildcard over a table
    with no classified columns is untidy, not dangerous.
    """
    patterns = policy.classification.sensitive_columns + policy.classification.pii_columns
    if not patterns:
        return False
    import fnmatch

    table = table.lower()
    for pattern in patterns:
        candidate = pattern.lower()
        if "." not in candidate:
            return True
        prefix = candidate.split(".", 1)[0]
        if fnmatch.fnmatch(table, prefix):
            return True
    return False
