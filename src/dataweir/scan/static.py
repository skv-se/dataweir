"""Static checks against the policy document itself.

These need no database and no agent — they read the policy the way an attacker
would, looking for the grant that is wider than anyone meant it to be.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from ..analyze import Operation
from ..policy import Mode, Policy, Severity
from .findings import ScanFinding

StaticCheck = Callable[[Policy], Iterator[ScanFinding]]

_CHECKS: list[StaticCheck] = []


def check(func: StaticCheck) -> StaticCheck:
    _CHECKS.append(func)
    return func


@check
def default_allow(policy: Policy) -> Iterator[ScanFinding]:
    if policy.default == "allow":
        yield ScanFinding(
            id="DWS001",
            title="Policy defaults to allow",
            severity=Severity.CRITICAL,
            detail=(
                "Any agent with no policy entry gets unrestricted data access. "
                "Least privilege requires the opposite default."
            ),
            remediation="Set `default: deny` and give each agent an explicit grant.",
            owasp=("ASI03", "ASI10"),
            subject="default",
        )


@check
def no_agents(policy: Policy) -> Iterator[ScanFinding]:
    if not policy.agents:
        yield ScanFinding(
            id="DWS013",
            title="No agents defined",
            severity=Severity.HIGH,
            detail="The policy governs nothing: no agent identities are declared.",
            remediation="Add an `agents:` entry for each agent that touches data.",
            owasp=("ASI10",),
            subject="agents",
        )


@check
def wildcard_grants(policy: Policy) -> Iterator[ScanFinding]:
    for agent in policy.agents.values():
        for index, grant in enumerate(agent.grants):
            if grant.is_wildcard:
                yield ScanFinding(
                    id="DWS002",
                    title="Wildcard table grant",
                    severity=Severity.HIGH,
                    detail=(
                        f"Agent {agent.id!r} grant #{index} matches every table "
                        f"({', '.join(grant.tables)}). Tables added later are "
                        "granted automatically, without review."
                    ),
                    remediation="Name the tables the agent needs. Revisit when they change.",
                    owasp=("ASI03",),
                    subject=agent.id,
                    evidence=f"tables: {list(grant.tables)}",
                )


@check
def missing_row_ceilings(policy: Policy) -> Iterator[ScanFinding]:
    for agent in policy.agents.values():
        for index, grant in enumerate(agent.grants):
            if Operation.SELECT in grant.operations and grant.max_rows is None:
                yield ScanFinding(
                    id="DWS003",
                    title="Read grant with no row ceiling",
                    severity=Severity.HIGH,
                    detail=(
                        f"Agent {agent.id!r} grant #{index} on "
                        f"{', '.join(grant.tables)} can read the whole table in one "
                        "query. Nothing separates a lookup from a bulk export."
                    ),
                    remediation="Set `max_rows` on the grant to the largest legitimate result.",
                    owasp=("ASI02",),
                    subject=agent.id,
                    evidence=f"tables: {list(grant.tables)}",
                )


@check
def missing_budgets(policy: Policy) -> Iterator[ScanFinding]:
    for agent in policy.agents.values():
        if agent.grants and agent.budgets.is_empty:
            yield ScanFinding(
                id="DWS004",
                title="No session budget",
                severity=Severity.MEDIUM,
                detail=(
                    f"Agent {agent.id!r} has per-query ceilings but no cumulative "
                    "budget. Ten thousand compliant queries still drain the table."
                ),
                remediation="Set `budgets.rows_per_session` and `budgets.rows_per_minute`.",
                owasp=("ASI02",),
                subject=agent.id,
            )


@check
def audit_disabled(policy: Policy) -> Iterator[ScanFinding]:
    if not policy.audit.enabled or policy.audit.path is None:
        yield ScanFinding(
            id="DWS005",
            title="Audit logging disabled",
            severity=Severity.HIGH,
            detail=(
                "No record is kept of what the agent read. After an incident there "
                "is nothing to reconstruct."
            ),
            remediation="Set `audit.path` to a writable location and keep it enabled.",
            owasp=("ASI03",),
            subject="audit",
        )
        return

    if not policy.audit.hash_chain:
        yield ScanFinding(
            id="DWS006",
            title="Audit chain not hash-linked",
            severity=Severity.MEDIUM,
            detail=(
                "Records can be edited or removed without leaving a trace, so the "
                "log proves less than it appears to."
            ),
            remediation="Set `audit.hash_chain: true`.",
            owasp=("ASI03",),
            subject="audit",
        )

    if not policy.audit.redact_params:
        yield ScanFinding(
            id="DWS015",
            title="Bound parameters recorded in the clear",
            severity=Severity.MEDIUM,
            detail=(
                "Query parameters routinely carry the very values the audit log "
                "exists to protect, and the log is usually less guarded than the "
                "database."
            ),
            remediation="Set `audit.redact_params: true`.",
            owasp=("ASI03",),
            subject="audit",
        )


@check
def write_and_ddl_grants(policy: Policy) -> Iterator[ScanFinding]:
    for agent in policy.agents.values():
        for index, grant in enumerate(agent.grants):
            if Operation.DDL in grant.operations:
                yield ScanFinding(
                    id="DWS011",
                    title="Agent granted schema-altering rights",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"Agent {agent.id!r} grant #{index} permits DDL. An agent that "
                        "can alter schema can disable its own controls."
                    ),
                    remediation="Remove `ddl` from the grant. Run migrations out of band.",
                    owasp=("ASI05",),
                    subject=agent.id,
                )
                continue

            writes = grant.operations & {Operation.UPDATE, Operation.DELETE}
            if writes and not grant.require_where:
                yield ScanFinding(
                    id="DWS007",
                    title="Unfiltered writes permitted",
                    severity=Severity.MEDIUM,
                    detail=(
                        f"Agent {agent.id!r} grant #{index} allows "
                        f"{'/'.join(sorted(op.value.upper() for op in writes))} without "
                        "requiring a WHERE clause, so one call can rewrite the table."
                    ),
                    remediation="Set `require_where: true` on the grant.",
                    owasp=("ASI02",),
                    subject=agent.id,
                )


@check
def no_classification(policy: Policy) -> Iterator[ScanFinding]:
    classification = policy.classification
    if not classification.sensitive_columns and not classification.pii_columns:
        yield ScanFinding(
            id="DWS008",
            title="No data classification",
            severity=Severity.MEDIUM,
            detail=(
                "Nothing marks which columns matter, so every row counts the same "
                "and reads of sensitive fields raise no signal."
            ),
            remediation="List `classification.sensitive_columns` and `pii_columns`.",
            owasp=("ASI03",),
            subject="classification",
        )


@check
def monitor_mode(policy: Policy) -> Iterator[ScanFinding]:
    modes = {policy.mode_for(agent_id) for agent_id in policy.agents} or {policy.mode}
    if modes <= {Mode.MONITOR, Mode.WARN}:
        yield ScanFinding(
            id="DWS009",
            title="Policy never blocks",
            severity=Severity.MEDIUM,
            detail=(
                f"Every agent runs in {'/'.join(sorted(m.value for m in modes))} mode. "
                "The findings below are recorded, not prevented — in production "
                "nothing here would actually be stopped."
            ),
            remediation="Move to `mode: enforce` once the audit log looks clean.",
            owasp=("ASI02",),
            subject="mode",
        )


@check
def agents_without_grants(policy: Policy) -> Iterator[ScanFinding]:
    for agent in policy.agents.values():
        if not agent.grants:
            yield ScanFinding(
                id="DWS010",
                title="Agent has no grants",
                severity=Severity.LOW,
                detail=(
                    f"Agent {agent.id!r} is declared but granted nothing. Under "
                    "deny-by-default every query it makes is refused — which may be "
                    "intended, or may be an unfinished policy."
                ),
                remediation="Add grants, or remove the agent entry.",
                owasp=("ASI03",),
                subject=agent.id,
            )


@check
def anomaly_disabled(policy: Policy) -> Iterator[ScanFinding]:
    for agent in policy.agents.values():
        if agent.grants and not agent.anomaly.enabled:
            yield ScanFinding(
                id="DWS012",
                title="Volume-anomaly detection off",
                severity=Severity.LOW,
                detail=(
                    f"Agent {agent.id!r} has anomaly detection disabled, so a query "
                    "that suddenly returns a thousand times its usual rows looks "
                    "exactly like every other compliant query."
                ),
                remediation="Set `anomaly.enabled: true`.",
                owasp=("ASI02",),
                subject=agent.id,
            )


@check
def result_inspection_disabled(policy: Policy) -> Iterator[ScanFinding]:
    if not policy.inspect_results:
        yield ScanFinding(
            id="DWS014",
            title="Result inspection disabled",
            severity=Severity.MEDIUM,
            detail=(
                "Returned rows are not checked for instruction-shaped text, so data "
                "poisoned upstream reaches the agent's context unflagged."
            ),
            remediation="Set `inspect_results: true`.",
            owasp=("ASI06", "ASI01"),
            subject="inspect_results",
        )


STATIC_CHECKS: tuple[StaticCheck, ...] = tuple(_CHECKS)


def run_static(policy: Policy) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for static_check in STATIC_CHECKS:
        findings.extend(static_check(policy))
    return findings
