"""The control catalog.

Every finding dataweir can raise has a stable ``DW###`` code, a fixed severity,
and a mapping to the OWASP Top 10 for Agentic Applications (ASI01-ASI10,
published 2025-12-09 by the OWASP GenAI Security Project). Codes are part of the
public interface: they appear in audit records, scan reports and exit codes, so
they do not change meaning between versions.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy import Severity

OWASP_ASI: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


@dataclass(frozen=True)
class Control:
    code: str
    title: str
    severity: Severity
    owasp: tuple[str, ...]
    remediation: str


def _c(
    code: str, title: str, severity: Severity, owasp: tuple[str, ...], remediation: str
) -> tuple[str, Control]:
    return code, Control(code, title, severity, owasp, remediation)


CONTROLS: dict[str, Control] = dict(
    (
        _c(
            "DW001",
            "Operation not granted",
            Severity.HIGH,
            ("ASI03",),
            "Add the operation to a grant for this agent, or leave it denied.",
        ),
        _c(
            "DW002",
            "Table not granted",
            Severity.HIGH,
            ("ASI03",),
            "Add the table to a grant, or narrow the query to granted tables.",
        ),
        _c(
            "DW003",
            "Denied column accessed",
            Severity.HIGH,
            ("ASI03",),
            "Remove the column from the projection, or from the grant's deny_columns.",
        ),
        _c(
            "DW004",
            "Unbounded read",
            Severity.MEDIUM,
            ("ASI02",),
            "Add a LIMIT, or set max_rows on the grant so dataweir can add one.",
        ),
        _c(
            "DW005",
            "Row ceiling exceeded",
            Severity.HIGH,
            ("ASI02",),
            "Raise max_rows if the volume is legitimate, or narrow the query.",
        ),
        _c(
            "DW006",
            "Session row budget exhausted",
            Severity.HIGH,
            ("ASI02",),
            "Raise budgets.rows_per_session, or start a new reviewed session.",
        ),
        _c(
            "DW007",
            "Rate budget exceeded",
            Severity.MEDIUM,
            ("ASI02",),
            "Raise budgets.rows_per_minute / queries_per_minute, or throttle the agent.",
        ),
        _c(
            "DW008",
            "Sensitive column read",
            Severity.MEDIUM,
            ("ASI03",),
            "Confirm the agent needs this column; otherwise deny it in the grant.",
        ),
        _c(
            "DW009",
            "Anomalous result volume",
            Severity.HIGH,
            ("ASI02",),
            "Investigate: this query shape returned far more rows than its baseline.",
        ),
        _c(
            "DW010",
            "Multiple statements in one call",
            Severity.HIGH,
            ("ASI05",),
            "Send one statement per execute() call; batching hides the second one.",
        ),
        _c(
            "DW011",
            "Schema or catalog enumeration",
            Severity.HIGH,
            ("ASI03",),
            "Give the agent a declared schema instead of letting it browse the catalog.",
        ),
        _c(
            "DW012",
            "Schema-altering statement",
            Severity.CRITICAL,
            ("ASI05",),
            "Agents should never issue DDL. Run migrations through a reviewed path.",
        ),
        _c(
            "DW013",
            "Instruction-shaped content in result data",
            Severity.HIGH,
            ("ASI06", "ASI01"),
            "Treat the row as untrusted data; do not feed it back into the agent verbatim.",
        ),
        _c(
            "DW014",
            "Unparseable statement",
            Severity.HIGH,
            ("ASI05",),
            "dataweir fails closed on SQL it cannot analyze. Check the dialect setting.",
        ),
        _c(
            "DW015",
            "Wildcard projection over classified columns",
            Severity.MEDIUM,
            ("ASI02",),
            "Name the columns the agent needs instead of SELECT *.",
        ),
        _c(
            "DW016",
            "Unknown agent identity",
            Severity.CRITICAL,
            ("ASI10", "ASI03"),
            "Every agent needs its own policy entry. Anonymous access is a rogue agent.",
        ),
        _c(
            "DW017",
            "Unfiltered write",
            Severity.HIGH,
            ("ASI02",),
            "Require a WHERE clause on writes so one call cannot rewrite a whole table.",
        ),
    )
)


def control(code: str) -> Control:
    try:
        return CONTROLS[code]
    except KeyError as err:  # pragma: no cover - programming error
        raise KeyError(f"unknown control code: {code}") from err


def owasp_titles(codes: tuple[str, ...]) -> list[str]:
    return [f"{code} {OWASP_ASI[code]}" for code in codes if code in OWASP_ASI]
