"""Findings, verdicts and the decision record the engine returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .controls import control
from .policy import Mode, Severity


class Verdict(str, Enum):
    """What the policy says about a request, independent of mode."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class Action(str, Enum):
    """What actually happened to the request, once mode is applied."""

    ALLOWED = "allowed"
    WARNED = "warned"
    REWRITTEN = "rewritten"
    BLOCKED = "blocked"
    OBSERVED = "observed"
    """Would have been blocked, but the policy is in monitor mode."""


@dataclass(frozen=True)
class Finding:
    """One control that fired, with the detail needed to act on it."""

    code: str
    detail: str
    subject: str = ""
    """The table, column or budget the finding is about."""
    severity_override: Severity | None = None

    @property
    def severity(self) -> Severity:
        return self.severity_override or control(self.code).severity

    @property
    def title(self) -> str:
        return control(self.code).title

    @property
    def owasp(self) -> tuple[str, ...]:
        return control(self.code).owasp

    @property
    def remediation(self) -> str:
        return control(self.code).remediation

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "subject": self.subject,
            "owasp": list(self.owasp),
        }

    def __str__(self) -> str:
        where = f" [{self.subject}]" if self.subject else ""
        return f"{self.code} {self.title}{where}: {self.detail}"


@dataclass
class Decision:
    """The engine's verdict on one request, plus everything worth auditing."""

    agent_id: str
    verdict: Verdict = Verdict.ALLOW
    action: Action = Action.ALLOWED
    mode: Mode = Mode.MONITOR
    findings: list[Finding] = field(default_factory=list)
    sql: str = ""
    effective_sql: str | None = None
    """Set when dataweir rewrote the statement (e.g. injected a LIMIT)."""
    row_limit: int | None = None
    operation: str = ""
    tables: list[str] = field(default_factory=list)
    classified_columns: dict[str, str] = field(default_factory=dict)
    rows_returned: int | None = None

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCKED

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def codes(self) -> list[str]:
        return [f.code for f in self.findings]

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def reason(self) -> str:
        if not self.findings:
            return "no findings"
        return "; ".join(str(f) for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_id": self.agent_id,
            "verdict": self.verdict.value,
            "action": self.action.value,
            "mode": self.mode.value,
            "operation": self.operation,
            "tables": self.tables,
            "findings": [f.to_dict() for f in self.findings],
            "max_severity": self.max_severity.value,
        }
        if self.classified_columns:
            payload["classified_columns"] = self.classified_columns
        if self.row_limit is not None:
            payload["row_limit"] = self.row_limit
        if self.rows_returned is not None:
            payload["rows_returned"] = self.rows_returned
        if self.effective_sql is not None:
            payload["rewritten"] = True
        return payload
