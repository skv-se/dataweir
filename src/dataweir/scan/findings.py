"""Scan result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..controls import OWASP_ASI
from ..policy import Severity


@dataclass(frozen=True)
class ScanFinding:
    """One weakness the scan established, with the evidence for it."""

    id: str
    title: str
    severity: Severity
    detail: str
    remediation: str
    owasp: tuple[str, ...] = ()
    subject: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "remediation": self.remediation,
            "owasp": [f"{code} {OWASP_ASI.get(code, '')}".strip() for code in self.owasp],
            "subject": self.subject,
            "evidence": self.evidence,
        }


@dataclass
class ScanReport:
    """Everything one `dataweir scan` produced."""

    policy_name: str
    policy_path: str | None = None
    findings: list[ScanFinding] = field(default_factory=list)
    probes_run: int = 0
    probes_passed: int = 0
    probes_skipped: int = 0
    checks_run: int = 0
    generated_at: str = field(
        default_factory=lambda: (
            datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        )
    )

    def add(self, finding: ScanFinding) -> None:
        self.findings.append(finding)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    @property
    def counts(self) -> dict[str, int]:
        return {severity.value: self.count(severity) for severity in Severity}

    def sorted_findings(self) -> list[ScanFinding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.id))

    def exit_code(self, fail_on: Severity = Severity.HIGH) -> int:
        """0 when nothing at or above ``fail_on`` was found — CI-friendly."""
        return 1 if self.max_severity.rank >= fail_on.rank and self.findings else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "dataweir",
            "generated_at": self.generated_at,
            "policy": {"name": self.policy_name, "path": self.policy_path},
            "summary": {
                "checks_run": self.checks_run,
                "probes_run": self.probes_run,
                "probes_passed": self.probes_passed,
                "probes_failed": self.probes_run - self.probes_passed,
                "probes_skipped": self.probes_skipped,
                "findings": len(self.findings),
                "by_severity": self.counts,
                "max_severity": self.max_severity.value,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
