"""Ties the static checks and the probes into one report."""

from __future__ import annotations

from ..policy import Policy
from .findings import ScanReport
from .probes import probe_summary, run_probes
from .static import STATIC_CHECKS, run_static


def run_scan(policy: Policy, static: bool = True, probes: bool = True) -> ScanReport:
    """Run the scan and return a :class:`ScanReport`.

    Args:
        policy: the policy to red-team.
        static: run the policy-document checks.
        probes: run the attack probes against the engine.
    """
    report = ScanReport(policy_name=policy.name, policy_path=policy.source_path)

    if static:
        report.findings.extend(run_static(policy))
        report.checks_run = len(STATIC_CHECKS)

    if probes:
        probe_findings, results = run_probes(policy)
        report.findings.extend(probe_findings)
        summary = probe_summary(results)
        report.probes_run = summary["run"]
        report.probes_passed = summary["passed"]
        report.probes_skipped = summary["skipped"]

    return report
