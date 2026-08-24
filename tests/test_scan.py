from __future__ import annotations

import dataclasses

from dataweir.policy import Mode, Policy, Severity
from dataweir.scan import PROBES, run_scan
from dataweir.scan.probes import run_probes
from dataweir.scan.static import run_static

WEAK = {
    "default": "allow",
    "mode": "monitor",
    "audit": False,
    "inspect_results": False,
    "agents": [{"id": "everything", "grants": [{"tables": ["*"], "operations": ["*", "ddl"]}]}],
}

TIGHT = {
    "default": "deny",
    "mode": "enforce",
    "block_severity": "medium",
    "audit": {"path": "audit.jsonl", "hash_chain": True, "redact_params": True},
    "classification": {"sensitive_columns": ["customers.ssn"], "pii_columns": ["*.email"]},
    "agents": [
        {
            "id": "support",
            "grants": [
                {
                    "tables": ["tickets"],
                    "operations": ["select"],
                    "max_rows": 100,
                },
                {
                    "tables": ["customers"],
                    "operations": ["select"],
                    "deny_columns": ["customers.ssn", "customers.email"],
                    "max_rows": 25,
                },
            ],
            "budgets": {"rows_per_session": 1000, "rows_per_minute": 200},
        }
    ],
}


def ids(findings) -> set[str]:
    return {f.id for f in findings}


# -- static --------------------------------------------------------------


def test_weak_policy_trips_the_headline_static_checks():
    found = ids(run_static(Policy.from_dict(WEAK)))
    assert {"DWS001", "DWS002", "DWS003", "DWS005", "DWS011", "DWS014"} <= found


def test_tight_policy_trips_almost_nothing():
    found = ids(run_static(Policy.from_dict(TIGHT)))
    assert "DWS001" not in found
    assert "DWS002" not in found
    assert "DWS003" not in found
    assert "DWS005" not in found
    assert "DWS009" not in found


def test_monitor_mode_is_reported():
    assert "DWS009" in ids(run_static(Policy.from_dict({**TIGHT, "mode": "monitor"})))


def test_unhashed_audit_is_reported():
    document = {**TIGHT, "audit": {"path": "a.jsonl", "hash_chain": False}}
    assert "DWS006" in ids(run_static(Policy.from_dict(document)))


def test_unredacted_params_are_reported():
    document = {**TIGHT, "audit": {"path": "a.jsonl", "redact_params": False}}
    assert "DWS015" in ids(run_static(Policy.from_dict(document)))


def test_agent_without_grants_is_reported():
    assert "DWS010" in ids(run_static(Policy.from_dict({"agents": [{"id": "idle"}]})))


def test_policy_with_no_agents_is_reported():
    assert "DWS013" in ids(run_static(Policy.from_dict({})))


def test_missing_classification_is_reported():
    document = {**TIGHT}
    document.pop("classification")
    assert "DWS008" in ids(run_static(Policy.from_dict(document)))


def test_unfiltered_write_grant_is_reported():
    document = {
        **TIGHT,
        "agents": [
            {
                "id": "w",
                "grants": [
                    {"tables": ["t"], "operations": ["update"], "max_rows": 10},
                ],
            }
        ],
    }
    assert "DWS007" in ids(run_static(Policy.from_dict(document)))


def test_require_where_clears_the_unfiltered_write_finding():
    document = {
        **TIGHT,
        "agents": [
            {
                "id": "w",
                "grants": [
                    {
                        "tables": ["t"],
                        "operations": ["update"],
                        "max_rows": 10,
                        "require_where": True,
                    }
                ],
            }
        ],
    }
    assert "DWS007" not in ids(run_static(Policy.from_dict(document)))


# -- probes --------------------------------------------------------------


def test_tight_policy_catches_every_probe_it_can_run():
    findings, results = run_probes(Policy.from_dict(TIGHT))
    ran = [r for r in results if not r.skipped]
    assert ran, "probes should have run"
    missed = [r.probe.id for r in ran if not r.passed]
    assert missed == [], f"probes not caught: {missed}"
    assert findings == []


def test_weak_policy_misses_probes():
    findings, _ = run_probes(Policy.from_dict(WEAK))
    assert findings
    assert any(f.severity is Severity.CRITICAL for f in findings)


def test_unknown_agent_probe_fires_when_default_is_allow():
    findings, _ = run_probes(Policy.from_dict(WEAK))
    assert "DWP013" in ids(findings)


def test_injection_probe_fails_when_result_inspection_is_off():
    findings, _ = run_probes(Policy.from_dict({**TIGHT, "inspect_results": False}))
    assert "DWP014" in ids(findings)


def test_injection_probe_passes_when_inspection_is_on():
    findings, _ = run_probes(Policy.from_dict(TIGHT))
    assert "DWP014" not in ids(findings)


def test_probes_never_write_to_the_real_audit_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    document = {**TIGHT, "audit": {"path": str(path), "hash_chain": True}}
    run_probes(Policy.from_dict(document))
    assert not path.exists()


def test_probes_force_enforcement_regardless_of_live_mode():
    monitored = Policy.from_dict({**TIGHT, "mode": "monitor"})
    findings, results = run_probes(monitored)
    ran = [r for r in results if not r.skipped]
    assert any(r.blocked for r in ran)


def test_every_probe_has_a_control_mapping():
    for probe in PROBES:
        assert probe.expect_codes
        assert probe.owasp
        assert probe.remediation


def test_probe_ids_are_unique():
    assert len({probe.id for probe in PROBES}) == len(PROBES)


# -- report --------------------------------------------------------------


def test_report_exit_code_respects_fail_on():
    report = run_scan(Policy.from_dict(WEAK))
    assert report.exit_code(Severity.HIGH) == 1
    assert report.exit_code(Severity.CRITICAL) == 1

    clean = run_scan(Policy.from_dict(TIGHT))
    assert clean.exit_code(Severity.HIGH) == 0


def test_report_serializes():
    payload = run_scan(Policy.from_dict(WEAK)).to_dict()
    assert payload["tool"] == "dataweir"
    assert payload["summary"]["findings"] == len(payload["findings"])
    assert payload["summary"]["max_severity"] == "critical"
    assert all("owasp" in f for f in payload["findings"])


def test_findings_are_sorted_most_severe_first():
    findings = run_scan(Policy.from_dict(WEAK)).sorted_findings()
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_scan_can_run_static_only():
    report = run_scan(Policy.from_dict(WEAK), probes=False)
    assert report.probes_run == 0
    assert report.checks_run > 0


def test_scan_can_run_probes_only():
    report = run_scan(Policy.from_dict(WEAK), static=False)
    assert report.checks_run == 0
    assert report.probes_run > 0


def test_scan_does_not_mutate_the_policy():
    policy = Policy.from_dict({**TIGHT, "mode": "monitor"})
    before = dataclasses.asdict(policy)
    run_scan(policy)
    assert dataclasses.asdict(policy) == before
    assert policy.mode is Mode.MONITOR
