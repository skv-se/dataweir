from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from dataweir.audit import JsonlAuditSink
from dataweir.cli import main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "dataweir" in result.output


def test_policy_init_then_validate_then_scan(runner, tmp_path):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        init = runner.invoke(main, ["policy", "init"])
        assert init.exit_code == 0

        validate = runner.invoke(main, ["policy", "validate"])
        assert validate.exit_code == 0
        assert "valid" in validate.output

        scan = runner.invoke(main, ["scan"])
        assert scan.exit_code == 0  # starter policy has no high-severity findings


def test_policy_init_refuses_to_clobber(runner, tmp_path):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        runner.invoke(main, ["policy", "init"])
        again = runner.invoke(main, ["policy", "init"])
        assert again.exit_code == 2
        assert runner.invoke(main, ["policy", "init", "--force"]).exit_code == 0


def test_policy_validate_reports_a_bad_document(runner, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("default: maybe\n")
    result = runner.invoke(main, ["policy", "validate", "-p", str(bad)])
    assert result.exit_code == 2


def test_scan_fails_the_build_on_a_weak_policy(runner, tmp_path):
    weak = tmp_path / "weak.yaml"
    weak.write_text(
        """
default: allow
audit: false
agents:
  - id: everything
    grants:
      - tables: ["*"]
        operations: ["*", ddl]
"""
    )
    result = runner.invoke(main, ["scan", "-p", str(weak)])
    assert result.exit_code == 1
    assert "CRITICAL" in result.output


def test_scan_fail_on_threshold_is_respected(runner, tmp_path):
    weak = tmp_path / "weak.yaml"
    weak.write_text("default: allow\nagents: [{id: a}]\n")
    strict = runner.invoke(main, ["scan", "-p", str(weak), "--fail-on", "critical"])
    lenient = runner.invoke(main, ["scan", "-p", str(weak), "--fail-on", "info"])
    assert strict.exit_code == 1
    assert lenient.exit_code == 1


def test_scan_json_output_is_valid(runner, tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("default: deny\nagents: [{id: a}]\n")
    result = runner.invoke(main, ["scan", "-p", str(policy), "--format", "json"])
    payload = json.loads(result.output)
    assert payload["tool"] == "dataweir"
    assert "findings" in payload


def test_scan_writes_a_report_file(runner, tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("default: deny\nagents: [{id: a}]\n")
    out = tmp_path / "report.json"
    runner.invoke(main, ["scan", "-p", str(policy), "-o", str(out)])
    assert json.loads(out.read_text())["tool"] == "dataweir"


def test_scan_missing_policy_exits_two(runner, tmp_path):
    result = runner.invoke(main, ["scan", "-p", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2


def test_controls_catalog(runner):
    result = runner.invoke(main, ["controls"])
    assert result.exit_code == 0
    assert "DW001" in result.output
    assert "ASI03" in result.output


def test_controls_single(runner):
    result = runner.invoke(main, ["controls", "dw009"])
    assert result.exit_code == 0
    assert "Anomalous result volume" in result.output


def test_controls_unknown(runner):
    assert runner.invoke(main, ["controls", "DW999"]).exit_code == 2


# -- audit ---------------------------------------------------------------


@pytest.fixture
def audit_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path)
    sink.write(
        {
            "event": "decision",
            "agent_id": "support",
            "action": "allowed",
            "sql": "SELECT id FROM tickets LIMIT 5",
            "findings": [],
            "rows_returned": 5,
        }
    )
    sink.write(
        {
            "event": "decision",
            "agent_id": "support",
            "action": "blocked",
            "sql": "SELECT amount FROM payroll",
            "findings": [{"code": "DW002", "severity": "high"}],
        }
    )
    return path


def test_audit_verify_ok(runner, audit_file):
    result = runner.invoke(main, ["audit", "verify", str(audit_file)])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_audit_verify_detects_tampering(runner, audit_file):
    lines = audit_file.read_text().splitlines()
    lines[0] = lines[0].replace('"rows_returned":5', '"rows_returned":0')
    audit_file.write_text("\n".join(lines) + "\n")
    result = runner.invoke(main, ["audit", "verify", str(audit_file)])
    assert result.exit_code == 1
    assert "TAMPERED" in result.output


def test_audit_tail(runner, audit_file):
    result = runner.invoke(main, ["audit", "tail", str(audit_file)])
    assert result.exit_code == 0
    assert "support" in result.output


def test_audit_tail_filters_by_blocked(runner, audit_file):
    result = runner.invoke(main, ["audit", "tail", str(audit_file), "--blocked"])
    assert "1 matching record" in result.output


def test_audit_tail_filters_by_code(runner, audit_file):
    result = runner.invoke(main, ["audit", "tail", str(audit_file), "--code", "DW002"])
    assert "1 matching record" in result.output


def test_audit_tail_filters_by_agent(runner, audit_file):
    result = runner.invoke(main, ["audit", "tail", str(audit_file), "--agent", "nobody"])
    assert "0 matching record" in result.output


def test_audit_summary(runner, audit_file):
    result = runner.invoke(main, ["audit", "summary", str(audit_file)])
    assert result.exit_code == 0
    assert "support" in result.output
    assert "Table not granted" in result.output


def test_audit_commands_on_a_missing_file(runner, tmp_path):
    missing = str(tmp_path / "nope.jsonl")
    for command in (["audit", "verify"], ["audit", "tail"], ["audit", "summary"]):
        assert runner.invoke(main, [*command, missing]).exit_code == 2
