from __future__ import annotations

import pytest

from dataweir.analyze import Operation
from dataweir.policy import Mode, Policy, PolicyError, Severity


def test_loads_from_yaml(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(
        """
version: 1
name: yaml-policy
default: deny
mode: enforce
agents:
  - id: a
    grants:
      - tables: [t]
        operations: [select]
        max_rows: 5
"""
    )
    policy = Policy.load(path)
    assert policy.name == "yaml-policy"
    assert policy.mode is Mode.ENFORCE
    assert policy.agents["a"].grants[0].max_rows == 5
    assert policy.source_path == str(path)


def test_agents_may_be_a_mapping():
    policy = Policy.from_dict(
        {"agents": {"a": {"grants": [{"tables": ["t"], "operations": ["select"]}]}}}
    )
    assert "a" in policy.agents


def test_operation_aliases():
    policy = Policy.from_dict(
        {
            "agents": [
                {"id": "r", "grants": [{"tables": ["t"], "operations": ["read"]}]},
                {"id": "w", "grants": [{"tables": ["t"], "operations": ["write"]}]},
                {"id": "s", "grants": [{"tables": ["t"], "operations": ["*"]}]},
            ]
        }
    )
    assert policy.agents["r"].grants[0].operations == frozenset({Operation.SELECT})
    assert policy.agents["w"].grants[0].operations == frozenset(
        {Operation.INSERT, Operation.UPDATE, Operation.DELETE}
    )
    assert Operation.SELECT in policy.agents["s"].grants[0].operations
    assert Operation.DDL not in policy.agents["s"].grants[0].operations


def test_wildcard_star_does_not_silently_grant_ddl():
    policy = Policy.from_dict(
        {"agents": [{"id": "s", "grants": [{"tables": ["t"], "operations": ["*"]}]}]}
    )
    assert Operation.DDL not in policy.agents["s"].grants[0].operations


def test_missing_defaults_are_sane():
    policy = Policy.from_dict({})
    assert policy.default == "deny"
    assert policy.mode is Mode.MONITOR
    assert policy.block_severity is Severity.HIGH
    assert policy.audit.hash_chain is True
    assert policy.audit.redact_params is True
    assert policy.inspect_results is True


@pytest.mark.parametrize(
    "document",
    [
        {"default": "maybe"},
        {"mode": "nope"},
        {"block_severity": "extreme"},
        {"agents": [{"grants": []}]},  # no id
        {"agents": [{"id": "a", "grants": [{"operations": ["select"]}]}]},  # no tables
        {"agents": [{"id": "a", "grants": [{"tables": ["t"], "operations": ["frobnicate"]}]}]},
        {"agents": [{"id": "a"}, {"id": "a"}]},  # duplicate
        {"agents": "not a list"},
    ],
)
def test_invalid_documents_are_rejected(document):
    with pytest.raises(PolicyError):
        Policy.from_dict(document)


def test_missing_file_raises_policy_error(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        Policy.load(tmp_path / "nope.yaml")


def test_invalid_yaml_raises_policy_error(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("agents: [\n")
    with pytest.raises(PolicyError, match="invalid YAML"):
        Policy.load(path)


def test_audit_false_disables_it():
    assert Policy.from_dict({"audit": False}).audit.enabled is False


def test_grant_table_matching_is_glob_and_case_insensitive():
    policy = Policy.from_dict(
        {"agents": [{"id": "a", "grants": [{"tables": ["app_*"], "operations": ["select"]}]}]}
    )
    grant = policy.agents["a"].grants[0]
    assert grant.covers_table("app_users")
    assert grant.covers_table("APP_ORDERS")
    assert not grant.covers_table("other")


def test_wildcard_detection():
    policy = Policy.from_dict(
        {
            "agents": [
                {"id": "a", "grants": [{"tables": ["*"], "operations": ["select"]}]},
                {"id": "b", "grants": [{"tables": ["t"], "operations": ["select"]}]},
            ]
        }
    )
    assert policy.agents["a"].grants[0].is_wildcard
    assert not policy.agents["b"].grants[0].is_wildcard


def test_classification_matches_bare_and_qualified_patterns():
    policy = Policy.from_dict(
        {"classification": {"sensitive_columns": ["*.ssn", "password"], "pii_columns": ["*.email"]}}
    )
    classification = policy.classification
    assert classification.is_sensitive("customers.ssn")
    assert classification.is_sensitive("users.password")
    assert classification.is_pii("customers.email")
    assert classification.classify("customers.name") is None


def test_per_agent_mode_overrides():
    policy = Policy.from_dict({"mode": "enforce", "agents": [{"id": "a", "mode": "monitor"}]})
    assert policy.mode_for("a") is Mode.MONITOR
    assert policy.mode_for("unknown") is Mode.ENFORCE


def test_budgets_is_empty_detection():
    policy = Policy.from_dict(
        {"agents": [{"id": "a"}, {"id": "b", "budgets": {"rows_per_session": 10}}]}
    )
    assert policy.agents["a"].budgets.is_empty
    assert not policy.agents["b"].budgets.is_empty


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank
