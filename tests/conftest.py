from __future__ import annotations

import sqlite3

import pytest

from dataweir import Guardrail, MemoryAuditSink, Mode, Monitor, Policy

POLICY_DICT = {
    "version": 1,
    "name": "test",
    "default": "deny",
    "mode": "enforce",
    "audit": {"enabled": False, "path": None},
    "classification": {
        "sensitive_columns": ["*.ssn"],
        "pii_columns": ["*.email"],
    },
    "agents": [
        {
            "id": "support",
            "grants": [
                {"tables": ["tickets"], "operations": ["select"], "max_rows": 100},
                {
                    "tables": ["customers"],
                    "operations": ["select"],
                    "deny_columns": ["customers.ssn"],
                    "max_rows": 10,
                },
            ],
            "budgets": {"rows_per_session": 500, "rows_per_minute": 400},
            "anomaly": {"min_observations": 5, "row_zscore": 3.0, "absolute_floor": 10},
        },
        {
            "id": "writer",
            "grants": [
                {
                    "tables": ["tickets"],
                    "operations": ["select", "insert", "update"],
                    "max_rows": 50,
                    "require_where": True,
                }
            ],
        },
    ],
}


@pytest.fixture
def policy() -> Policy:
    return Policy.from_dict(POLICY_DICT)


@pytest.fixture
def monitor_policy() -> Policy:
    return Policy.from_dict({**POLICY_DICT, "mode": "monitor"})


@pytest.fixture
def sink() -> MemoryAuditSink:
    return MemoryAuditSink()


@pytest.fixture
def guardrail(policy: Policy, sink: MemoryAuditSink) -> Guardrail:
    return Guardrail(policy, monitor=Monitor(), sink=sink)


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE tickets (id INTEGER PRIMARY KEY, owner TEXT, status TEXT, note TEXT);
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, ssn TEXT);
        CREATE TABLE payroll (id INTEGER PRIMARY KEY, amount INTEGER);
        """
    )
    conn.executemany(
        "INSERT INTO tickets (id, owner, status, note) VALUES (?, ?, ?, ?)",
        [(i, "ana" if i % 2 else "bo", "open", f"note {i}") for i in range(1, 201)],
    )
    conn.executemany(
        "INSERT INTO customers (id, name, email, ssn) VALUES (?, ?, ?, ?)",
        [(i, f"c{i}", f"c{i}@example.invalid", f"000-00-{i:04d}") for i in range(1, 51)],
    )
    conn.executemany(
        "INSERT INTO payroll (id, amount) VALUES (?, ?)", [(i, i * 100) for i in range(1, 21)]
    )
    conn.commit()
    return conn


__all__ = ["Mode"]
