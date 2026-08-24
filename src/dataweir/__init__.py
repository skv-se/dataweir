"""dataweir — a data-layer guardrail and activity monitor for AI agents.

A weir is a low dam that both *controls* and *measures* flow. That is the job
here: sit at the query boundary between an agent and its data, enforce
least-privilege access, meter every row that crosses, and say something when the
volume or the content stops looking normal.

Quick start::

    import sqlite3
    from dataweir import Policy, guard

    policy = Policy.load("dataweir.yaml")
    conn = guard(sqlite3.connect("app.db"), policy, agent="support-copilot")

    cur = conn.cursor()
    cur.execute("SELECT id, status FROM tickets WHERE owner = ?", ("ana",))
    rows = cur.fetchall()

Every statement is evaluated before it reaches the database; every row is
counted after it comes back. In ``monitor`` mode nothing is blocked or
rewritten, so it is safe to put in front of a running agent on day one.
"""

from __future__ import annotations

from .analyze import Operation, StatementFacts, analyze
from .audit import (
    ChainReport,
    JsonlAuditSink,
    MemoryAuditSink,
    NullAuditSink,
    read_records,
    verify_chain,
)
from .controls import CONTROLS, OWASP_ASI, Control, control
from .dbapi import GuardedConnection, GuardedCursor, guard
from .decision import Action, Decision, Finding, Verdict
from .engine import DataweirWarning, Guardrail
from .errors import AccessDenied, BudgetExceeded, DataweirError, ResultTruncated
from .monitor import Baseline, Monitor, SessionState, fingerprint
from .policy import (
    AgentPolicy,
    AnomalyConfig,
    AuditConfig,
    Budgets,
    Classification,
    Grant,
    Mode,
    Policy,
    PolicyError,
    Severity,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # entry points
    "guard",
    "Guardrail",
    "Policy",
    # policy model
    "AgentPolicy",
    "AnomalyConfig",
    "AuditConfig",
    "Budgets",
    "Classification",
    "Grant",
    "Mode",
    "PolicyError",
    "Severity",
    # decisions
    "Action",
    "Decision",
    "Finding",
    "Verdict",
    # controls
    "CONTROLS",
    "OWASP_ASI",
    "Control",
    "control",
    # connections
    "GuardedConnection",
    "GuardedCursor",
    # analysis
    "Operation",
    "StatementFacts",
    "analyze",
    # monitoring
    "Baseline",
    "Monitor",
    "SessionState",
    "fingerprint",
    # audit
    "ChainReport",
    "JsonlAuditSink",
    "MemoryAuditSink",
    "NullAuditSink",
    "read_records",
    "verify_chain",
    # errors
    "AccessDenied",
    "BudgetExceeded",
    "DataweirError",
    "DataweirWarning",
    "ResultTruncated",
]
