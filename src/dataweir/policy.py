"""Policy model and YAML loader.

A policy is deny-by-default: an agent may perform exactly the operations its
grants describe, on exactly the tables and columns they name, up to the row
ceilings they set. Everything else is a finding.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from .analyze import Operation


class Mode(str, Enum):
    """What the guardrail does with a BLOCK verdict."""

    MONITOR = "monitor"
    """Record the verdict, let the query through. Safe first install."""
    WARN = "warn"
    """Record and emit a Python warning, let the query through."""
    ENFORCE = "enforce"
    """Raise :class:`~dataweir.errors.AccessDenied` and never touch the database."""


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class PolicyError(ValueError):
    """The policy document is malformed or self-contradictory."""


DEFAULT_INJECTION_PATTERNS: tuple[str, ...] = (
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|the\s+above)",
    r"you\s+are\s+now\s+(a|an|the)\b",
    r"</?(system|assistant|user)>",
    r"<\|im_(start|end)\|>",
    r"\[\[?\s*system\s*\]?\]",
    r"new\s+instructions\s*:",
    r"do\s+not\s+tell\s+the\s+user",
    r"!\[[^\]]*\]\(\s*https?://",
)


@dataclass(frozen=True)
class Grant:
    """One allowance: these operations, on these tables, up to this many rows."""

    tables: tuple[str, ...]
    operations: frozenset[Operation]
    columns: tuple[str, ...] = ("*",)
    deny_columns: tuple[str, ...] = ()
    max_rows: int | None = None
    require_where: bool = False

    def covers_table(self, table: str) -> bool:
        return any(fnmatch.fnmatch(table.lower(), pattern.lower()) for pattern in self.tables)

    def covers_operation(self, operation: Operation) -> bool:
        return operation in self.operations

    @property
    def is_wildcard(self) -> bool:
        return any(pattern.strip() in {"*", "**", "*.*"} for pattern in self.tables)


@dataclass(frozen=True)
class Budgets:
    """Cumulative ceilings across a whole agent session."""

    rows_per_session: int | None = None
    rows_per_minute: int | None = None
    queries_per_minute: int | None = None
    sensitive_rows_per_session: int | None = None

    @property
    def is_empty(self) -> bool:
        return all(
            value is None
            for value in (
                self.rows_per_session,
                self.rows_per_minute,
                self.queries_per_minute,
                self.sensitive_rows_per_session,
            )
        )


@dataclass(frozen=True)
class AnomalyConfig:
    """Volume-anomaly detection against a per-query-shape baseline."""

    enabled: bool = True
    row_zscore: float = 4.0
    min_observations: int = 20
    absolute_floor: int = 50
    """Never flag a result smaller than this, however unusual it looks."""


@dataclass(frozen=True)
class AgentPolicy:
    id: str
    grants: tuple[Grant, ...] = ()
    budgets: Budgets = field(default_factory=Budgets)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    mode: Mode | None = None
    description: str = ""


@dataclass(frozen=True)
class Classification:
    """Column patterns that raise the stakes of a read."""

    sensitive_columns: tuple[str, ...] = ()
    pii_columns: tuple[str, ...] = ()

    def matches(self, patterns: tuple[str, ...], qualified_column: str) -> bool:
        column = qualified_column.lower()
        bare = column.split(".", 1)[-1]
        for pattern in patterns:
            candidate = pattern.lower()
            if fnmatch.fnmatch(column, candidate):
                return True
            if "." not in candidate and fnmatch.fnmatch(bare, candidate):
                return True
        return False

    def is_sensitive(self, qualified_column: str) -> bool:
        return self.matches(self.sensitive_columns, qualified_column)

    def is_pii(self, qualified_column: str) -> bool:
        return self.matches(self.pii_columns, qualified_column)

    def classify(self, qualified_column: str) -> str | None:
        if self.is_sensitive(qualified_column):
            return "sensitive"
        if self.is_pii(qualified_column):
            return "pii"
        return None


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = True
    path: str | None = "dataweir-audit.jsonl"
    hash_chain: bool = True
    redact_params: bool = True
    include_sql: bool = True
    log_results: bool = True
    """Write a second record per query carrying the row count."""


@dataclass(frozen=True)
class Policy:
    version: int = 1
    name: str = "default"
    default: str = "deny"
    mode: Mode = Mode.MONITOR
    block_severity: Severity = Severity.HIGH
    agents: dict[str, AgentPolicy] = field(default_factory=dict)
    classification: Classification = field(default_factory=Classification)
    audit: AuditConfig = field(default_factory=AuditConfig)
    injection_patterns: tuple[str, ...] = DEFAULT_INJECTION_PATTERNS
    inspect_results: bool = True
    source_path: str | None = None

    def agent(self, agent_id: str) -> AgentPolicy | None:
        return self.agents.get(agent_id)

    def mode_for(self, agent_id: str) -> Mode:
        agent = self.agents.get(agent_id)
        if agent is not None and agent.mode is not None:
            return agent.mode
        return self.mode

    # -- loading ---------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str | None = None) -> Policy:
        if not isinstance(data, dict):
            raise PolicyError("policy document must be a mapping")

        default = str(data.get("default", "deny")).lower()
        if default not in {"deny", "allow"}:
            raise PolicyError("policy 'default' must be 'deny' or 'allow'")

        agents: dict[str, AgentPolicy] = {}
        raw_agents = data.get("agents", [])
        if isinstance(raw_agents, dict):
            raw_agents = [{"id": key, **value} for key, value in raw_agents.items()]
        if not isinstance(raw_agents, list):
            raise PolicyError("policy 'agents' must be a list or mapping")

        for raw in raw_agents:
            agent = _parse_agent(raw)
            if agent.id in agents:
                raise PolicyError(f"duplicate agent id: {agent.id}")
            agents[agent.id] = agent

        raw_class = data.get("classification") or {}
        classification = Classification(
            sensitive_columns=tuple(raw_class.get("sensitive_columns", ()) or ()),
            pii_columns=tuple(raw_class.get("pii_columns", ()) or ()),
        )

        raw_audit = data.get("audit")
        if raw_audit is None:
            audit = AuditConfig()
        elif raw_audit is False:
            audit = AuditConfig(enabled=False, path=None)
        else:
            audit = AuditConfig(
                enabled=bool(raw_audit.get("enabled", True)),
                path=raw_audit.get("path", "dataweir-audit.jsonl"),
                hash_chain=bool(raw_audit.get("hash_chain", True)),
                redact_params=bool(raw_audit.get("redact_params", True)),
                include_sql=bool(raw_audit.get("include_sql", True)),
                log_results=bool(raw_audit.get("log_results", True)),
            )

        return cls(
            version=int(data.get("version", 1)),
            name=str(data.get("name", "default")),
            default=default,
            mode=_parse_mode(data.get("mode", "monitor")),
            block_severity=_parse_severity(data.get("block_severity", "high")),
            agents=agents,
            classification=classification,
            audit=audit,
            injection_patterns=tuple(data.get("injection_patterns") or DEFAULT_INJECTION_PATTERNS),
            inspect_results=bool(data.get("inspect_results", True)),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        path = Path(path)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except FileNotFoundError as err:
            raise PolicyError(f"policy file not found: {path}") from err
        except yaml.YAMLError as err:
            raise PolicyError(f"invalid YAML in {path}: {err}") from err
        return cls.from_dict(raw or {}, source_path=str(path))


def _parse_mode(value: Any) -> Mode:
    try:
        return Mode(str(value).lower())
    except ValueError as err:
        raise PolicyError(
            f"invalid mode {value!r}; expected one of {[m.value for m in Mode]}"
        ) from err


def _parse_severity(value: Any) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError as err:
        raise PolicyError(
            f"invalid severity {value!r}; expected one of {[s.value for s in Severity]}"
        ) from err


def _parse_operations(value: Any) -> frozenset[Operation]:
    if value is None:
        return frozenset({Operation.SELECT})
    if isinstance(value, str):
        value = [value]
    operations: set[Operation] = set()
    for item in value:
        text = str(item).lower()
        if text in {"read", "*"}:
            operations.add(Operation.SELECT)
            if text == "*":
                operations |= {
                    Operation.INSERT,
                    Operation.UPDATE,
                    Operation.DELETE,
                }
            continue
        if text == "write":
            operations |= {Operation.INSERT, Operation.UPDATE, Operation.DELETE}
            continue
        try:
            operations.add(Operation(text))
        except ValueError as err:
            raise PolicyError(f"unknown operation {item!r}") from err
    return frozenset(operations)


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _parse_agent(raw: Any) -> AgentPolicy:
    if not isinstance(raw, dict):
        raise PolicyError("each agent must be a mapping")
    agent_id = raw.get("id")
    if not agent_id:
        raise PolicyError("each agent needs an 'id'")

    grants: list[Grant] = []
    for raw_grant in raw.get("grants", []) or []:
        if not isinstance(raw_grant, dict):
            raise PolicyError(f"agent {agent_id}: each grant must be a mapping")
        tables = _as_tuple(raw_grant.get("tables"))
        if not tables:
            raise PolicyError(f"agent {agent_id}: a grant must name at least one table")
        max_rows = raw_grant.get("max_rows")
        grants.append(
            Grant(
                tables=tables,
                operations=_parse_operations(raw_grant.get("operations")),
                columns=_as_tuple(raw_grant.get("columns")) or ("*",),
                deny_columns=_as_tuple(raw_grant.get("deny_columns")),
                max_rows=int(max_rows) if max_rows is not None else None,
                require_where=bool(raw_grant.get("require_where", False)),
            )
        )

    raw_budgets = raw.get("budgets") or {}
    budgets = Budgets(
        rows_per_session=_opt_int(raw_budgets.get("rows_per_session")),
        rows_per_minute=_opt_int(raw_budgets.get("rows_per_minute")),
        queries_per_minute=_opt_int(raw_budgets.get("queries_per_minute")),
        sensitive_rows_per_session=_opt_int(raw_budgets.get("sensitive_rows_per_session")),
    )

    raw_anomaly = raw.get("anomaly") or {}
    anomaly = AnomalyConfig(
        enabled=bool(raw_anomaly.get("enabled", True)),
        row_zscore=float(raw_anomaly.get("row_zscore", 4.0)),
        min_observations=int(raw_anomaly.get("min_observations", 20)),
        absolute_floor=int(raw_anomaly.get("absolute_floor", 50)),
    )

    return AgentPolicy(
        id=str(agent_id),
        grants=tuple(grants),
        budgets=budgets,
        anomaly=anomaly,
        mode=_parse_mode(raw["mode"]) if raw.get("mode") else None,
        description=str(raw.get("description", "")),
    )


def _opt_int(value: Any) -> int | None:
    return None if value is None else int(value)
