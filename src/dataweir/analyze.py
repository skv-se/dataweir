"""Static analysis of a single data-access request.

Turns a raw SQL string into :class:`StatementFacts` — the structured view the
policy engine reasons about. Parsing is done with ``sqlglot``; anything that
fails to parse is reported as such so the engine can fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

# Catalogs an agent has no legitimate reason to browse. Reading these is how an
# agent discovers what else it could reach, so it is treated as its own signal
# rather than as ordinary table access.
SCHEMA_CATALOGS = frozenset(
    {
        "information_schema",
        "pg_catalog",
        "sys",
        "sqlite_master",
        "sqlite_temp_master",
        "mysql",
        "performance_schema",
        "pg_stat_activity",
        "pg_shadow",
        "pg_user",
        "pg_authid",
        "dba_users",
        "all_tables",
        "user_tables",
    }
)


class Operation(str, Enum):
    """The class of data operation a statement performs."""

    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    DDL = "ddl"
    OTHER = "other"

    @property
    def is_write(self) -> bool:
        return self in (Operation.INSERT, Operation.UPDATE, Operation.DELETE, Operation.DDL)


_ROOT_TO_OP: dict[type, Operation] = {
    exp.Select: Operation.SELECT,
    exp.Union: Operation.SELECT,
    exp.Except: Operation.SELECT,
    exp.Intersect: Operation.SELECT,
    exp.Subquery: Operation.SELECT,
    exp.Insert: Operation.INSERT,
    exp.Update: Operation.UPDATE,
    exp.Delete: Operation.DELETE,
    exp.Create: Operation.DDL,
    exp.Drop: Operation.DDL,
    exp.Alter: Operation.DDL,
    exp.TruncateTable: Operation.DDL,
}


@dataclass
class StatementFacts:
    """Everything the policy engine needs to know about one statement."""

    sql: str
    dialect: str | None = None
    operation: Operation = Operation.OTHER
    tables: set[str] = field(default_factory=set)
    """Bare table names, lowercased, without schema qualifier."""
    qualified_tables: set[str] = field(default_factory=set)
    """``schema.table`` where a schema was written, else the bare name."""
    columns: set[str] = field(default_factory=set)
    """``table.column`` pairs. Unresolvable qualifiers use ``?`` as the table."""
    star_tables: set[str] = field(default_factory=set)
    """Tables pulled in whole by a ``*`` projection."""
    has_projection_star: bool = False
    has_where: bool = False
    limit: int | None = None
    statement_count: int = 1
    touches_catalog: bool = False
    parse_error: str | None = None

    @property
    def parsed(self) -> bool:
        return self.parse_error is None

    @property
    def is_bounded(self) -> bool:
        """True when the statement caps its own result size."""
        return self.limit is not None


def _table_key(table: exp.Table) -> tuple[str, str]:
    name = (table.name or "").lower()
    db = (table.db or "").lower()
    return name, db


def _collect_aliases(node: exp.Expression) -> dict[str, str]:
    """Map every table alias (and bare name) to the real table name."""
    aliases: dict[str, str] = {}
    for table in node.find_all(exp.Table):
        name, _ = _table_key(table)
        if not name:
            continue
        aliases[name] = name
        alias = (table.alias or "").lower()
        if alias:
            aliases[alias] = name
    return aliases


def _projection_stars(node: exp.Expression) -> tuple[bool, set[str]]:
    """Find ``*`` projections and the tables they expand to.

    ``count(*)`` is deliberately excluded: it reveals a row count, not rows.
    """
    found = False
    tables: set[str] = set()
    for select in node.find_all(exp.Select):
        scope_tables = {n for n, _ in (_table_key(t) for t in select.find_all(exp.Table)) if n}
        aliases = _collect_aliases(select)
        for projection in select.expressions:
            if isinstance(projection, exp.Star):
                found = True
                tables |= scope_tables
            elif isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star):
                found = True
                qualifier = (projection.table or "").lower()
                tables.add(aliases.get(qualifier, qualifier) if qualifier else "")
    tables.discard("")
    return found, tables


def _limit_value(node: exp.Expression) -> int | None:
    limit = node.args.get("limit")
    if limit is None:
        return None
    expression = limit.args.get("expression") if isinstance(limit, exp.Limit) else None
    if isinstance(expression, exp.Literal) and expression.is_int:
        try:
            return int(expression.name)
        except (TypeError, ValueError):
            return None
    # A LIMIT exists but is not a plain integer (parameter, expression). Treat it
    # as bounded-but-unknown rather than unbounded.
    return -1


def _resolve_columns(node: exp.Expression) -> set[str]:
    aliases = _collect_aliases(node)
    real_tables = sorted(set(aliases.values()))
    resolved: set[str] = set()

    for column in node.find_all(exp.Column):
        if isinstance(column.this, exp.Star):
            continue
        name = (column.name or "").lower()
        if not name:
            continue
        qualifier = (column.table or "").lower()
        if qualifier:
            table = aliases.get(qualifier, qualifier)
        elif len(real_tables) == 1:
            table = real_tables[0]
        else:
            table = "?"
        resolved.add(f"{table}.{name}")

    # INSERT column lists live in a Schema node, not as Column nodes.
    for schema in node.find_all(exp.Schema):
        parent_table = schema.this
        if not isinstance(parent_table, exp.Table):
            continue
        table = (parent_table.name or "").lower()
        for identifier in schema.expressions:
            col = (getattr(identifier, "name", "") or "").lower()
            if col:
                resolved.add(f"{table}.{col}")

    return resolved


def _operation_for(node: exp.Expression) -> Operation:
    for kind, operation in _ROOT_TO_OP.items():
        if isinstance(node, kind):
            return operation
    return Operation.OTHER


def analyze(sql: str, dialect: str | None = None) -> StatementFacts:
    """Parse ``sql`` and return the facts the policy engine evaluates.

    Never raises on malformed SQL: a parse failure is recorded on the returned
    facts so callers can decide how to fail (the engine fails closed).
    """
    facts = StatementFacts(sql=sql, dialect=dialect)

    try:
        # sqlglot types its parse result loosely; narrow it explicitly so the
        # rest of this module can rely on having real Expression nodes.
        statements: list[exp.Expression] = [
            s for s in sqlglot.parse(sql, read=dialect) if isinstance(s, exp.Expression)
        ]
    except ParseError as err:
        facts.parse_error = str(err).splitlines()[0]
        return facts
    except Exception as err:  # pragma: no cover - sqlglot internal failure
        facts.parse_error = f"{type(err).__name__}: {err}"
        return facts

    if not statements:
        facts.parse_error = "no statement found"
        return facts

    facts.statement_count = len(statements)
    operations: list[Operation] = []
    limits: list[int | None] = []

    for statement in statements:
        operations.append(_operation_for(statement))

        for table in statement.find_all(exp.Table):
            name, db = _table_key(table)
            if not name:
                continue
            facts.tables.add(name)
            facts.qualified_tables.add(f"{db}.{name}" if db else name)
            if name in SCHEMA_CATALOGS or db in SCHEMA_CATALOGS:
                facts.touches_catalog = True

        facts.columns |= _resolve_columns(statement)

        star, star_tables = _projection_stars(statement)
        facts.has_projection_star = facts.has_projection_star or star
        facts.star_tables |= star_tables

        if statement.args.get("where") is not None:
            facts.has_where = True

        limits.append(_limit_value(statement))

    # The riskiest operation in the batch governs, and the batch is only bounded
    # if every statement in it is.
    for candidate in (
        Operation.DDL,
        Operation.DELETE,
        Operation.UPDATE,
        Operation.INSERT,
        Operation.SELECT,
    ):
        if candidate in operations:
            facts.operation = candidate
            break
    else:
        facts.operation = Operation.OTHER

    if limits and all(limit is not None for limit in limits):
        concrete = [limit for limit in limits if limit is not None and limit >= 0]
        facts.limit = max(concrete) if concrete else -1

    return facts
