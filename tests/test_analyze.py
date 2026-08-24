from __future__ import annotations

import pytest

from dataweir.analyze import Operation, analyze


def test_select_tables_and_columns():
    facts = analyze("SELECT id, status FROM tickets WHERE owner = 'ana'")
    assert facts.operation is Operation.SELECT
    assert facts.tables == {"tickets"}
    assert facts.columns == {"tickets.id", "tickets.status", "tickets.owner"}
    assert facts.has_where is True
    assert facts.limit is None
    assert facts.is_bounded is False


def test_alias_resolution_across_join():
    facts = analyze("SELECT c.ssn, t.status FROM customers c JOIN tickets t ON c.id = t.id")
    assert facts.tables == {"customers", "tickets"}
    assert "customers.ssn" in facts.columns
    assert "tickets.status" in facts.columns


def test_star_projection_records_tables():
    facts = analyze("SELECT * FROM customers")
    assert facts.has_projection_star is True
    assert facts.star_tables == {"customers"}


def test_count_star_is_not_a_projection_star():
    facts = analyze("SELECT count(*) FROM tickets")
    assert facts.has_projection_star is False
    assert facts.star_tables == set()


def test_qualified_star():
    facts = analyze("SELECT c.* FROM customers c JOIN tickets t ON c.id = t.id")
    assert facts.has_projection_star is True
    assert facts.star_tables == {"customers"}


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("INSERT INTO tickets (id) VALUES (1)", Operation.INSERT),
        ("UPDATE tickets SET status = 'x'", Operation.UPDATE),
        ("DELETE FROM tickets", Operation.DELETE),
        ("DROP TABLE tickets", Operation.DDL),
        ("CREATE TABLE t (a INT)", Operation.DDL),
        ("ALTER TABLE tickets ADD COLUMN z INT", Operation.DDL),
    ],
)
def test_operation_classification(sql, expected):
    assert analyze(sql).operation is expected


def test_insert_columns_are_extracted():
    facts = analyze("INSERT INTO tickets (id, status) VALUES (1, 'open')")
    assert facts.columns == {"tickets.id", "tickets.status"}


def test_limit_is_read():
    assert analyze("SELECT id FROM tickets LIMIT 25").limit == 25


def test_non_integer_limit_counts_as_bounded_unknown():
    facts = analyze("SELECT id FROM tickets LIMIT ?")
    assert facts.limit == -1
    assert facts.is_bounded is True


def test_multiple_statements_counted_and_riskiest_wins():
    facts = analyze("SELECT 1; DROP TABLE tickets")
    assert facts.statement_count == 2
    assert facts.operation is Operation.DDL


def test_batch_is_unbounded_if_any_statement_is():
    facts = analyze("SELECT a FROM t LIMIT 5; SELECT b FROM t")
    assert facts.is_bounded is False


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT name FROM sqlite_master",
        "SELECT table_name FROM information_schema.tables",
        "SELECT * FROM pg_catalog.pg_tables",
    ],
)
def test_catalog_detection(sql):
    assert analyze(sql).touches_catalog is True


def test_ordinary_table_is_not_a_catalog():
    assert analyze("SELECT id FROM tickets").touches_catalog is False


def test_parse_error_is_reported_not_raised():
    facts = analyze("SELECT ((( FROM")
    assert facts.parsed is False
    assert facts.parse_error


def test_empty_statement_is_a_parse_error():
    assert analyze("   ").parsed is False


def test_subquery_tables_are_seen():
    facts = analyze("SELECT id FROM tickets WHERE id IN (SELECT id FROM payroll)")
    assert facts.tables == {"tickets", "payroll"}


def test_union_collects_both_sides():
    facts = analyze("SELECT id FROM tickets UNION SELECT id FROM payroll")
    assert facts.tables == {"tickets", "payroll"}
    assert facts.operation is Operation.SELECT
