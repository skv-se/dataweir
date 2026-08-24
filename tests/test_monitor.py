from __future__ import annotations

from dataweir.monitor import Baseline, Monitor, fingerprint
from dataweir.policy import AnomalyConfig, Budgets


def test_fingerprint_ignores_literals():
    assert fingerprint("SELECT a FROM t WHERE id = 1") == fingerprint(
        "SELECT a FROM t WHERE id = 99"
    )


def test_fingerprint_distinguishes_shapes():
    assert fingerprint("SELECT a FROM t") != fingerprint("SELECT b FROM t")
    assert fingerprint("SELECT a FROM t") != fingerprint("SELECT a FROM u")


def test_fingerprint_survives_unparseable_sql():
    assert fingerprint("SELECT ((( FROM") == fingerprint("select ((( from")


def test_baseline_tracks_mean_and_spread():
    baseline = Baseline()
    for value in [10, 12, 11, 9, 13]:
        baseline.update(value)
    assert baseline.count == 5
    assert 10.5 < baseline.mean < 11.5
    assert baseline.stdev > 0
    assert baseline.max_seen == 13


def test_zscore_without_spread_uses_proportional_deviation():
    baseline = Baseline()
    for _ in range(10):
        baseline.update(100)
    assert baseline.stdev == 0
    assert baseline.zscore(500) > 3


def test_anomaly_needs_enough_observations():
    monitor = Monitor()
    config = AnomalyConfig(min_observations=10, absolute_floor=1, row_zscore=2.0)
    for _ in range(5):
        monitor.observe("a", "shape", 10)
    flagged, _ = monitor.check_anomaly("a", "shape", 5000, config)
    assert flagged is False


def test_anomaly_fires_once_the_baseline_exists():
    monitor = Monitor()
    config = AnomalyConfig(min_observations=5, absolute_floor=1, row_zscore=3.0)
    for value in [10, 11, 9, 12, 10, 11]:
        monitor.observe("a", "shape", value)
    flagged, explanation = monitor.check_anomaly("a", "shape", 5000, config)
    assert flagged is True
    assert "baseline" in explanation


def test_absolute_floor_suppresses_small_results():
    monitor = Monitor()
    config = AnomalyConfig(min_observations=3, absolute_floor=100, row_zscore=1.0)
    for _ in range(5):
        monitor.observe("a", "shape", 1)
    flagged, _ = monitor.check_anomaly("a", "shape", 50, config)
    assert flagged is False


def test_disabled_anomaly_never_fires():
    monitor = Monitor()
    config = AnomalyConfig(enabled=False, min_observations=1, absolute_floor=1)
    monitor.observe("a", "shape", 1)
    assert monitor.check_anomaly("a", "shape", 10_000, config)[0] is False


def test_baselines_are_per_agent():
    monitor = Monitor()
    config = AnomalyConfig(min_observations=3, absolute_floor=1, row_zscore=3.0)
    for _ in range(5):
        monitor.observe("a", "shape", 10)
    assert monitor.check_anomaly("b", "shape", 5000, config)[0] is False


def test_session_budget_accounts_for_the_projection():
    monitor = Monitor()
    budgets = Budgets(rows_per_session=100)
    monitor.record_rows("a", "s", 90)
    assert monitor.check_budgets("a", "s", budgets, projected_rows=5).ok
    check = monitor.check_budgets("a", "s", budgets, projected_rows=50)
    assert not check.ok
    assert check.code == "DW006"


def test_query_rate_budget():
    monitor = Monitor()
    budgets = Budgets(queries_per_minute=3)
    for _ in range(3):
        monitor.record_query("a", "s")
    check = monitor.check_budgets("a", "s", budgets)
    assert not check.ok
    assert check.code == "DW007"


def test_row_rate_budget():
    monitor = Monitor()
    budgets = Budgets(rows_per_minute=100)
    monitor.record_rows("a", "s", 80)
    assert not monitor.check_budgets("a", "s", budgets, projected_rows=50).ok


def test_empty_budgets_always_pass():
    monitor = Monitor()
    monitor.record_rows("a", "s", 10_000)
    assert monitor.check_budgets("a", "s", Budgets()).ok


def test_sensitive_budget_is_separate():
    monitor = Monitor()
    budgets = Budgets(sensitive_rows_per_session=0)
    assert monitor.check_budgets("a", "s", budgets).ok
    assert not monitor.check_sensitive_budget("a", "s", budgets, projected=1).ok


def test_sessions_are_keyed_by_agent_and_session():
    monitor = Monitor()
    monitor.record_rows("a", "s1", 5)
    monitor.record_rows("a", "s2", 7)
    monitor.record_rows("b", "s1", 9)
    assert monitor.session("a", "s1").rows == 5
    assert monitor.session("a", "s2").rows == 7
    assert monitor.session("b", "s1").rows == 9
    assert len(monitor.sessions()) == 3


def test_snapshot_shape():
    monitor = Monitor()
    monitor.record_query("a", "s")
    monitor.record_rows("a", "s", 3, sensitive=True)
    snapshot = monitor.session("a", "s").snapshot()
    assert snapshot["queries"] == 1
    assert snapshot["rows"] == 3
    assert snapshot["sensitive_rows"] == 3
    assert "duration_s" in snapshot


def test_reset_clears_everything():
    monitor = Monitor()
    monitor.record_rows("a", "s", 10)
    monitor.observe("a", "shape", 10)
    monitor.reset()
    assert monitor.sessions() == []
    assert monitor.baseline("a", "shape").count == 0
