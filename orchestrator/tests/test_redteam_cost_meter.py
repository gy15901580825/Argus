# tests/test_redteam_cost_meter.py
from __future__ import annotations
import pytest
from orchestrator.redteam.cost_meter import CostMeter, CostExceededError


def test_per_run_cap_aborts_run_not_global():
    m = CostMeter(daily_cap_usd=1.00, per_run_cap_usd=0.05)
    with m.run_scope("run-a"):
        # Haiku rates: $1/M input, $5/M output → 100k input + 100k output ≈ $0.60
        # First call IS allowed (under per-run cap when accumulator starts at 0).
        # Hmm - need a smaller call. Let's use 30k+30k ≈ $0.18 first which goes over $0.05.
        with pytest.raises(CostExceededError, match="per_run"):
            m.record("claude-haiku-4-5-20251001", 30_000, 30_000)
    # Daily not exhausted
    assert m.spent_today() < 1.00


def test_predictive_abort_for_oversized_run():
    m = CostMeter(daily_cap_usd=10.00, per_run_cap_usd=0.10)
    # Simulate a run with 100 probes × 10 rounds — way over $0.10 estimate
    with pytest.raises(CostExceededError, match="estimated"):
        m.check_or_abort_pre_run(probe_ids=["p"] * 100, target_kind="custom_http", iterative_rounds=10)


def test_pre_run_under_cap_passes():
    m = CostMeter(daily_cap_usd=10.00, per_run_cap_usd=1.00)
    # 3 probes, single round — within $1
    m.check_or_abort_pre_run(probe_ids=["p1", "p2", "p3"], target_kind="openai_compat", iterative_rounds=1)


def test_run_scope_clears_per_run_counter_on_exit():
    m = CostMeter(daily_cap_usd=10.00, per_run_cap_usd=1.00)
    with m.run_scope("run-a"):
        m.record("claude-haiku-4-5-20251001", 100_000, 100_000)
        a_spent = m.spent_in_current_run()
    assert m.spent_in_current_run() == 0.0
    with m.run_scope("run-b"):
        m.record("claude-haiku-4-5-20251001", 50_000, 50_000)
        assert m.spent_in_current_run() < a_spent


def test_run_scope_non_reentrant():
    m = CostMeter(daily_cap_usd=10, per_run_cap_usd=1)
    with m.run_scope("a"):
        with pytest.raises(RuntimeError, match="non-reentrant"):
            with m.run_scope("b"):
                pass


def test_alert_threshold_fires_once_per_cooldown(monkeypatch):
    captured = []
    monkeypatch.setattr(
        "orchestrator.redteam.cost_meter._send_alert",
        lambda meter: captured.append(meter.spent_today()),
    )
    m = CostMeter(daily_cap_usd=1.00, per_run_cap_usd=10.00, alert_threshold=0.80, alert_cooldown_s=3600)
    with m.run_scope("r"):
        m.record("claude-haiku-4-5-20251001", 200_000, 200_000)  # ~$1.20 → trigger
    assert len(captured) == 1
    # Re-trigger within cooldown window — no new alert
    with m.run_scope("r2"):
        # Daily cap raises before threshold check, so use a try/except
        try:
            m.record("claude-haiku-4-5-20251001", 50_000, 50_000)
        except CostExceededError:
            pass
    assert len(captured) == 1


def test_record_under_cap_returns_cost():
    m = CostMeter(daily_cap_usd=10.00, per_run_cap_usd=10.00)
    with m.run_scope("r"):
        cost = m.record("claude-haiku-4-5-20251001", 1000, 1000)
    # 1k input + 1k output ≈ ($1/M)*0.001 + ($5/M)*0.001 = $0.001 + $0.005 = $0.006
    assert 0.005 < cost < 0.007


def test_daily_cap_already_reached_blocks_record():
    m = CostMeter(daily_cap_usd=0.001, per_run_cap_usd=10.00)
    # First record exhausts daily
    with m.run_scope("r"):
        try:
            m.record("claude-haiku-4-5-20251001", 100_000, 100_000)  # ≈ $0.60
        except CostExceededError:
            pass
    # Second call should immediately reject (daily cap already breached)
    with m.run_scope("r2"):
        with pytest.raises(CostExceededError, match="daily cap"):
            m.record("claude-haiku-4-5-20251001", 100, 100)


def test_total_exchanges_overrides_probe_count():
    """One probe is not one LLM exchange: a multi-prompt probe sends several,
    and a deep thread sends up to max_rounds. The caller knows the real count."""
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    # 3 probes at one exchange each is comfortably under the cap...
    m.check_or_abort_pre_run(probe_ids=["p1", "p2", "p3"], target_kind="openai_compat")
    # ...the same 3 probes at 100 exchanges each is not.
    with pytest.raises(CostExceededError, match="per_run_cap"):
        m.check_or_abort_pre_run(
            probe_ids=["p1", "p2", "p3"], target_kind="openai_compat", total_exchanges=300
        )


def test_deep_preflight_is_capped_by_the_deep_per_run_cap():
    """Deep runs are budgeted against deep_per_run_cap_usd ($5.00), not the
    $0.50 static cap — otherwise a single-probe deep run could never start."""
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50, deep_per_run_cap_usd=5.00)
    with pytest.raises(CostExceededError, match="per_run_cap"):
        m.check_or_abort_pre_run(probe_ids=["p1"], target_kind="openai_compat", total_exchanges=60)
    estimated = m.check_or_abort_pre_run(
        probe_ids=["p1"], target_kind="openai_compat", total_exchanges=60, deep=True
    )
    assert 0.50 < estimated < 5.00


def test_deep_preflight_respects_the_deep_daily_slice():
    """The deep slice ($8.10 of $13.50) exists so deep scans cannot starve the
    static CI path; the estimate must be checked against it, not the whole day."""
    m = CostMeter(daily_cap_usd=13.50, deep_per_run_cap_usd=50.00, deep_budget_fraction=0.60)
    # ~$9 of estimated spend fits the day ($13.50) but not the deep slice ($8.10).
    with pytest.raises(CostExceededError, match="deep"):
        m.check_or_abort_pre_run(
            probe_ids=["p1"], target_kind="openai_compat", total_exchanges=910, deep=True
        )
