# tests/test_redteam_cost_meter.py
from __future__ import annotations
import pytest
from argus.cost_meter import CostMeter, CostExceededError, estimate_call_usd


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
        "argus.cost_meter._send_alert",
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
        m.check_or_abort_pre_run(probe_ids=["p1"], target_kind="openai_compat", total_exchanges=200)
    estimated = m.check_or_abort_pre_run(
        probe_ids=["p1"], target_kind="openai_compat", total_exchanges=200, deep=True
    )
    assert 0.50 < estimated < 5.00


def test_deep_preflight_respects_the_deep_daily_slice():
    """The deep slice ($8.10 of $13.50) exists so deep scans cannot starve the
    static CI path; the estimate must be checked against it, not the whole day."""
    m = CostMeter(daily_cap_usd=13.50, deep_per_run_cap_usd=50.00, deep_budget_fraction=0.60)
    # ~$9 of estimated spend fits the day ($13.50) but not the deep slice ($8.10).
    with pytest.raises(CostExceededError, match="deep"):
        m.check_or_abort_pre_run(
            probe_ids=["p1"], target_kind="openai_compat", total_exchanges=545, deep=True
        )


def _big_run(m, **kw):
    # owasp-llm-top10 shape: 552 judged exchanges.
    return m.check_or_abort_pre_run(
        probe_ids=["p"] * 205, target_kind="custom_http", total_exchanges=552,
        per_run_cap_override=0.50, **kw
    )


def test_preflight_default_estimate_is_haiku_rated(monkeypatch):
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    # 1000/4*1.2=300 in, 2000/4*1.2=600 out tokens per call; per exchange a Haiku fast call
    # ($1/$5 per M) and, as if it escalated, a Sonnet strong call ($3/$15 per M).
    expected = ((300 / 1e6 * 1.0 + 600 / 1e6 * 5.0) + (300 / 1e6 * 3.0 + 600 / 1e6 * 15.0)) * 10
    assert m.check_or_abort_pre_run(
        probe_ids=["p"], target_kind="custom_http", total_exchanges=10
    ) == pytest.approx(expected)


def test_preflight_ollama_fast_model_is_free(monkeypatch):
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "litellm")
    monkeypatch.setenv("REDTEAM_FAST_MODEL", "ollama/qwen2.5:32b")
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    assert _big_run(m) == 0.0


def test_preflight_openai_default_uses_luna_rates(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    expected = ((300 / 1e6 * 0.20 + 600 / 1e6 * 1.20) + (300 / 1e6 * 2.00 + 600 / 1e6 * 12.00)) * 10
    assert m.check_or_abort_pre_run(
        probe_ids=["p"], target_kind="custom_http", total_exchanges=10
    ) == pytest.approx(expected)


def test_preflight_unknown_litellm_model_stays_pessimistic(monkeypatch):
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "litellm")
    monkeypatch.setenv("REDTEAM_FAST_MODEL", "openai/my-local-vllm")
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    with pytest.raises(CostExceededError, match="per_run_cap"):
        _big_run(m)


def test_estimate_call_usd_uses_price_table_with_margin():
    # 4000 chars / 4 * 1.2 = 1200 input tokens at $1/M, 400 output tokens at $5/M.
    assert estimate_call_usd("claude-haiku-4-5-20251001", 4000, 400) == pytest.approx(0.0012 + 0.002)
    # Sonnet: 1200 * $3/M + 400 * $15/M.
    assert estimate_call_usd("claude-sonnet-4-6", 4000, 400) == pytest.approx(0.0036 + 0.006)
    # An unknown model is billed at the dearest known rate, as record() does.
    assert estimate_call_usd("no-such-model", 4000, 400) == pytest.approx(1200 * 15 / 1e6 + 400 * 75 / 1e6)


_HAIKU = 300 / 1e6 * 1.0 + 600 / 1e6 * 5.0
_SONNET = 300 / 1e6 * 3.0 + 600 / 1e6 * 15.0


@pytest.mark.parametrize("kind", ["openai_compat", "anthropic_native", "custom_http", "mcp_agent"])
def test_estimate_counts_only_argus_llm_calls(kind, monkeypatch):
    """Sends to the target are not Argus's spend. Per exchange: a fast judge call plus
    a strong one (every verdict assumed to escalate), and the attacker in deep mode."""
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50, deep_per_run_cap_usd=5.00)
    assert m.check_or_abort_pre_run(
        probe_ids=["p"], target_kind=kind, total_exchanges=10
    ) == pytest.approx((_HAIKU + _SONNET) * 10)
    assert m.check_or_abort_pre_run(
        probe_ids=["p"], target_kind=kind, total_exchanges=10, deep=True
    ) == pytest.approx((2 * _HAIKU + _SONNET) * 10)


def test_estimate_skips_escalation_when_fast_and_strong_are_one_model(monkeypatch):
    # Azure ships one deployment for both roles; the judge does not escalate then.
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "azure")
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    one_call = 300 / 1e6 * 1.0 + 600 / 1e6 * 5.0  # gpt-5.4-mini placeholder rate
    assert m.check_or_abort_pre_run(
        probe_ids=["p"], target_kind="custom_http", total_exchanges=10
    ) == pytest.approx(one_call * 10)


def test_per_run_cap_error_carries_the_estimate(monkeypatch):
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    m = CostMeter(daily_cap_usd=13.50, per_run_cap_usd=0.50)
    with pytest.raises(CostExceededError) as exc:
        m.check_or_abort_pre_run(probe_ids=["p"], target_kind="custom_http", total_exchanges=100)
    assert exc.value.estimated_usd == pytest.approx((_HAIKU + _SONNET) * 100)
    assert str(exc.value) == f"estimated cost ${exc.value.estimated_usd:.4f} > per_run_cap $0.50"


def test_daily_budget_error_carries_no_estimate():
    # A bigger per-run cap cannot fix an exhausted day, so no cap is suggested.
    m = CostMeter(daily_cap_usd=0.01, per_run_cap_usd=10.0)
    with pytest.raises(CostExceededError, match="daily") as exc:
        m.check_or_abort_pre_run(probe_ids=["p"], target_kind="custom_http", total_exchanges=10)
    assert exc.value.estimated_usd is None


def test_run_scope_cap_override_applies_to_record():
    m = CostMeter(daily_cap_usd=100.0, per_run_cap_usd=0.50)
    with m.run_scope("r", per_run_cap_usd=0.01):
        with pytest.raises(CostExceededError, match=r"per_run cap \$0\.01"):
            m.record("claude-haiku-4-5-20251001", 0, 10_000)  # $0.05
    with m.run_scope("r", per_run_cap_usd=1.00):
        assert m.record("claude-haiku-4-5-20251001", 0, 10_000) == pytest.approx(0.05)
    with m.run_scope("r"):  # no override: the meter's own cap
        with pytest.raises(CostExceededError, match=r"per_run cap \$0\.50"):
            m.record("claude-haiku-4-5-20251001", 0, 200_000)  # $1.00


def test_the_call_that_crosses_the_cap_is_counted_before_the_error():
    # record() runs after the call has returned: that money is spent, so it is counted.
    m = CostMeter(daily_cap_usd=100.0, per_run_cap_usd=0.08)
    with m.run_scope("r"):
        m.record("claude-haiku-4-5-20251001", 0, 10_000)  # $0.05
        with pytest.raises(CostExceededError, match=r"per_run cap \$0\.08 exceeded: this run has spent \$0\.1000"):
            m.record("claude-haiku-4-5-20251001", 0, 10_000)
        assert m.spent_in_current_run() == pytest.approx(0.10)
    assert m.spent_today() == pytest.approx(0.10)


def test_a_call_after_the_daily_cap_is_counted_and_refused():
    m = CostMeter(daily_cap_usd=0.05)
    m.record("claude-haiku-4-5-20251001", 0, 10_000)  # $0.05: reaches the cap
    with pytest.raises(CostExceededError, match="daily cap"):
        m.record("claude-haiku-4-5-20251001", 0, 10_000)
    assert m.spent_today() == pytest.approx(0.10)


def test_deep_crossing_call_counts_toward_the_deep_slice():
    m = CostMeter(daily_cap_usd=100.0, deep_per_run_cap_usd=0.08)
    with m.run_scope("r", deep=True):
        m.record("claude-haiku-4-5-20251001", 0, 10_000)
        with pytest.raises(CostExceededError, match="deep per_run cap"):
            m.record("claude-haiku-4-5-20251001", 0, 10_000)
    assert m.spent_today_deep() == pytest.approx(0.10)


def test_run_scope_resumes_from_spent_usd():
    m = CostMeter(daily_cap_usd=100.0, per_run_cap_usd=0.08)
    with m.run_scope("r", spent_usd=0.05):
        with pytest.raises(CostExceededError, match=r"spent \$0\.1000"):
            m.record("claude-haiku-4-5-20251001", 0, 10_000)
    assert m._spent_in_run is None
