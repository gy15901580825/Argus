"""Offline regressions for typical preflight spend and the retained worst case."""
import pytest

from argus import cost_meter as cm


@pytest.fixture
def hosted_judge(monkeypatch):
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "azure")
    monkeypatch.setenv("REDTEAM_FAST_MODEL", "gpt-6.1-sol")
    monkeypatch.setenv("REDTEAM_STRONG_MODEL", "gpt-6.1-sol")
    monkeypatch.delenv("ARGUS_ESTIMATE_OUTPUT_TOKENS", raising=False)


def test_hosted_suite_typical_spend(hosted_judge):
    # The old $27.54 at $4/$15 per M and 4000 output tokens implies 450
    # judged exchanges across 279 probes, including multi-prompt probes.
    assert 0.51 < cm.estimate_run_usd(450) <= 3 * 0.51


def test_hosted_suite_worst_case_is_legacy_formula(hosted_judge):
    estimate = cm.estimate_run_cost(450)
    assert estimate.typical == pytest.approx(1.404)
    assert estimate.worst_case == pytest.approx((300 * 4 + 4000 * 15) / 1e6 * 450)
    assert estimate.worst_case == pytest.approx(27.54)


def test_admission_uses_typical_for_run_and_daily_caps(hosted_judge):
    meter = cm.CostMeter(daily_cap_usd=2, per_run_cap_usd=2)
    assert meter.check_or_abort_pre_run(["p"] * 279, "custom_http", total_exchanges=450) < 2


def test_output_override_scales_output_cost(hosted_judge, monkeypatch):
    before = cm.estimate_run_usd(450)
    monkeypatch.setenv("ARGUS_ESTIMATE_OUTPUT_TOKENS", "256")
    after = cm.estimate_run_usd(450)
    input_cost = 450 * 300 * 4 / 1e6
    assert after - input_cost == pytest.approx(2 * (before - input_cost))


@pytest.mark.parametrize("value", ["", "0", "-1", "1.5", "nan", "inf", "abc", "4001"])
def test_invalid_output_override_is_clear(hosted_judge, monkeypatch, value):
    monkeypatch.setenv("ARGUS_ESTIMATE_OUTPUT_TOKENS", value)
    with pytest.raises(ValueError, match="ARGUS_ESTIMATE_OUTPUT_TOKENS.*integer.*1.*4000"):
        cm.estimate_run_usd(1)


def test_rejection_names_both_estimates(hosted_judge):
    meter = cm.CostMeter(daily_cap_usd=100, per_run_cap_usd=1)
    with pytest.raises(cm.CostExceededError, match=r"typical \$1.4040, worst case \$27.5400"):
        meter.check_or_abort_pre_run(["p"] * 279, "custom_http", total_exchanges=450)


async def test_local_estimate_event_retains_legacy_field(hosted_judge, monkeypatch):
    from argus import api, local

    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test")
    monkeypatch.setattr(api, "_COST_METER", cm.CostMeter(daily_cap_usd=100, deep_per_run_cap_usd=100))
    target = {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1/v1/chat/completions", "model": "test"}
    stream = local.run_local(target, ["owasp_01_prompt_injection_basic"], mode="deep", deep_pairs=1, max_rounds=1)
    try:
        event = await anext(stream)  # No target or model call is made before this event.
        assert event["type"] == "estimate"
        assert event["estimated_usd"] == event["worst_case_usd"]
        assert 0 < event["typical_usd"] < event["worst_case_usd"]
    finally:
        await stream.aclose()


def test_jev_keeps_judge_assumption_and_weights_explanation(monkeypatch):
    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "jev")
    monkeypatch.setenv("REDTEAM_EXPLAIN_MODEL", "gpt-6.1-sol")
    estimate = cm.estimate_run_cost(10)
    assert estimate.typical == pytest.approx(10 * (300 * 0.042 / 1e6 + 0.25 * (300 * 4 + 128 * 15) / 1e6))
    assert estimate.worst_case == pytest.approx(10 * (300 * 0.042 / 1e6 + (300 * 4 + 4000 * 15) / 1e6))


def test_server_preflight_invalid_override_is_422(hosted_judge, monkeypatch):
    from fastapi.testclient import TestClient
    from argus.server import app

    monkeypatch.setenv("ARGUS_ESTIMATE_OUTPUT_TOKENS", "bad")
    response = TestClient(app).post("/redteam/run/preflight", json={
        "target": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1/v1/chat/completions", "model": "test"},
        "probe_ids": ["owasp_01_prompt_injection_basic"],
    })
    assert response.status_code == 422
    assert "ARGUS_ESTIMATE_OUTPUT_TOKENS must be an integer" in response.json()["detail"]
