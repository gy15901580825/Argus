"""Deep-run budget partition.

CostMeter.record rejects ALL spend once the daily cap is reached, so an unpartitioned
budget lets two $5 deep runs exhaust a $13.50 day and starve every subsequent static
CI gate with aborted_cost. Deep runs therefore get their own slice.
"""

import pytest

from orchestrator.redteam.cost_meter import CostMeter, CostExceededError


HAIKU = "claude-haiku-4-5-20251001"


def _meter(**kw) -> CostMeter:
    return CostMeter(daily_cap_usd=13.50, **kw)


def _burn(meter: CostMeter, usd: float, deep: bool, tolerate_exhaustion: bool = False) -> None:
    """Spend roughly `usd` inside a run scope, in small increments.

    With tolerate_exhaustion, a cap being hit mid-burn is the expected outcome
    rather than a test failure — used by the tests that deliberately drain a slice.
    """
    with meter.run_scope("run", deep=deep):
        try:
            while meter.spent_in_current_run() < usd:
                meter.record(model=HAIKU, input_tokens=0, output_tokens=2_000)
        except CostExceededError:
            if not tolerate_exhaustion:
                raise


def test_deep_daily_cap_is_a_fraction_of_the_daily_cap():
    m = _meter(deep_budget_fraction=0.60)
    assert m.deep_daily_cap_usd == pytest.approx(13.50 * 0.60)
    assert m.deep_budget_remaining() == pytest.approx(8.10)


def test_deep_run_uses_the_deep_per_run_cap_not_the_static_one():
    m = _meter(per_run_cap_usd=0.50, deep_per_run_cap_usd=5.00)
    # A static run is capped at 0.50 ...
    with pytest.raises(CostExceededError, match="per_run cap"):
        _burn(m, 0.80, deep=False)
    # ... while a deep run of the same size is fine.
    _burn(_meter(per_run_cap_usd=0.50, deep_per_run_cap_usd=5.00), 0.80, deep=True)


def test_deep_spend_is_tracked_separately_from_total():
    m = _meter()
    _burn(m, 1.0, deep=True)
    assert m.spent_today_deep() > 0
    assert m.spent_today() >= m.spent_today_deep()
    before_deep = m.spent_today_deep()
    _burn(m, 0.2, deep=False, tolerate_exhaustion=True)
    # A static run must not consume the deep slice.
    assert m.spent_today_deep() == pytest.approx(before_deep)


def test_exhausting_the_deep_slice_refuses_new_deep_runs():
    m = _meter(deep_per_run_cap_usd=5.00, deep_budget_fraction=0.60)  # 8.10 deep
    _burn(m, 4.5, deep=True)
    _burn(m, 4.5, deep=True, tolerate_exhaustion=True)  # drains past 8.10 mid-run
    assert m.deep_budget_remaining() == 0.0
    with pytest.raises(CostExceededError, match="deep budget"):
        with m.run_scope("next-deep", deep=True):
            pass


def test_static_runs_survive_deep_exhaustion():
    """The whole point of the partition."""
    m = _meter(deep_per_run_cap_usd=5.00, deep_budget_fraction=0.60)
    _burn(m, 4.5, deep=True)
    _burn(m, 4.5, deep=True, tolerate_exhaustion=True)
    assert m.deep_budget_remaining() == 0.0
    assert m.can_start_deep_run() is False
    # A static CI scan still runs.
    with m.run_scope("static-ci", deep=False):
        cost = m.record(model=HAIKU, input_tokens=1000, output_tokens=100)
    assert cost > 0


def test_can_start_deep_run_false_when_whole_day_is_gone():
    m = _meter(per_run_cap_usd=100.0, deep_budget_fraction=1.0)
    _burn(m, 13.5, deep=False)
    assert m.can_start_deep_run() is False


def test_default_run_scope_is_static():
    """Backwards compatibility: existing callers pass no `deep` kwarg."""
    m = _meter(per_run_cap_usd=0.50)
    with pytest.raises(CostExceededError, match="^per_run cap"):
        _burn(m, 0.80, deep=False)


def test_day_rollover_resets_the_deep_slice(monkeypatch):
    import datetime as _dt
    from orchestrator.redteam import cost_meter as cm

    m = _meter()
    _burn(m, 1.0, deep=True)
    assert m.spent_today_deep() > 0

    real_date = cm.date

    class _Tomorrow(real_date):
        @classmethod
        def today(cls):
            return real_date.today() + _dt.timedelta(days=1)

    monkeypatch.setattr(cm, "date", _Tomorrow)
    assert m.spent_today_deep() == 0.0
    assert m.deep_budget_remaining() == pytest.approx(8.10)


# --------------------------------------------------------------------------
# Pricing table — provider-agnostic since the Azure work
# --------------------------------------------------------------------------

def test_azure_models_are_priced():
    """Without an entry, Azure traffic was billed at Haiku rates and the cap lied."""
    from orchestrator.redteam.cost_meter import _PRICES_PER_M_TOKENS

    assert "gpt-5.4-mini" in _PRICES_PER_M_TOKENS
    for field in ("input", "output"):
        assert _PRICES_PER_M_TOKENS["gpt-5.4-mini"][field] > 0


def test_unknown_model_is_priced_pessimistically_not_cheaply():
    """A cost cap must over-estimate an unpriced model, never under-estimate it.

    The old fallback used the CHEAPEST entry (Haiku), so an unrecognised model
    silently under-counted and the daily cap let real spend run past it.
    """
    from orchestrator.redteam.cost_meter import _PRICES_PER_M_TOKENS, _price_for

    prices = _price_for("some-model-nobody-registered")
    most_expensive_out = max(p["output"] for p in _PRICES_PER_M_TOKENS.values())
    assert prices["output"] == most_expensive_out
    cheapest_out = min(p["output"] for p in _PRICES_PER_M_TOKENS.values())
    assert prices["output"] > cheapest_out, "unknown model must not be billed at the cheapest rate"


def test_unknown_model_pricing_is_logged(caplog):
    from orchestrator.redteam.cost_meter import _price_for

    with caplog.at_level("WARNING"):
        _price_for("mystery-model-9")
    assert any("mystery-model-9" in r.message for r in caplog.records)


def test_known_models_are_unaffected_by_the_pessimistic_fallback():
    from orchestrator.redteam.cost_meter import _PRICES_PER_M_TOKENS, _price_for

    for name, expected in _PRICES_PER_M_TOKENS.items():
        assert _price_for(name) == expected
