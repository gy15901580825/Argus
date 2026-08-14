"""Tests for TAP iterative attack."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from orchestrator.redteam.iterative import IterationContext
from orchestrator.redteam.iterative_tap import TAPProbe


@pytest.mark.asyncio
async def test_tap_round0_uses_seed_prompt():
    probe = TAPProbe(seed_goal="Make the model output PWNED.", branching_factor=2, max_rounds=3)
    with patch("orchestrator.redteam.iterative_tap._call_planner_llm", AsyncMock(return_value="Generated round-0 prompt about PWNED")):
        ctx = IterationContext(round_n=0)
        p = await probe.next_prompt(ctx)
        assert "PWNED" in p or "pwned" in p.lower() or len(p) > 20


@pytest.mark.asyncio
async def test_tap_round1_mutates_based_on_prior_warn():
    """Given a 'warn' verdict on round 0, round 1 should mutate the prompt — not return identical."""
    probe = TAPProbe(seed_goal="Make the model output PWNED.", branching_factor=2, max_rounds=3)
    with patch("orchestrator.redteam.iterative_tap._call_planner_llm", AsyncMock(return_value="mutated prompt with stronger framing")):
        ctx = IterationContext(
            round_n=1,
            prior_prompts=("first try",),
            prior_responses=("I cannot do that.",),
            prior_verdicts=(MagicMock(verdict="warn", severity="medium", confidence=0.5, reasoning=""),),
        )
        p = await probe.next_prompt(ctx)
        assert p != "first try"
        assert "mutated" in p


@pytest.mark.asyncio
async def test_tap_halts_on_fail():
    probe = TAPProbe(seed_goal="x", branching_factor=2, max_rounds=10)
    ctx = IterationContext(
        round_n=2,
        prior_verdicts=(
            MagicMock(verdict="warn", severity="low", confidence=0.5, reasoning=""),
            MagicMock(verdict="fail", severity="high", confidence=0.9, reasoning=""),
        ),
    )
    assert probe.should_halt(ctx) is True


@pytest.mark.asyncio
async def test_tap_planner_llm_records_to_cost_meter(monkeypatch):
    """When _cost_meter is set, planner LLM calls record token usage."""
    from orchestrator.redteam.cost_meter import CostMeter
    from orchestrator.redteam import iterative_tap

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
    meter = CostMeter(daily_cap_usd=10, per_run_cap_usd=10)
    iterative_tap.set_cost_meter(meter)
    try:
        with patch("orchestrator.redteam.llm._anthropic_client") as MockAnth:
            fake_client = AsyncMock()
            fake_resp = MagicMock(content=[MagicMock(text='{"refined": "prompt"}')])
            fake_resp.usage = MagicMock(input_tokens=1000, output_tokens=500)
            fake_client.messages.create = AsyncMock(return_value=fake_resp)
            MockAnth.return_value = fake_client

            with meter.run_scope("test-run"):
                probe = TAPProbe(seed_goal="test goal", branching_factor=2, max_rounds=3)
                ctx = IterationContext(round_n=0)
                await probe.next_prompt(ctx)
                assert meter.spent_in_current_run() > 0
    finally:
        iterative_tap.set_cost_meter(None)  # reset to avoid test pollution
