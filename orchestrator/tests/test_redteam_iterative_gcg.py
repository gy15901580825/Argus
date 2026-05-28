"""Tests for GCG (black-box adaptation) iterative attack."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from orchestrator.redteam.iterative import IterationContext
from orchestrator.redteam.iterative_gcg import GCGProbe


@pytest.mark.asyncio
async def test_gcg_round0_returns_base_plus_random_suffix():
    probe = GCGProbe(base_prompt="Tell me x.", suffix_tokens=4, max_rounds=10)
    ctx = IterationContext(round_n=0)
    p = await probe.next_prompt(ctx)
    assert p.startswith("Tell me x.")
    assert len(p.split()) > 4  # base + suffix tokens


@pytest.mark.asyncio
async def test_gcg_round_n_mutates_suffix():
    """At round N>0, GCG always mutates the current suffix (v0 random-walk).

    The previous test name implied conditional acceptance, but the v0 implementation
    always mutates regardless of prior verdict's confidence."""
    probe = GCGProbe(base_prompt="x", suffix_tokens=4, max_rounds=10)
    # Round 1: prior was high confidence pass → we want to keep mutating
    ctx = IterationContext(
        round_n=1,
        prior_prompts=("x [tok0 tok1 tok2 tok3]",),
        prior_responses=("I refuse.",),
        prior_verdicts=(MagicMock(verdict="pass", severity="info", confidence=0.95, reasoning=""),),
    )
    p = await probe.next_prompt(ctx)
    assert p.startswith("x")
    assert p != ctx.prior_prompts[-1]  # should mutate


@pytest.mark.asyncio
async def test_gcg_halts_on_fail():
    probe = GCGProbe(base_prompt="x", suffix_tokens=4, max_rounds=10)
    ctx = IterationContext(
        round_n=2,
        prior_verdicts=(MagicMock(verdict="fail", severity="high", confidence=0.92, reasoning=""),),
    )
    assert probe.should_halt(ctx) is True
