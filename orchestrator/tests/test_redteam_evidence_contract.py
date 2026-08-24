"""The evidence channel: a target may report what it observed, not just what it said."""

import datetime
import uuid

import pytest

from orchestrator.redteam.runner import Finding
from orchestrator.redteam.targets import _BUILDERS
from orchestrator.redteam.targets._base import Target


@pytest.mark.asyncio
async def test_base_target_collects_empty_evidence():
    class Bare(Target):
        async def send_prompt(self, prompt, history=()):
            return "hi", 1.0

    assert await Bare().collect_evidence() == {}


def test_every_shipped_adapter_inherits_the_default():
    """Adding the channel must not require touching the five text-only adapters."""
    for kind, (_spec, target_cls) in _BUILDERS.items():
        assert hasattr(target_cls, "collect_evidence"), kind


def test_finding_evidence_defaults_to_none():
    f = Finding(
        id=uuid.uuid4(), probe_id="p", attack_prompt="", target_response="",
        target_latency_ms=0.0, probed_at=datetime.datetime.now(datetime.timezone.utc),
        verdict="pass", severity="info", confidence=1.0, reasoning="",
        judge_model="", escalated_model=None,
    )
    assert f.evidence is None
