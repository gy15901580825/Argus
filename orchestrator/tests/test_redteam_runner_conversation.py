"""Runner-level conversation tests.

Covers the three behaviours that make `multi-turn` probes honest:
  1. `conversation: true` sends prompt N with turns 1..N-1 as history.
  2. Absent/false, every call still gets `history=()` — the legacy path.
  3. A conversation probe aimed at an adapter that cannot hold one is `skipped`,
     not silently flattened into single shots and reported as defended.
"""

import pytest
from pathlib import Path
from typing import ClassVar

from orchestrator.redteam.probe import Probe, ProbeMappings, load_probe
from orchestrator.redteam.runner import Runner, VERDICT_SKIPPED
from orchestrator.redteam.judge import Verdict
from orchestrator.redteam.targets._base import Target, Turn


class _RecordingTarget(Target):
    """Records every (prompt, history) pair it is asked to send."""

    supports_history: ClassVar[bool] = True
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"http-chat"})

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Turn, ...]]] = []

    async def send_prompt(self, prompt: str, history: tuple[Turn, ...] = ()):
        self.calls.append((prompt, history))
        return f"reply to {prompt}", 1.0


class _NoHistoryTarget(_RecordingTarget):
    supports_history: ClassVar[bool] = False


class _StubJudge:
    _cost_meter = None

    async def judge(self, probe_name, attack_prompt, target_response, rubric_text):
        return Verdict(
            verdict="pass",
            severity="info",
            confidence=0.9,
            reasoning="stub",
            judge_model="stub",
            escalated_model=None,
        )


def _probe(conversation: bool) -> Probe:
    return Probe(
        id="test_probe",
        name="Test probe",
        target_class=("http-chat",),
        attack_class=("jailbreak",),
        severity="medium",
        prompts=("turn one", "turn two", "turn three"),
        mappings=ProbeMappings(atlas=("AML.T0051",)),
        judge_model="stub",
        judge_rubric_path="rubrics/default.md",
        conversation=conversation,
    )


def _runner(target):
    rubrics = Path(__file__).parent.parent / "orchestrator" / "redteam" / "rubrics"
    return Runner(target=target, judge=_StubJudge(), rubrics_dir=rubrics)


@pytest.mark.asyncio
async def test_conversation_probe_accumulates_transcript():
    target = _RecordingTarget()
    findings = [f async for f in _runner(target).run_probe(_probe(conversation=True))]

    assert len(findings) == 3
    prompts = [c[0] for c in target.calls]
    assert prompts == ["turn one", "turn two", "turn three"]

    # Turn 1 opens cold.
    assert target.calls[0][1] == ()
    # Turn 2 sees turn 1's exchange.
    assert target.calls[1][1] == (
        Turn(role="user", content="turn one"),
        Turn(role="assistant", content="reply to turn one"),
    )
    # Turn 3 sees both prior exchanges, in order.
    assert target.calls[2][1] == (
        Turn(role="user", content="turn one"),
        Turn(role="assistant", content="reply to turn one"),
        Turn(role="user", content="turn two"),
        Turn(role="assistant", content="reply to turn two"),
    )


@pytest.mark.asyncio
async def test_non_conversation_probe_sends_every_prompt_cold():
    target = _RecordingTarget()
    findings = [f async for f in _runner(target).run_probe(_probe(conversation=False))]

    assert len(findings) == 3
    assert all(history == () for _, history in target.calls)


@pytest.mark.asyncio
async def test_conversation_probe_on_stateless_adapter_is_skipped():
    target = _NoHistoryTarget()
    findings = [f async for f in _runner(target).run_probe(_probe(conversation=True))]

    assert len(findings) == 1
    assert findings[0].verdict == VERDICT_SKIPPED
    assert "history" in findings[0].reasoning.lower()
    # Nothing was sent — a flattened conversation would be a false 'defended'.
    assert target.calls == []
    # Standards mappings survive so the skip is still traceable in reports.
    assert findings[0].atlas_id == ["AML.T0051"]


@pytest.mark.asyncio
async def test_non_conversation_probe_on_stateless_adapter_still_runs():
    target = _NoHistoryTarget()
    findings = [f async for f in _runner(target).run_probe(_probe(conversation=False))]
    assert len(findings) == 3
    assert findings[0].verdict != VERDICT_SKIPPED


# --------------------------------------------------------------------------
# Probe loader
# --------------------------------------------------------------------------

def test_probe_conversation_defaults_to_false(tmp_path):
    p = tmp_path / "x.yaml"
    p.write_text(
        "id: x\nname: X\ntarget_class: ['http-chat']\nattack_class: ['jailbreak']\n"
        "severity: low\nprompts: ['a']\n"
    )
    assert load_probe(p).conversation is False


def test_probe_conversation_true_is_loaded(tmp_path):
    p = tmp_path / "x.yaml"
    p.write_text(
        "id: x\nname: X\ntarget_class: ['http-chat']\nattack_class: ['jailbreak']\n"
        "severity: low\nconversation: true\nprompts: ['a', 'b']\n"
    )
    assert load_probe(p).conversation is True


def test_shipped_multi_turn_probes_declare_conversation():
    """Any probe claiming multi-turn must actually hold a conversation.

    This is the regression that motivated the feature: syscard_crescendo and
    syscard_sleeper_agent carried `multi-turn` in attack_class while firing
    independent cold-start requests.
    """
    from orchestrator.redteam.probe import load_all_probes

    probes_dir = Path(__file__).parent.parent / "orchestrator" / "redteam" / "probes"
    offenders = [
        p.id
        for p in load_all_probes(probes_dir)
        if "multi-turn" in p.attack_class and not p.conversation
    ]
    assert offenders == [], f"probes claim multi-turn but are single-shot: {offenders}"
