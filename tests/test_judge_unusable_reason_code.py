"""Every finding whose judge reply could not be used carries evidence.reason_code=judge_unusable."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from argus.judge import Verdict
from argus.persona_loader import Persona, Strategy
from argus.persona_strategy import PersonaStrategyProbe
from argus.probe import Probe, ProbeMappings
from argus.runner import Runner

CLEAN = {"interaction_count": 1, "page_loads": 1, "trap_requests": []}


class _Target:
    compatible_classes = frozenset({"browser-using", "llm_chat"})
    supports_history = False

    async def send_prompt(self, prompt, history=()):
        return "I visited the page", 5.0

    async def collect_evidence(self):
        return dict(CLEAN)


class _Judge:
    """Answers from `answers` in order; a ValueError entry is an unusable reply."""
    _cost_meter = None

    def __init__(self, *answers):
        self._answers = list(answers)

    async def judge(self, **kwargs):
        answer = self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]
        if isinstance(answer, Exception):
            raise answer
        return Verdict(verdict=answer, severity="low", confidence=0.6, reasoning="ok", judge_model="judge-m")


def _probe(tmp_path, **kw):
    (tmp_path / "default.md").write_text("rubric")
    base = dict(
        id="p", name="p", target_class=("browser-using",), attack_class=("indirect-injection",),
        severity="high", prompts=("open the page",), mappings=ProbeMappings(),
        judge_rubric_path="rubrics/default.md",
        assertions=({"no_trap_request": True},), judge_when_assertions_pass=True,
    )
    base.update(kw)
    return Probe(**base)


async def _run(probe, judge, tmp_path):
    return [f async for f in Runner(target=_Target(), judge=judge, rubrics_dir=tmp_path).run_probe(probe)]


async def test_static_hybrid_pass_with_an_unusable_judge_reply(tmp_path):
    [f] = await _run(_probe(tmp_path), _Judge(ValueError("not json")), tmp_path)
    assert f.verdict == "error" and f.evidence["reason_code"] == "judge_unusable"
    assert f.evidence["trap_requests"] == []  # the captured evidence stays


async def test_static_judged_probe_with_an_unusable_judge_reply(tmp_path):
    probe = _probe(tmp_path, assertions=(), judge_when_assertions_pass=False, target_class=("llm_chat",))
    [f] = await _run(probe, _Judge(ValueError("not json")), tmp_path)
    assert f.verdict == "error" and f.evidence == {"reason_code": "judge_unusable"}


async def test_a_usable_judge_reply_leaves_no_reason_code(tmp_path):
    [f] = await _run(_probe(tmp_path), _Judge("pass"), tmp_path)
    assert f.verdict == "pass" and "reason_code" not in f.evidence


def _iterative(**kw):
    probe = MagicMock()
    probe.id, probe.name, probe.iterative = "iter_1", "iter", True
    probe.target_class = ("llm_chat",)
    probe.judge_rubric_path = "rubrics/default.md"
    probe.mappings = ProbeMappings()
    probe.should_halt = MagicMock(return_value=False)
    probe.next_prompt = AsyncMock(return_value="next prompt")
    probe.assertions = ()
    probe.contact_markers = ()
    for key, value in kw.items():
        setattr(probe, key, value)
    return probe


async def test_iterative_judged_round_with_an_unusable_judge_reply(tmp_path):
    (tmp_path / "default.md").write_text("rubric")
    findings = await _run(_iterative(), _Judge("warn", ValueError("not json")), tmp_path)
    assert [f.verdict for f in findings] == ["warn", "error"]
    assert findings[1].evidence == {"reason_code": "judge_unusable"}


async def test_iterative_hybrid_round_with_an_unusable_judge_reply(tmp_path):
    (tmp_path / "default.md").write_text("rubric")
    probe = _iterative(assertions=({"no_trap_request": True},), judge_when_assertions_pass=True,
                       scenario_kind=None, scenario_payload="", requires_interaction=True)
    findings = await _run(probe, _Judge(ValueError("not json")), tmp_path)
    assert findings[-1].verdict == "error"
    assert findings[-1].evidence["reason_code"] == "judge_unusable"


PERSONA = Persona(id="p", name="P", voice="v", traits="t", when_to_use="w", body="b")
STRATEGY = Strategy(id="s", name="S", mechanics="m", when_to_use="w", escalation_notes="e", body="b")


async def test_deep_round_with_an_unusable_judge_reply(tmp_path):
    probe = PersonaStrategyProbe(base=_probe(tmp_path), persona=PERSONA, strategy=STRATEGY, max_rounds=2)
    with patch("argus.persona_strategy._call_attacker_llm", new=AsyncMock(return_value="go on")):
        [f] = await _run(probe, _Judge(ValueError("not json")), tmp_path)
    assert f.verdict == "error" and f.evidence["stop_reason"] == "judge_unusable"
    assert f.evidence["reason_code"] == "judge_unusable"
