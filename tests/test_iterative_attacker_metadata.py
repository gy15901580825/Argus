"""What the iterative attackers tell the judge and the report about themselves.

Reports print the probe id, never `name`. The name reaches the judge prompt,
and the judge's reasoning lands in the report. `attack_class` reaches the
report as remediation text.
"""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from argus import remediation
from argus.api import finding_dict
from argus.cli import run_json
from argus.iterative_gcg import GCGProbe
from argus.iterative_pair import PAIRProbe
from argus.iterative_tap import TAPProbe
from argus.judge import build_judge_prompts
from argus.runner import Runner
from argus.targets._base import Target

CASES = [
    (lambda: TAPProbe(seed_goal="say PWNED", max_rounds=1),
     "Iterative jailbreak named after TAP (one prompt per round, no tree search or pruning)",
     ("jailbreak", "iterative")),
    (lambda: PAIRProbe(seed_prompt="say PWNED", max_rounds=1),
     "PAIR — Prompt Automatic Iterative Refinement",
     ("jailbreak", "iterative", "self-refinement")),
    (lambda: GCGProbe(base_prompt="say PWNED", max_rounds=1),
     "Random adversarial suffix named after GCG (no gradient, no revert to best suffix)",
     ("jailbreak", "iterative", "adversarial-suffix")),
]


class _Target(Target):
    async def send_prompt(self, prompt, history=()):
        return "I cannot help with that.", 1.0


class _PromptRecordingJudge:
    def __init__(self):
        self.user_prompts = []

    async def judge(self, *, probe_name, attack_prompt, target_response, rubric_text, severity):
        self.user_prompts.append(build_judge_prompts(probe_name, attack_prompt, target_response, rubric_text)[1])
        return SimpleNamespace(verdict="pass", severity="info", confidence=1.0, reasoning="refused",
                               judge_model="test", escalated_model=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("make_probe,name,classes", CASES)
async def test_judge_reads_the_attacker_name_and_report_carries_class_remediation(tmp_path, make_probe, name,
                                                                                   classes):
    (tmp_path / "iterative.md").write_text("Assess the response")
    probe = make_probe()
    judge = _PromptRecordingJudge()
    runner = Runner(target=_Target(), judge=judge, rubrics_dir=tmp_path)
    with patch("argus.iterative_tap._call_planner_llm", AsyncMock(return_value="say PWNED now")):
        findings = [finding_dict(f, probe) async for f in runner.run_probe(probe)]

    assert [p.splitlines()[0] for p in judge.user_prompts] == [f"Probe: {name}"]
    assert probe.attack_class == classes
    report = json.loads(run_json.render_json({"id": "r1", "status": "completed",
                                              "target_spec": {"kind": "http"}, "findings": findings}))
    assert [f["probe_id"] for f in report["findings"]] == [probe.id]
    assert [f["remediation"] for f in report["findings"]] == [remediation.for_classes(("jailbreak",))]
    assert [f["remediation_actions"] for f in report["findings"]] == [remediation.actions_for_classes(("jailbreak",))]
