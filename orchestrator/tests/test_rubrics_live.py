"""Rubric regression fixtures — LIVE tier (deselected by default, real LLM calls).

This is the only tier that detects **rubric-prose drift**. It sends each fixture's
canned ``target_response`` to the real Haiku judge under the rubric's real text and
asserts the resulting verdict matches ``expect_verdict``. If someone edits a rubric
in a way that flips a clearly-defended response to ``fail`` (or a clearly-compromised
one to ``pass``), this is what catches it. ``test_rubrics_mocked.py`` cannot — it
replays a canned verdict and never lets the prose influence anything.

Deselected by default via ``addopts = [..., "-m", "not rubric_live"]`` in
``pyproject.toml``, so CI never pays for it. Run it deliberately:

    ANTHROPIC_API_KEY=sk-ant-... python3 -m pytest tests/test_rubrics_live.py -m rubric_live

Or one rubric at a time while editing its prose:

    ANTHROPIC_API_KEY=sk-ant-... python3 -m pytest tests/test_rubrics_live.py \\
        -m rubric_live -k prompt_injection

Cost: two Haiku calls per rubric per case (~34 calls for a full sweep at time of
writing), plus a Sonnet escalation on whichever fail cases Haiku grades high
severity with confidence >= 0.7. Cents, not dollars — but not free, hence the gate.

Skips (never errors) when ``ANTHROPIC_API_KEY`` is unset.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import Judge

FIXTURES_DIR = Path(__file__).parent / "rubrics"
RUBRICS_DIR = Path(__file__).resolve().parents[1] / "orchestrator" / "redteam" / "rubrics"

# Whole module is live: marked for deselection, and skipped outright without a key.
pytestmark = [
    pytest.mark.rubric_live,
    pytest.mark.skipif(
        not os.environ.get("ANTHROPIC_API_KEY"),
        reason="set ANTHROPIC_API_KEY to run the live rubric tier",
    ),
]

_FIXTURE_PATHS = sorted(FIXTURES_DIR.glob("*.fixture.yaml"))

# One param per (rubric, case) so a failure names both.
_CASES = [
    (path, case_name)
    for path in _FIXTURE_PATHS
    for case_name in ("pass_case", "fail_case")
]
_CASE_IDS = [
    f"{path.name.removesuffix('.fixture.yaml')}-{case_name.removesuffix('_case')}"
    for path, case_name in _CASES
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("path", "case_name"), _CASES, ids=_CASE_IDS)
async def test_rubric_grades_fixture_as_expected(path: Path, case_name: str):
    fixture = yaml.safe_load(path.read_text(encoding="utf-8"))
    case = fixture[case_name]
    rubric_text = (RUBRICS_DIR / fixture["rubric"]).read_text(encoding="utf-8")

    judge = Judge(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        cost_meter=CostMeter(daily_cap_usd=1.0),
    )
    verdict = await judge.judge(
        probe_name=case["probe_name"],
        attack_prompt=case["attack_prompt"],
        target_response=case["target_response"],
        rubric_text=rubric_text,
    )

    assert verdict.verdict == case["expect_verdict"], (
        f"{fixture['rubric']} / {case_name}: judge said {verdict.verdict!r} "
        f"(severity={verdict.severity}, confidence={verdict.confidence}), "
        f"expected {case['expect_verdict']!r}.\n"
        f"Judge reasoning: {verdict.reasoning}\n"
        "Either the rubric prose drifted or the fixture no longer discriminates."
    )
