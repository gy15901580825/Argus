"""Rubric regression fixtures — LIVE tier (deselected by default, real LLM calls).

This is the only tier that detects **rubric-prose drift**. It sends each fixture's
canned ``target_response`` to the real judge under the rubric's real text and
checks the resulting verdict against the case's expectation (``expect_verdict``, or ``expect_not`` for the empty-reply cases). If someone edits a rubric
in a way that flips a clearly-defended response to ``fail`` (or a clearly-compromised
one to ``pass``), this is what catches it. ``test_rubrics_mocked.py`` cannot — it
replays a canned verdict and never lets the prose influence anything.

Deselected by default via ``addopts = [..., "-m", "not rubric_live"]`` in
``pyproject.toml``, so CI never pays for it. The judge comes from the same environment
the CLI reads (``REDTEAM_MODEL_PROVIDER``, ``REDTEAM_FAST_MODEL``, the fallback settings
and so on), so any judge works. Run it deliberately:

    ANTHROPIC_API_KEY=sk-ant-... python3 -m pytest tests/test_rubrics_live.py -m rubric_live

With an Azure judge:

    REDTEAM_MODEL_PROVIDER=azure REDTEAM_FAST_MODEL=<deployment> \\
        AZURE_API_KEY=... AZURE_API_BASE=https://<resource>.openai.azure.com AZURE_API_VERSION=<version> \\
        python3 -m pytest tests/test_rubrics_live.py -m rubric_live

Or one rubric at a time while editing its prose:

    ANTHROPIC_API_KEY=sk-ant-... python3 -m pytest tests/test_rubrics_live.py \\
        -m rubric_live -k prompt_injection

Cost with the default Anthropic judge: one Haiku call per case (155 cases at time of writing), plus a Sonnet escalation
on whichever fail cases Haiku grades high severity with confidence >= 0.7. Cents, not dollars — but not free, hence
the gate.

Skips (never errors) when the chosen judge's credential is unset, or its configuration is invalid; the skip reason
names the variable.
"""

from __future__ import annotations

import os
from typing import Mapping, Optional

import pytest

from argus import llm
from argus.cost_meter import CostMeter
from argus.judge import Judge
from argus.judge_bench import credential_problem, load_all_cases, rubric_text


def live_judge_config(env: Mapping[str, str]) -> tuple[Optional[llm.LLMConfig], str]:
    """The judge config the CLI would build from `env`, or None and the reason to skip."""
    try:
        cfg = llm.resolve_config(env)
    except ValueError as e:
        return None, f"live rubric tier: judge configuration is invalid: {e}"
    problem = credential_problem(cfg, env)
    if problem:
        return None, f"live rubric tier: {problem}"
    return cfg, ""


_CONFIG, _SKIP_REASON = live_judge_config(os.environ)

# Whole module is live: marked for deselection, and skipped outright without the judge's credential.
pytestmark = [
    pytest.mark.rubric_live,
    pytest.mark.skipif(_CONFIG is None, reason=_SKIP_REASON),
]

_CASES_ALL = load_all_cases()
_CASE_IDS = [f"{c.rubric.removesuffix('.md')}-{c.case_id.replace(':', '-')}" for c in _CASES_ALL]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES_ALL, ids=_CASE_IDS)
async def test_rubric_grades_fixture_as_expected(case):
    judge = Judge(api_key="", cost_meter=CostMeter(daily_cap_usd=1.0), config=_CONFIG)
    verdict = await judge.judge(
        probe_name=case.probe_name,
        attack_prompt=case.attack_prompt,
        target_response=case.target_response,
        rubric_text=rubric_text(case.rubric),
    )

    assert case.is_correct(verdict.verdict), (
        f"{case.rubric} / {case.case_id}: judge said {verdict.verdict!r} "
        f"(severity={verdict.severity}, confidence={verdict.confidence}), "
        f"expected {case.expect_verdict or 'not ' + '/'.join(case.expect_not)!r}.\n"
        f"Judge reasoning: {verdict.reasoning}\n"
        "Either the rubric prose drifted or the fixture no longer discriminates."
    )
