"""Rubric regression fixtures — MOCKED tier (default, every commit, zero LLM calls).

WHAT THIS TIER DOES NOT TEST
============================
This tier does **not** test rubric-prose quality. The Anthropic client is patched
to replay a canned verdict, so the rubric text is passed to a mock and its content
never influences the result. Editing a rubric's prose cannot fail these tests.

Only ``test_rubrics_live.py`` (marked ``rubric_live``, deselected by default) can
detect rubric-prose drift, because only it puts the fixture's ``target_response``
in front of a real judge.

WHAT THIS TIER DOES TEST
========================
1. Fixture integrity — every rubric in ``redteam/rubrics/`` has exactly one
   fixture, each fixture is well-formed, and its ``rubric:`` field points at a
   file that exists. A malformed or orphaned fixture fails here rather than
   silently degrading the live tier.
2. Judge plumbing, exercised once per fixture with that fixture's real probe
   name / attack prompt / target response as inputs:
   - verdict parsing (``pass`` and ``fail`` both round-trip out of the JSON),
   - severity normalization (``judge._normalize_severity``: ``"n/a"`` -> ``"info"``),
   - confidence coercion (``judge._parse_confidence``: ``"high"`` -> ``0.9``),
   - the Sonnet escalation branch (severity >= high AND confidence >= 0.7).

Mocking style follows ``tests/test_redteam_judge.py``: patch
``orchestrator.redteam.judge.anthropic.AsyncAnthropic`` and hand back an
``AsyncMock`` whose ``messages.create`` returns a canned response object.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import HAIKU_MODEL, SONNET_MODEL, Judge

FIXTURES_DIR = Path(__file__).parent / "rubrics"
RUBRICS_DIR = Path(__file__).resolve().parents[1] / "orchestrator" / "redteam" / "rubrics"

REQUIRED_CASE_KEYS = {"probe_name", "attack_prompt", "target_response", "expect_verdict"}


def _fixture_paths() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*.fixture.yaml"))


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# Parameter ids are the rubric stem, so a failure names the rubric directly.
FIXTURE_PATHS = _fixture_paths()
FIXTURE_IDS = [p.name.removesuffix(".fixture.yaml") for p in FIXTURE_PATHS]


def _canned(text: str, input_tokens: int = 100, output_tokens: int = 20) -> MagicMock:
    """A stand-in for an Anthropic Messages response, shaped like judge.py expects."""
    resp = MagicMock()
    resp.content = [MagicMock(text=text)]
    resp.usage = MagicMock(input_tokens=input_tokens, output_tokens=output_tokens)
    return resp


def _client_replaying(*responses: MagicMock) -> AsyncMock:
    """An AsyncAnthropic stand-in that hands back `responses` in order."""
    client = AsyncMock()
    client.messages.create = AsyncMock(side_effect=list(responses))
    return client


def _rubric_text(fixture: dict) -> str:
    return (RUBRICS_DIR / fixture["rubric"]).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Fixture integrity
# ---------------------------------------------------------------------------


def test_every_rubric_has_exactly_one_fixture():
    """A new rubric without a fixture is a silent regression-coverage hole."""
    rubrics = {p.name for p in RUBRICS_DIR.glob("*.md")}
    covered = {_load(p)["rubric"] for p in FIXTURE_PATHS}

    assert rubrics, f"no rubrics found under {RUBRICS_DIR}"
    assert rubrics - covered == set(), f"rubrics with no fixture: {sorted(rubrics - covered)}"
    assert covered - rubrics == set(), f"fixtures for missing rubrics: {sorted(covered - rubrics)}"
    assert len(covered) == len(FIXTURE_PATHS), "two fixtures claim the same rubric"


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=FIXTURE_IDS)
def test_fixture_is_well_formed(path: Path):
    fixture = _load(path)

    assert set(fixture) <= {"rubric", "pass_case", "fail_case", "extra_cases"}, (
        f"{path.name}: unexpected top-level keys {sorted(fixture)}"
    )
    assert {"rubric", "pass_case", "fail_case"} <= set(fixture), (
        f"{path.name}: missing required keys {sorted({'rubric','pass_case','fail_case'} - set(fixture))}"
    )

    rubric_name = fixture["rubric"]
    assert (RUBRICS_DIR / rubric_name).is_file(), f"{path.name}: no such rubric {rubric_name}"
    assert path.name == rubric_name.replace(".md", ".fixture.yaml"), (
        f"{path.name}: filename does not match rubric {rubric_name}"
    )

    # extra_cases hold discriminators beyond the required pair — e.g. the
    # "reports the injection" case that the 2026-08-13 browser_visual fix turns on.
    # They carry an extra `name` for the failure message.
    for i, extra in enumerate(fixture.get("extra_cases") or []):
        assert set(extra) == REQUIRED_CASE_KEYS | {"name"}, (
            f"{path.name}:extra_cases[{i}]: keys {sorted(extra)} unexpected"
        )
        assert extra["expect_verdict"] in {"pass", "fail", "warn", "error"}, (
            f"{path.name}:extra_cases[{i}]: bad expect_verdict {extra['expect_verdict']!r}"
        )
        for key in REQUIRED_CASE_KEYS:
            assert isinstance(extra[key], str) and extra[key].strip(), (
                f"{path.name}:extra_cases[{i}]:{key} must be a non-empty string"
            )

    for case_name, expected in (("pass_case", "pass"), ("fail_case", "fail")):
        case = fixture[case_name]
        assert set(case) == REQUIRED_CASE_KEYS, (
            f"{path.name}:{case_name}: keys {sorted(case)} != {sorted(REQUIRED_CASE_KEYS)}"
        )
        for key in REQUIRED_CASE_KEYS:
            assert isinstance(case[key], str) and case[key].strip(), (
                f"{path.name}:{case_name}:{key} must be a non-empty string"
            )
        assert case["expect_verdict"] == expected, (
            f"{path.name}:{case_name}: expect_verdict must be {expected!r}"
        )

    assert fixture["pass_case"]["target_response"] != fixture["fail_case"]["target_response"], (
        f"{path.name}: pass and fail cases share a target_response — nothing is discriminated"
    )


# ---------------------------------------------------------------------------
# 2. Judge plumbing, driven by each fixture's own inputs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=FIXTURE_IDS)
async def test_pass_case_parses_and_does_not_escalate(path: Path):
    """pass verdict round-trips; severity 'n/a' normalizes to 'info'; no Sonnet call."""
    fixture = _load(path)
    case = fixture["pass_case"]

    # severity "n/a" is what Haiku actually emits on a pass — exercises _normalize_severity.
    canned = _canned(
        json.dumps(
            {
                "verdict": "pass",
                "severity": "n/a",
                "confidence": 0.92,
                "reasoning": "target held the line",
            }
        )
    )

    with patch("orchestrator.redteam.judge.anthropic.AsyncAnthropic") as MockClient:
        client = _client_replaying(canned)
        MockClient.return_value = client

        judge = Judge(api_key="sk-ant-test", cost_meter=CostMeter(daily_cap_usd=10.0))
        verdict = await judge.judge(
            probe_name=case["probe_name"],
            attack_prompt=case["attack_prompt"],
            target_response=case["target_response"],
            rubric_text=_rubric_text(fixture),
        )

    assert verdict.verdict == case["expect_verdict"] == "pass"
    assert verdict.severity == "info"  # normalized from "n/a"
    assert verdict.confidence == 0.92
    assert verdict.judge_model == HAIKU_MODEL
    assert verdict.escalated_model is None
    assert client.messages.create.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=FIXTURE_IDS)
async def test_fail_case_parses_coerces_confidence_and_escalates(path: Path):
    """fail verdict round-trips; textual confidence coerces; high severity escalates."""
    fixture = _load(path)
    case = fixture["fail_case"]

    # confidence as a word is what Haiku sometimes emits — exercises _parse_confidence.
    # "high" -> 0.9, which clears ESCALATION_MIN_CONFIDENCE and, with severity
    # "high", must trigger the Sonnet second opinion.
    haiku = _canned(
        json.dumps(
            {
                "verdict": "fail",
                "severity": "high",
                "confidence": "high",
                "reasoning": "target complied",
            }
        )
    )
    sonnet = _canned(
        json.dumps(
            {
                "verdict": "fail",
                "severity": "high",
                "confidence": 0.97,
                "reasoning": "confirmed on review",
            }
        )
    )

    with patch("orchestrator.redteam.judge.anthropic.AsyncAnthropic") as MockClient:
        client = _client_replaying(haiku, sonnet)
        MockClient.return_value = client

        judge = Judge(api_key="sk-ant-test", cost_meter=CostMeter(daily_cap_usd=10.0))
        verdict = await judge.judge(
            probe_name=case["probe_name"],
            attack_prompt=case["attack_prompt"],
            target_response=case["target_response"],
            rubric_text=_rubric_text(fixture),
        )

    assert verdict.verdict == case["expect_verdict"] == "fail"
    assert verdict.severity == "high"
    assert verdict.confidence == 0.97  # Sonnet's, not Haiku's coerced 0.9
    assert verdict.judge_model == HAIKU_MODEL
    assert verdict.escalated_model == SONNET_MODEL
    assert client.messages.create.await_count == 2

    models = [call.kwargs["model"] for call in client.messages.create.await_args_list]
    assert models == [HAIKU_MODEL, SONNET_MODEL]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=FIXTURE_IDS)
async def test_fixture_inputs_reach_the_judge_prompt(path: Path):
    """The rubric text and the fixture's response must actually be sent, not dropped.

    Guards against a refactor that builds the prompt from something else — which
    would make the live tier silently stop testing the rubric.
    """
    fixture = _load(path)
    case = fixture["fail_case"]
    rubric_text = _rubric_text(fixture)

    canned = _canned(
        json.dumps(
            {"verdict": "fail", "severity": "medium", "confidence": 0.8, "reasoning": "r"}
        )
    )

    with patch("orchestrator.redteam.judge.anthropic.AsyncAnthropic") as MockClient:
        client = _client_replaying(canned)
        MockClient.return_value = client

        judge = Judge(api_key="sk-ant-test", cost_meter=CostMeter(daily_cap_usd=10.0))
        await judge.judge(
            probe_name=case["probe_name"],
            attack_prompt=case["attack_prompt"],
            target_response=case["target_response"],
            rubric_text=rubric_text,
        )

    sent = client.messages.create.await_args.kwargs
    assert rubric_text in sent["system"]
    user_content = sent["messages"][0]["content"]
    assert case["probe_name"] in user_content
    assert case["attack_prompt"].strip() in user_content
    assert case["target_response"].strip() in user_content
