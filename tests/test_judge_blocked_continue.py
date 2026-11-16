"""A blocked exchange leaves an error finding and lets the other probes run."""
from dataclasses import asdict, replace
import json

import httpx
import pytest
from click.testing import CliRunner
from fastapi import FastAPI

from argus import api, llm, local
from argus.cli.__main__ import main
from argus.cost_meter import CostMeter
from argus.coverage import build_summary
from argus.judge import Judge, Verdict
from argus.probe import Probe, ProbeMappings
from argus.runner import Runner


BLOCK = {"provider": "azure", "model": "judge-deployment", "categories": ["hate"], "fallback": None}


def blocked():
    return llm.JudgeBlockedError("synthetic block", provider=BLOCK["provider"], model=BLOCK["model"],
                                categories=("hate",), fallback=None)


class Target:
    compatible_classes = frozenset()
    supports_history = False

    async def send_prompt(self, prompt, **kwargs):
        return "Target reply", 1.0

    async def aclose(self):
        pass


@pytest.fixture
def setup(monkeypatch, tmp_path):
    probes = [Probe(id=f"probe_{i}", name=f"Probe {i}", target_class=(), attack_class=("prompt-injection",),
                    severity="info", prompts=(f"prompt {i}",), mappings=ProbeMappings(),
                    judge_rubric_path="test.md") for i in range(3)]
    (tmp_path / "test.md").write_text("Assess the reply.")
    monkeypatch.setattr(api, "RUBRICS_DIR", tmp_path)
    for module in (api, local):
        monkeypatch.setattr(module, "load_probe_library", lambda _: probes)
    for module in (api, local):
        monkeypatch.setattr(module, "build_target", lambda *a, **kw: Target())
    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "azure", "AZURE_API_KEY": "fake",
                              "AZURE_API_BASE": "http://127.0.0.1:9", "REDTEAM_FAST_MODEL": "judge-deployment",
                              "REDTEAM_STRONG_MODEL": "judge-deployment", "REDTEAM_LLM_FALLBACK": "off"})
    monkeypatch.setattr(llm, "resolve_config", lambda *a, **kw: cfg)
    monkeypatch.setattr("argus.decider.from_env", lambda: None)
    monkeypatch.setattr(api, "_COST_METER", CostMeter(daily_cap_usd=100, per_run_cap_usd=10))
    calls = []

    async def judge(self, probe_name, *args, **kwargs):
        calls.append(probe_name)
        if len(calls) == 2:
            raise blocked()
        return Verdict("pass", "info", 1.0, "No violation", "judge-deployment")

    monkeypatch.setattr(Judge, "judge", judge)
    return probes, tmp_path, calls


def assert_findings(findings, summary):
    assert [f["verdict"] for f in findings] == ["pass", "error", "pass"]
    error = findings[1]
    assert error["severity"] == "info"
    assert error["evidence"]["judge_blocked"] == BLOCK
    assert error["evidence"]["reason_code"] == "judge_blocked"
    assert error["attack_prompt"] == "prompt 1" and error["target_response"] == "Target reply"
    assert "azure" in error["reasoning"] and "hate" in error["reasoning"]
    assert summary["judge_blocked"] == {"count": 1, "categories": ["hate"],
                                        "providers": [{"provider": "azure", "model": "judge-deployment"}]}


def test_static_local_continues_and_prints_summary(setup, tmp_path):
    probes, _, calls = setup
    out = tmp_path / "run.json"
    result = CliRunner().invoke(main, ["run", "--local", "--target", json.dumps({'kind': 'custom_http', 'request_url': 'http://127.0.0.1:9/run', 'request_body_template': '{"prompt": {{ prompt|tojson }}}', 'response_jsonpath': '$.text'}),
                                      "--probes", ",".join(p.id for p in probes), "--format", "json", "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert out.exists(), result.output
    run = json.loads(out.read_text())
    assert_findings(run["findings"], run["summary"])
    assert len(calls) == 3
    assert "1 finding could not be judged" in result.output
    assert "categories: hate" in result.output and "Run stopped early" not in result.output
    from argus.cli.reports import render_html
    assert "1 finding could not be judged" in render_html(run)


async def test_server_continues_to_coverage_and_end(setup):
    app = FastAPI()
    app.include_router(api.router)
    probes, _, calls = setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1") as client:
        response = await client.post("/redteam/run", json={"target": {"kind": "test"}, "probe_ids": [p.id for p in probes]})
    assert response.status_code == 200
    assert "event: error" not in response.text and "event: end" in response.text
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
    assert_findings([e for e in events if "verdict" in e], next(e["summary"] for e in events if e.get("type") == "coverage"))
    assert len(calls) == 3


async def test_blocked_trial_prevents_aggregate_pass(setup):
    probes, path, calls = setup
    runner = Runner(Target(), Judge("", CostMeter(daily_cap_usd=100)), path)
    findings = [asdict(f) async for f in runner.run_probe(replace(probes[0], trials=3))]
    assert len(calls) == 3 and len(findings) == 1
    finding = findings[0]
    assert finding["verdict"] == "error" and finding["severity"] == "info"
    assert finding["evidence"]["reason_code"] == "judge_blocked"
    assert finding["evidence"]["judge_blocked"] == BLOCK
    assert finding["evidence"]["trial_summary"]["error"] == 1
    assert build_summary(findings)["judge_blocked"]["count"] == 1


async def test_strong_block_after_fast_pass_becomes_error(monkeypatch, tmp_path):
    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "azure", "REDTEAM_FAST_MODEL": "fast",
                              "REDTEAM_STRONG_MODEL": "strong", "REDTEAM_LLM_FALLBACK": "off"})
    judge = Judge("", CostMeter(daily_cap_usd=100), cfg)

    async def call(role, *args):
        if role == "strong":
            raise blocked()
        return Verdict("pass", "high", .9, "Fast pass", "fast")

    monkeypatch.setattr(judge, "_call", call)
    probe = Probe(id="probe", name="Probe", target_class=(), attack_class=("prompt-injection",), severity="high",
                  prompts=("prompt",), mappings=ProbeMappings(), judge_rubric_path="test.md")
    (tmp_path / "test.md").write_text("Assess reply")
    findings = [f async for f in Runner(Target(), judge, tmp_path).run_probe(probe)]
    assert findings[0].verdict == "error"
    assert "strong escalation" in findings[0].reasoning and "fast pass" in findings[0].reasoning
    assert findings[0].evidence["judge_blocked"] == BLOCK


@pytest.mark.parametrize("method, initial", [("_hybrid_finding", "pass"), ("_warn_finding", "warn"),
                                             ("_reply_check_finding", "pass")])
async def test_assertion_judge_helpers_keep_evidence_and_fail_closed(setup, method, initial):
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock
    probes, path, _ = setup
    judge = Judge("", CostMeter(daily_cap_usd=100))
    judge.judge = AsyncMock(side_effect=blocked())
    runner = Runner(Target(), judge, path)
    original = runner._finding(probes[0], "prompt", "reply", 1.0, datetime.now(timezone.utc),
                               verdict=initial, severity="high", confidence=1.0, reasoning="Evidence clean",
                               evidence={"recorded": True})
    finding = await getattr(runner, method)(probes[0], "rubric", original)
    assert finding.verdict == "error" and finding.severity == "info"
    assert finding.evidence == {"recorded": True, "judge_blocked": BLOCK, "reason_code": "judge_blocked"}
    assert finding.attack_prompt == "prompt" and finding.target_response == "reply"


async def test_configured_fallback_verdict_stays_judged(monkeypatch, tmp_path):
    from test_judge_blocked import _azure_block, _config, _stub_anthropic, _stub_litellm, DEPLOYMENT
    _stub_litellm(monkeypatch, _azure_block())
    calls = _stub_anthropic(monkeypatch)
    cfg = _config(AZURE_API_KEY="fake", AZURE_API_BASE="http://127.0.0.1:9", ANTHROPIC_API_KEY="fake",
                  REDTEAM_LLM_FALLBACK="on")
    judge = Judge("", CostMeter(daily_cap_usd=100), cfg)
    probe = Probe(id="probe", name="Probe", target_class=(), attack_class=("prompt-injection",), severity="info",
                  prompts=("prompt",), mappings=ProbeMappings(), judge_rubric_path="test.md")
    (tmp_path / "test.md").write_text("Assess reply")
    findings = [asdict(f) async for f in Runner(Target(), judge, tmp_path).run_probe(probe)]
    assert findings[0]["verdict"] == "pass" and calls
    assert "judge_blocked" not in (findings[0]["evidence"] or {})
    assert "judge_blocked" not in build_summary(findings)


def test_summary_unions_all_trial_blocks_and_counts_findings_once():
    other = {"provider": "openai", "model": "other", "categories": ["violence", "hate"], "fallback": "off"}
    evidence = {"trials": [{"attack": {"observations": [{"evidence": {"judge_blocked": block}}
                                                          for block in (BLOCK, other)]}}]}
    summary = build_summary([{"verdict": "error", "severity": "info", "evidence": evidence}])
    assert summary["judge_blocked"] == {"count": 1, "categories": ["hate", "violence"],
                                        "providers": [{"provider": "azure", "model": "judge-deployment"},
                                                      {"provider": "openai", "model": "other"}]}


async def test_legacy_iterative_judge_block_ends_only_that_probe(setup):
    from test_runner_target_failures import _iterative
    probes, path, calls = setup
    (path / "default.md").write_text("Assess reply")
    runner = Runner(Target(), Judge("", CostMeter(daily_cap_usd=100)), path)
    iterative = _iterative("iterative")
    iterative.trials = 1
    findings = [f async for f in runner.run_probe(iterative)]
    assert [f.verdict for f in findings] == ["pass", "error"]
    assert findings[-1].evidence["reason_code"] == "judge_blocked"
    following = [f async for f in runner.run_probe(probes[0])]
    assert following[0].verdict == "pass" and len(calls) == 3
