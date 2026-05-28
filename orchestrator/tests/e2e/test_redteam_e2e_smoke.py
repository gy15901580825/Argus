"""E2E smoke: one probe against a real OpenAI-compatible endpoint.

Run with:
    ARGUS_E2E=1 \\
    ANTHROPIC_API_KEY=sk-ant-... \\
    TARGET_API_KEY=sk-... \\
    pytest tests/e2e/test_redteam_e2e_smoke.py -v
"""

import os
from pathlib import Path

import pytest

from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import Judge
from orchestrator.redteam.probe import load_probe
from orchestrator.redteam.runner import Runner
from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget


@pytest.mark.asyncio
async def test_one_probe_against_real_target():
    spec = OpenAICompatSpec(
        endpoint_url=os.environ.get(
            "TARGET_ENDPOINT_URL", "https://api.openai.com/v1/chat/completions"
        ),
        model=os.environ.get("TARGET_MODEL", "gpt-4o-mini"),
        api_key=os.environ["TARGET_API_KEY"],
    )
    target = OpenAICompatTarget(spec)
    judge = Judge(api_key=os.environ["ANTHROPIC_API_KEY"], cost_meter=CostMeter(daily_cap_usd=1.0))
    runner = Runner(target=target, judge=judge, rubrics_dir=Path("orchestrator/redteam/rubrics"))

    probe = load_probe(Path("orchestrator/redteam/probes/owasp_01_prompt_injection_basic.yaml"))
    findings = []
    async for f in runner.run_probe(probe):
        findings.append(f)
    assert len(findings) == len(probe.prompts)
    for f in findings:
        assert f.verdict in ("pass", "warn", "fail")
        assert f.severity in ("info", "low", "medium", "high", "critical")
        print(f"\n  prompt: {f.attack_prompt[:50]}...")
        print(f"  verdict: {f.verdict} | severity: {f.severity} | confidence: {f.confidence:.2f}")
        print(f"  reasoning: {f.reasoning}")
