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

from argus.cost_meter import CostMeter
from argus.judge import Judge
from argus.probe import load_probe
from argus.runner import Runner
from argus.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget

ARGUS_DIR = Path(__file__).resolve().parents[2] / "argus"


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
    runner = Runner(target=target, judge=judge, rubrics_dir=Path(ARGUS_DIR, "rubrics"))

    probe = load_probe(Path(ARGUS_DIR, "probes/owasp_01_prompt_injection_basic.yaml"))
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
