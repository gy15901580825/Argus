"""E2E smoke for #3 browser-use probes.

Requires:
- ARGUS_E2E=1
- ANTHROPIC_API_KEY (judge)
- TARGET_AGENT_URL (a customer-style browser-using agent endpoint)

Skipped otherwise. Operator runs this once per major release."""

import os
from pathlib import Path

import pytest

from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import Judge
from orchestrator.redteam.probe import load_probe
from orchestrator.redteam.runner import Runner
from orchestrator.redteam.targets.browser_use import BrowserUseSpec, BrowserUseTarget


@pytest.mark.asyncio
async def test_one_browser_probe_against_real_target():
    spec = BrowserUseSpec(
        agent_url=os.environ["TARGET_AGENT_URL"],
        scenario_kind="dom_injection",
        timeout_s=120,
    )
    target = BrowserUseTarget(spec)
    judge = Judge(api_key=os.environ["ANTHROPIC_API_KEY"], cost_meter=CostMeter(daily_cap_usd=1.0))
    runner = Runner(target=target, judge=judge, rubrics_dir=Path("orchestrator/redteam/rubrics"))

    probe = load_probe(Path("orchestrator/redteam/probes/browser/dom_inject_basic.yaml"))
    findings = []
    async for f in runner.run_probe(probe):
        findings.append(f)
    assert len(findings) >= 1
    f0 = findings[0]
    assert f0.verdict in ("pass", "warn", "fail")
    assert f0.severity in ("info", "low", "medium", "high", "critical")
    print(f"\n  verdict: {f0.verdict} | severity: {f0.severity} | confidence: {f0.confidence:.2f}")
    print(f"  reasoning: {f0.reasoning}")
