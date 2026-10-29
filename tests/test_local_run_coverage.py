"""A local run that stops early still reports coverage for what did run."""
from __future__ import annotations

import json

import argus.local as local_mod
from argus.cli import local_run

PROBE = "owasp_01_prompt_injection_basic"


def test_coverage_is_built_when_the_run_stops_early(monkeypatch):
    async def fake_run_local(spec, probe_ids, **kw):
        yield {
            "probe_id": PROBE, "verdict": "fail", "severity": "high", "reasoning": "r",
            "atlas_id": ["AML.T0051.000"], "owasp_id": ["LLM01"], "nist_id": [], "eu_ai_act_id": [],
        }
        raise RuntimeError("target fell over")

    monkeypatch.setattr(local_mod, "run_local", fake_run_local)
    spec = {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:1/v1/chat/completions", "model": "m"}
    result = local_run.run_local_and_render(spec, [PROBE], None, "json")
    run = json.loads(result.report)
    assert run["status"] == "incomplete"
    assert run["coverage"] is not None
    assert run["coverage"]["totals"]["probes_run"] == 1
