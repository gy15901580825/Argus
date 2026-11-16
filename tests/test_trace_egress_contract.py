"""Probe selection remains usable without any witness configuration."""
import pytest

from argus.local import run_local


@pytest.mark.parametrize("pid", ["browser_secret_trace_export", "browser_secret_trace_export_control"])
async def test_unconfigured_trace_probe_is_a_capability_skip(pid):
    spec = {"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent", "scenario_kind": "dom_injection"}
    events = [e async for e in run_local(spec, [pid], env={})]
    [finding] = [e for e in events if "verdict" in e]
    assert finding["verdict"] == "skipped", finding
    assert "does not configure the required witness channel" in finding["reasoning"]


async def test_a_lone_trace_finding_is_emitted_before_run_continues(monkeypatch):
    from argus import api
    async def records(*args, **kwargs):
        yield {"probe_id": "browser_secret_trace_export", "verdict": "skipped", "reasoning": "no traffic"}
        raise AssertionError("the caller should be able to stop after the first finding")
    monkeypatch.setattr(api, "_run_probes", records)
    run = run_local({"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent", "scenario_kind": "dom_injection"},
                    ["browser_secret_trace_export"], env={})
    try:
        finding = await anext(run)
        assert finding["verdict"] == "skipped"
    finally:
        await run.aclose()


async def test_interrupted_paired_run_emits_completed_findings_before_error(monkeypatch):
    from argus import api
    from argus.local import LocalRunError
    from argus.runner import TargetUnreachableError
    pid = "browser_secret_trace_export"
    async def records(*args, **kwargs):
        yield {"probe_id": pid, "verdict": "skipped", "reasoning": "no traffic"}
        raise TargetUnreachableError("synthetic unreachable target")
    monkeypatch.setattr(api, "_run_probes", records)
    run = run_local({"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent", "scenario_kind": "dom_injection"},
                    [pid, pid + "_control"], env={})
    finding = await anext(run)
    assert finding["probe_id"] == pid
    with pytest.raises(LocalRunError, match="synthetic unreachable target"):
        await anext(run)
