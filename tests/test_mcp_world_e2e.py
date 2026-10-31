import dataclasses
from types import SimpleNamespace
import pytest
from argus import api
from argus.demo import servers
from argus.local import run_local
from argus.probe import load_probe_library
from argus.runner import Runner
from argus.targets import build_target
from mcp_world_harness import serve_world_demo
from test_mcp_world_probes import EXPECTED

WORLD_PROBES = sorted(EXPECTED)
CASES = [
    (probe, agent, mode)
    for probe in WORLD_PROBES
    for agent in ("naive", "safe")
    for mode in ("dynamic", "fixed")
]


async def findings(spec, ids):
    events = [event async for event in run_local(spec, ids, env={})]
    return [event for event in events if "verdict" in event], events


@pytest.mark.parametrize(
    "probe_id,agent,url_mode", CASES, ids=["-".join(case) for case in CASES]
)
async def test_world_probe_verdict(probe_id, agent, url_mode):
    with serve_world_demo(agent, url_mode) as spec:
        result, _ = await findings(spec, [probe_id])
    assert len(result) == 1
    finding = result[0]
    assert finding["verdict"] == {"naive": "fail", "safe": "pass"}[agent], finding[
        "reasoning"
    ]
    assert finding["evidence"]["trial_summary"]["attempted"] == 1
    assert finding["evidence"]["trials"][0]["clean"]["task_completed"] is True


async def test_naive_forged_narration_fail_names_preview_vs_executed_target():
    with serve_world_demo("naive", "dynamic") as spec:
        result, _ = await findings(spec, ["approval_forged_narration"])
    assert result[0]["verdict"] == "fail"
    assert all(
        text in result[0]["reasoning"]
        for text in ["tmp_cache", "prod_customers", "would have been denied"]
    )


async def test_agent_without_approval_step_errors_asi09_probes():
    with serve_world_demo("safe,skip_approval", "dynamic") as spec:
        result, _ = await findings(
            spec, ["approval_forged_narration", "approval_substitution"]
        )
    assert len(result) == 2 and all(f["verdict"] == "error" for f in result)


async def test_trials_two_run_four_fresh_worlds():
    probe = dataclasses.replace(
        next(
            p
            for p in load_probe_library(api.PROBES_DIR)
            if p.id == "memory_poison_tool_result"
        ),
        trials=2,
    )
    with serve_world_demo("safe", "dynamic") as spec:
        target = build_target(spec)
        try:
            result = [
                f
                async for f in Runner(
                    target, SimpleNamespace(), api.RUBRICS_DIR
                ).run_probe(probe)
            ]
        finally:
            await target.aclose()
    trials = result[0].evidence["trials"]
    worlds = [t[phase] for t in trials for phase in ("clean", "attack")]
    assert len(trials) == 2 and len({w["session_id"] for w in worlds}) == 4
    assert len({w["canaries"]["payee_account"] for w in worlds}) == 4
    assert result[0].evidence["trial_summary"]["attempted"] == 2


async def test_existing_mcp_probes_in_fixed_mode():
    with serve_world_demo("", "fixed") as spec:
        result, _ = await findings(spec, list(servers.PROBE_IDS))
    assert len(result) == 12
    for finding in result:
        if finding["probe_id"] in {
            "mcp_rugpull_after_relist",
            "mcp_rugpull_silent_escalation",
        }:
            assert finding["verdict"] == "skipped"
        else:
            assert finding["verdict"] != "error", finding


async def test_mcp_world_run_needs_no_key():
    with serve_world_demo("safe", "dynamic") as spec:
        result, events = await findings(spec, WORLD_PROBES)
    assert len(result) == 11 and all(f["verdict"] == "pass" for f in result), result
    assert not any(event.get("type") == "judge" for event in events)
    assert all(f["judge_model"] == "" for f in result)
