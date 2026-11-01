import pytest

from argus import api
from argus.probe import load_probe_library
from mcp_world_harness import serve_world_demo
from test_mcp_world_e2e import findings

PROTOCOL = [
    "mcp_cross_server_mail_redirect",
    "mcp_resource_embedded_injection",
    "mcp_resource_read_injection",
    "mcp_instructions_injection",
]
CASES = [
    (probe, agent, mode)
    for probe in PROTOCOL
    for agent in ("naive", "safe")
    for mode in ("dynamic", "fixed")
]


@pytest.mark.parametrize(
    "probe_id,agent,url_mode", CASES, ids=["-".join(case) for case in CASES]
)
async def test_protocol_probe_verdict(probe_id, agent, url_mode):
    with serve_world_demo(agent, url_mode) as spec:
        result, _ = await findings(spec, [probe_id])
    assert len(result) == 1
    finding = result[0]
    if probe_id == "mcp_cross_server_mail_redirect" and url_mode == "fixed":
        assert finding["verdict"] == "skipped"
        assert "mcp_mode dynamic" in finding["reasoning"]
        return
    assert finding["verdict"] == {"naive": "fail", "safe": "pass"}[agent], finding[
        "reasoning"
    ]
    trial = finding["evidence"]["trials"][0]
    assert trial["clean"]["task_completed"] is True
    assert trial["attack"]["attack_delivered"]


async def test_protocol_probes_need_no_key_and_are_deterministic():
    with serve_world_demo("safe", "dynamic") as spec:
        result, events = await findings(spec, PROTOCOL)
    assert len(result) == 4 and all(f["verdict"] == "pass" for f in result)
    assert not any(event.get("type") == "judge" for event in events)
    assert all(f["judge_model"] == "" for f in result)


def test_protocol_probes_are_phased_unjudged_and_mcp_suite():
    library = {
        probe.id: probe
        for probe in load_probe_library(api.PROBES_DIR)
        if probe.id in PROTOCOL
    }
    assert set(library) == set(PROTOCOL)
    assert all(
        probe.is_phased
        and probe.assertions
        and not probe.needs_judge
        and "mcp-abuse" in probe.attack_class
        for probe in library.values()
    )
