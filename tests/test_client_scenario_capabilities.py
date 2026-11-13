"""Server mode: a client agent says which browser scenarios it serves, and a probe
it cannot serve is skipped before anything is sent to it."""
from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import uvicorn
import websockets

from argus import llm
from argus.browser_runner.scenarios._options import BROWSER_KINDS, OPTION_KEYS, supported_scenarios
from argus.cli.severity import run_exit_code
from argus.connection_manager import CLIENT_1_12_SCENARIOS, ConnectionManager, connection_manager
from argus.probe import load_probe

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client_agent"))

PLACEMENT_PROBE = "browser_dom_inject_basic"
PLAIN_PROBE = "browser_visual_inject_qr_code"  # a 1.12.0 kind with a 1.12.0 option
WITNESS = "504817"
TARGET = {"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent",
          "scenario_kind": "dom_injection", "timeout_s": 10}
UPGRADE = ("the connected client agent does not support dom_injection option(s) 'placement'; "
           "upgrade the client agent to run this probe")
BROWSER_PROBES = [load_probe(p) for p in sorted((ROOT / "argus/probes/browser").glob("*.yaml"))]
BY_ID = {p.id: p for p in BROWSER_PROBES}


def reply_for(params):
    return {"final_text": f"The page lists Widget A and Widget B. The item number is {WITNESS}.",
            "latency_ms": 1.0,
            "trap_evidence": {"interaction_count": 1, "page_loads": 1, "trap_requests": []}}


@pytest.fixture
async def server(monkeypatch):
    """The real argus server on a free 127.0.0.1 port, with a judge that says pass."""
    for name in ("ARGUS_SERVER_TOKEN", "AGENT_CONNECT_SECRET", "API_SERVICE_URL", "REDTEAM_MODEL_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-not-a-key")

    async def judge(cfg, *, role, system, user, max_tokens):
        body = {"verdict": "pass", "severity": "info", "confidence": 0.9, "reasoning": "ignored the page text"}
        return llm.Completion(text=json.dumps(body), input_tokens=1, output_tokens=1, model="fake-judge")

    monkeypatch.setattr(llm, "complete", judge)
    from argus.server import app

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    srv = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
    task = asyncio.create_task(srv.serve(sockets=[sock]))
    while not srv.started:
        assert not task.done(), "server did not start"
        await asyncio.sleep(0.01)
    try:
        yield sock.getsockname()[1]
    finally:
        srv.should_exit = True
        await task
        sock.close()
    assert connection_manager.active_connections == {}


@contextlib.asynccontextmanager
async def raw_client(port, capabilities):
    """A client agent that sends `capabilities` and answers every probe; yields what it received."""
    received = []
    ready = asyncio.Event()

    async def run():
        async with websockets.connect(f"ws://127.0.0.1:{port}/agent/connect",
                                      additional_headers={"x-agent-id": "fixture"}) as ws:
            await ws.send(json.dumps({"jsonrpc": "2.0", "method": "agent_capabilities", "params": capabilities}))
            await ws.send(json.dumps({"jsonrpc": "2.0", "method": "ping", "id": "sync"}))
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("id") == "sync":
                    ready.set()
                elif msg.get("method") == "redteam_browser_probe":
                    received.append(msg["params"])
                    await ws.send(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": reply_for(msg["params"])}))

    task = asyncio.create_task(run())
    await asyncio.wait_for(ready.wait(), 5)
    try:
        yield received
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await wait_for(lambda: "fixture" not in connection_manager.active_connections)


async def wait_for(condition, timeout=5.0):
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


async def run_server_mode(port, probe_ids):
    """POST /redteam/run and read the SSE stream: (findings, last event name)."""
    findings, event = [], None
    async with httpx.AsyncClient(timeout=60) as http:
        async with http.stream("POST", f"http://127.0.0.1:{port}/redteam/run",
                               json={"target": TARGET, "probe_ids": probe_ids}) as resp:
            assert resp.status_code == 200, await resp.aread()
            async for line in resp.aiter_lines():
                if line.startswith("event: "):
                    event = line.removeprefix("event: ")
                elif line.startswith("data: "):
                    data = json.loads(line.removeprefix("data: "))
                    if "verdict" in data:
                        findings.append(data)
    return {f["probe_id"]: f for f in findings}, event


def probe_ids_sent(received):
    payloads = {BY_ID[p].scenario_payload: p for p in (PLACEMENT_PROBE, PLAIN_PROBE)}
    return [payloads.get(params["payload"], "?") for params in received]


async def test_upgraded_client_advertises_its_runner_and_runs_a_placement_probe(server):
    import client_agent

    agent = client_agent.ClientAgent(orchestrator_url=f"ws://127.0.0.1:{server}", agent_name="fixture")
    agent.agent_id = "current"
    probe = AsyncMock(side_effect=lambda params, policy: reply_for(params))
    with patch("redteam_runner.browser_probe.BrowserProbe.run", probe):
        agent.running = True
        task = asyncio.create_task(agent.connect_orchestrator())
        try:
            await wait_for(lambda: "current" in connection_manager._scenarios)
            mgr_socket = connection_manager.active_connections["current"]
            assert connection_manager.scenarios("current", mgr_socket)["dom_injection"] == {"placement"}
            findings, event = await run_server_mode(server, [PLACEMENT_PROBE])
        finally:
            agent.running = False
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await wait_for(lambda: "current" not in connection_manager.active_connections)
    assert event == "end"
    assert findings[PLACEMENT_PROBE]["verdict"] == "pass", findings[PLACEMENT_PROBE]["reasoning"]
    [params] = [call.args[0] for call in probe.await_args_list]
    assert params["scenario_options"] == {"placement": "visible"}


async def test_client_from_1_12_skips_placement_probes_and_runs_the_rest(server):
    async with raw_client(server, {"transport_versions": [1]}) as received:
        findings, event = await run_server_mode(server, [PLACEMENT_PROBE, PLAIN_PROBE])
    assert event == "end"
    skipped = findings[PLACEMENT_PROBE]
    assert (skipped["verdict"], skipped["reasoning"]) == ("skipped", UPGRADE)
    assert findings[PLAIN_PROBE]["verdict"] not in {"skipped", "error"}, findings[PLAIN_PROBE]["reasoning"]
    assert probe_ids_sent(received) == [PLAIN_PROBE]
    assert received[0]["scenario_options"] == {"variant": "qr_code"}
    assert run_exit_code(list(findings.values()), None, None) == 0


@pytest.mark.parametrize("scenarios", [
    pytest.param({k: sorted(v) for k, v in CLIENT_1_12_SCENARIOS.items()}, id="kinds-without-placement"),
    pytest.param({"dom_injection": "placement"}, id="malformed-falls-back-to-1.12"),
])
async def test_client_without_placement_skips_the_same_way(server, scenarios):
    async with raw_client(server, {"transport_versions": [1], "scenarios": scenarios}) as received:
        findings, event = await run_server_mode(server, [PLACEMENT_PROBE])
    assert event == "end"
    assert (findings[PLACEMENT_PROBE]["verdict"], findings[PLACEMENT_PROBE]["reasoning"]) == ("skipped", UPGRADE)
    assert received == []
    assert run_exit_code(list(findings.values()), None, "high") == 0


async def test_client_without_a_kind_names_the_kind(server):
    scenarios = {k: sorted(v) for k, v in supported_scenarios().items() if k != "visual_injection"}
    async with raw_client(server, {"transport_versions": [1], "scenarios": scenarios}) as received:
        findings, _ = await run_server_mode(server, [PLAIN_PROBE])
    assert findings[PLAIN_PROBE]["reasoning"] == (
        "the connected client agent does not support scenario kind 'visual_injection'; "
        "upgrade the client agent to run this probe")
    assert received == []


def test_advertised_scenarios_are_the_validation_table():
    assert supported_scenarios() == {k: sorted(OPTION_KEYS.get(k, ())) for k in sorted(BROWSER_KINDS)}
    assert set(supported_scenarios()) == BROWSER_KINDS


def test_a_1_12_client_serves_every_browser_probe_except_the_ten_placements():
    mgr = ConnectionManager()
    mgr.active_connections["old"] = object()
    bridge = mgr.get_redteam_bridge()
    unsupported = sorted(p.id for p in BROWSER_PROBES
                         if p.scenario_kind and bridge.missing_scenario_support(p.scenario_kind, p.scenario_options))
    assert unsupported == sorted(p.id for p in BROWSER_PROBES if "placement" in p.scenario_options)
    assert len(unsupported) == 10


async def test_no_connected_client_still_errors_at_send():
    from argus.runner import Runner
    from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget

    probe = BY_ID[PLACEMENT_PROBE]
    target = BrowserUseTarget(BrowserUseSpec(agent_url="http://127.0.0.1:1/agent", scenario_kind="dom_injection"))
    judge = AsyncMock()
    runner = Runner(target=target, judge=judge, rubrics_dir=ROOT / "argus/rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ConnectionManager().get_redteam_bridge()):
        findings = [f async for f in runner.run_probe(probe)]
    assert [f.verdict for f in findings] == ["error"]
    assert "No client_agent connected" in findings[0].reasoning
