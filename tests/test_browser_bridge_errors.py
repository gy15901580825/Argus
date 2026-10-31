"""Server-mode browser_use: a bridge failure errors one probe, never the run."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from argus.connection_manager import ClientAgentDisconnectedError, ConnectionManager, NoClientAgentError
from argus.probe import Probe, ProbeMappings
from argus.runner import VERDICT_ERROR, Runner
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget

ARGUS_DIR = Path(__file__).resolve().parents[1] / "argus"

# Bridge and transport failures that must error one probe.
BRIDGE_ERRORS = [
    pytest.param(Exception({"code": -32000, "message": "browser crashed"}), "browser crashed", id="jsonrpc-error"),
    pytest.param(asyncio.TimeoutError(), "target could not deliver the probe: timed out after 65s", id="timeout"),
    pytest.param(NoClientAgentError("No client_agent connected for redteam bridge"), "No client_agent connected", id="no-client"),
    pytest.param(WebSocketDisconnect(code=1006), "WebSocketDisconnect", id="ws-disconnect"),
    pytest.param(ConnectionResetError("peer reset"), "peer reset", id="connection-reset"),
]


def _probe(pid: str) -> Probe:
    return Probe(
        id=pid,
        name=pid,
        target_class=("browser_using_agent",),
        attack_class=("prompt-injection",),
        severity="high",
        prompts=("Visit the URL provided and summarise it.",),
        mappings=ProbeMappings(atlas=("AML.T0051",), owasp_llm=("LLM01",), nist_ai_rmf=(), eu_ai_act=()),
        judge_model="m",
        judge_rubric_path="rubrics/default.md",
    )


def _judge():
    judge = MagicMock()
    judge.judge = AsyncMock(return_value=MagicMock(
        verdict="pass", severity="info", confidence=0.9,
        reasoning="refused", judge_model="haiku", escalated_model=None,
    ))
    return judge


def _target(timeout_s: float = 60.0) -> BrowserUseTarget:
    return BrowserUseTarget(BrowserUseSpec(
        agent_url="https://t.example.com/agent", scenario_kind="dom_injection", timeout_s=timeout_s,
    ))


@pytest.mark.asyncio
@pytest.mark.parametrize("exc, expected", BRIDGE_ERRORS)
async def test_bridge_failure_errors_one_probe_and_the_next_probe_runs(exc, expected):
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=[exc, {"final_text": "ok", "latency_ms": 1.0, "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}}])
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    findings = []
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        for pid in ("first", "second"):
            findings += [f async for f in runner.run_probe(_probe(pid))]

    assert [(f.probe_id, f.verdict) for f in findings] == [("first", VERDICT_ERROR), ("second", "pass")]
    err = findings[0]
    assert err.reasoning.startswith("target could not deliver the probe: ")
    assert expected in err.reasoning
    assert err.severity == "info"
    assert err.target_response == ""
    assert err.atlas_id == ["AML.T0051"]
    assert ws.send_and_wait.await_count == 2


@pytest.mark.asyncio
async def test_bridge_error_message_is_bounded():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=Exception("x" * 1000))
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        findings = [f async for f in runner.run_probe(_probe("p"))]
    assert len(findings) == 1
    assert findings[0].reasoning.startswith("target could not deliver the probe: Exception: xxx")
    assert len(findings[0].reasoning) < 300


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [None, "ok", ["ok"]])
async def test_reply_without_a_result_object_errors_one_probe(reply):
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=[reply, {"final_text": "ok", "latency_ms": 1.0, "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}}])
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    findings = []
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        for pid in ("first", "second"):
            findings += [f async for f in runner.run_probe(_probe(pid))]

    assert [(f.probe_id, f.verdict) for f in findings] == [("first", VERDICT_ERROR), ("second", "pass")]
    assert findings[0].reasoning == (
        "target could not deliver the probe: "
        f"client_agent reply has no result object (got {type(reply).__name__})"
    )


@pytest.mark.asyncio
async def test_wrong_bridge_signature_propagates_as_type_error():
    class OldBridge:
        async def send_and_wait(self, msg):
            return {"final_text": "ok"}

    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=OldBridge()):
        with pytest.raises(TypeError, match="timeout_s"):
            [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [
    AttributeError("'NoneType' object has no attribute 'send_json'"),
    NameError("name 'conn' is not defined"),
    KeyError("agent-1"),
    NotImplementedError("bridge method"),
])
async def test_caller_bugs_in_the_bridge_propagate(exc):
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=exc)
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        with pytest.raises(type(exc)):
            [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
async def test_bridge_raises_no_client_agent_error_that_is_still_a_runtime_error():
    bridge = ConnectionManager().get_redteam_bridge()
    with pytest.raises(NoClientAgentError) as info:
        await bridge.send_and_wait({"payload": "p"})
    assert isinstance(info.value, RuntimeError)
    assert str(info.value) == "No client_agent connected for redteam bridge"


@pytest.mark.asyncio
async def test_real_bridge_with_no_client_errors_one_probe():
    bridge = ConnectionManager().get_redteam_bridge()
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=bridge):
        findings = [f async for f in runner.run_probe(_probe("p"))]
    assert [(f.verdict, f.reasoning) for f in findings] == [(
        VERDICT_ERROR,
        "target could not deliver the probe: "
        "NoClientAgentError: No client_agent connected for redteam bridge",
    )]


class _Conn:
    """A client_agent socket: replies after `delay`, or fails every send."""

    def __init__(self, mgr, delay=0.0, send_error=None, reply=True):
        self.mgr, self.delay, self.send_error, self.reply = mgr, delay, send_error, reply
        self.sent = []

    async def send_json(self, envelope):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append(envelope)
        if self.reply:
            async def _reply():
                await asyncio.sleep(self.delay)
                self.mgr.handle_response({"id": envelope["id"], "result": {"final_text": "late ok", "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}}})
            asyncio.get_running_loop().create_task(_reply())


@pytest.mark.asyncio
async def test_reply_inside_the_grace_period_is_accepted_in_both_modes():
    from argus.targets.browser_use import local_browser_mode

    mgr = ConnectionManager()
    mgr.active_connections["a"] = _Conn(mgr, delay=2.0)
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=mgr.get_redteam_bridge()):
        text, _ = await _target(timeout_s=1.0).send_prompt("hi")
    assert text == "late ok"

    async def _late(self, msg):
        await asyncio.sleep(2.0)
        return {"final_text": "late ok", "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}}

    with patch.object(BrowserUseTarget, "_run_in_process", _late), local_browser_mode():
        text, _ = await _target(timeout_s=1.0).send_prompt("hi")
    assert text == "late ok"


@pytest.mark.asyncio
async def test_closed_socket_errors_one_probe_and_is_dropped(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    mgr = ConnectionManager()
    stale = _Conn(mgr, send_error=RuntimeError('Cannot call "send" once a close message has been sent.'))
    mgr.active_connections["stale"] = stale
    mgr.active_connections["live"] = _Conn(mgr)
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    findings = []
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=mgr.get_redteam_bridge()):
        for pid in ("first", "second"):
            findings += [f async for f in runner.run_probe(_probe(pid))]

    assert [(f.probe_id, f.verdict) for f in findings] == [("first", VERDICT_ERROR), ("second", "pass")]
    assert findings[0].reasoning == (
        "target could not deliver the probe: ClientAgentDisconnectedError: client_agent stale "
        'socket is closed: Cannot call "send" once a close message has been sent.'
    )
    assert list(mgr.active_connections) == ["live"]
    assert mgr.pending_commands == {} and mgr._command_agents == {}


@pytest.mark.asyncio
async def test_closed_socket_does_not_drop_a_newer_socket_with_the_same_id(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    mgr = ConnectionManager()
    newer = _Conn(mgr)

    class _Stale(_Conn):
        async def send_json(self, envelope):
            mgr.active_connections["a"] = newer  # the agent reconnected meanwhile
            raise RuntimeError("closed")

    mgr.active_connections["a"] = _Stale(mgr)
    with pytest.raises(ClientAgentDisconnectedError):
        await mgr.get_redteam_bridge().send_and_wait({"payload": "p"})
    assert mgr.active_connections["a"] is newer


@pytest.mark.asyncio
async def test_disconnect_fails_the_waiting_probe_at_once(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    mgr = ConnectionManager()
    conn = _Conn(mgr, reply=False)
    mgr.active_connections["a"] = conn
    runner = Runner(target=_target(timeout_s=30.0), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")

    async def _run():
        with patch("argus.targets.browser_use._get_client_agent_ws", return_value=mgr.get_redteam_bridge()):
            return [f async for f in runner.run_probe(_probe("p"))]

    task = asyncio.create_task(_run())
    while not conn.sent:
        await asyncio.sleep(0.01)
    await mgr.disconnect("a")
    findings = await asyncio.wait_for(task, timeout=2.0)

    assert [(f.verdict, f.reasoning) for f in findings] == [(
        VERDICT_ERROR,
        "target could not deliver the probe: "
        "ClientAgentDisconnectedError: client_agent a disconnected before replying",
    )]
    assert mgr.pending_commands == {} and mgr._command_agents == {}


@pytest.mark.asyncio
async def test_old_socket_disconnect_leaves_a_same_id_reconnect_alone(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    mgr = ConnectionManager()
    old, new = _Conn(mgr), _Conn(mgr, reply=False)
    mgr.active_connections["a"] = new  # "a" reconnected; `old` is closing late
    bridge = mgr.get_redteam_bridge()
    waiting = asyncio.create_task(bridge.send_and_wait({"payload": "p"}, timeout_s=5.0))
    while not new.sent:
        await asyncio.sleep(0.01)

    await mgr.disconnect("a", connection=old)

    assert mgr.active_connections["a"] is new
    assert not waiting.done()
    mgr.handle_response({"id": new.sent[0]["id"], "result": {"final_text": "ok"}})
    assert await asyncio.wait_for(waiting, timeout=1.0) == {"final_text": "ok"}


@pytest.mark.asyncio
async def test_disconnect_with_the_registered_socket_removes_it(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    mgr = ConnectionManager()
    conn = _Conn(mgr, reply=False)
    mgr.active_connections["a"] = conn
    waiting = asyncio.create_task(mgr.get_redteam_bridge().send_and_wait({"payload": "p"}, timeout_s=5.0))
    while not conn.sent:
        await asyncio.sleep(0.01)

    await mgr.disconnect("a", connection=conn)

    assert mgr.active_connections == {}
    with pytest.raises(ClientAgentDisconnectedError):
        await asyncio.wait_for(waiting, timeout=1.0)


@pytest.mark.asyncio
async def test_disconnect_without_connection_still_removes_by_id(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    mgr = ConnectionManager()
    conn = _Conn(mgr, reply=False)
    mgr.active_connections["a"] = conn
    waiting = asyncio.create_task(mgr.get_redteam_bridge().send_and_wait({"payload": "p"}, timeout_s=5.0))
    while not conn.sent:
        await asyncio.sleep(0.01)

    await mgr.disconnect("a")

    assert mgr.active_connections == {}
    with pytest.raises(ClientAgentDisconnectedError, match="client_agent a disconnected before replying"):
        await asyncio.wait_for(waiting, timeout=1.0)


def test_server_websocket_handler_disconnects_its_own_socket(monkeypatch):
    from argus.server import app, connection_manager as server_mgr

    monkeypatch.delenv("AGENT_CONNECT_SECRET", raising=False)
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    calls = []
    real = server_mgr.disconnect

    async def _spy(agent_id, **kwargs):
        calls.append((agent_id, kwargs))
        await real(agent_id, **kwargs)

    monkeypatch.setattr(server_mgr, "disconnect", _spy)
    with TestClient(app).websocket_connect("/agent/connect", headers={"x-agent-id": "srv-a"}):
        registered = server_mgr.active_connections["srv-a"]
    assert calls == [("srv-a", {"connection": registered})]
    assert "srv-a" not in server_mgr.active_connections


@pytest.mark.asyncio
async def test_plain_runtime_error_from_the_bridge_propagates():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=RuntimeError("bug in bridge"))
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        with pytest.raises(RuntimeError, match="bug in bridge"):
            [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
async def test_cancellation_still_propagates():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=asyncio.CancelledError())
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        with pytest.raises(asyncio.CancelledError):
            [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
async def test_server_mode_trap_settings_reach_the_client_agent():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(return_value={
        "final_text": "ok", "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}, "latency_ms": 1.0, "trap_url": "http://127.0.0.1:8765/AbCdEfGhIjKl-_12/scenario",
    })
    target = BrowserUseTarget(BrowserUseSpec(
        agent_url="https://t.example.com/agent", scenario_kind="dom_injection", trap_port=8765,
    ))
    runner = Runner(target=target, judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        findings = [f async for f in runner.run_probe(_probe("p"))]
    assert [f.verdict for f in findings] == ["pass"]
    assert ws.send_and_wait.call_args.args[0]["trap_port"] == 8765


@pytest.mark.asyncio
async def test_old_client_agent_ignoring_trap_settings_errors_the_probe():
    # A client_agent without trap support replies with no trap_url.
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(return_value={"final_text": "ok", "latency_ms": 1.0, "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}})
    target = BrowserUseTarget(BrowserUseSpec(
        agent_url="https://t.example.com/agent", scenario_kind="dom_injection", trap_port=8765,
    ))
    runner = Runner(target=target, judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        findings = [f async for f in runner.run_probe(_probe("p"))]
    assert [f.verdict for f in findings] == [VERDICT_ERROR]
    assert findings[0].reasoning.startswith(
        "target could not deliver the probe: client_agent did not use the trap settings (upgrade client_agent)"
    )


@pytest.mark.asyncio
async def test_unreachable_http_target_errors_the_probe_too():
    # An unreachable HTTP target is an error finding like a bridge failure; the
    # CLI still exits 1 because the run has an error finding.
    import httpx
    target = MagicMock()
    target.send_prompt = AsyncMock(side_effect=httpx.ConnectError("refused"))
    runner = Runner(target=target, judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    findings = [f async for f in runner.run_probe(_probe("p"))]
    assert [f.verdict for f in findings] == [VERDICT_ERROR]
    assert findings[0].reasoning == "target request failed: ConnectError: refused"


@pytest.mark.asyncio
async def test_iterative_bridge_failure_ends_the_thread_with_an_error_finding():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=[
        {"final_text": "ok", "latency_ms": 1.0, "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}},
        NoClientAgentError("No client_agent connected for redteam bridge"),
    ])
    probe = MagicMock()
    probe.id = "iter_1"
    probe.name = "iter"
    probe.target_class = ("browser-using",)
    probe.iterative = True
    probe.conversation = False
    probe.assertions = ()
    probe.rubrics_dir = None
    probe.scenario_kind = None
    probe.scenario_payload = None
    probe.judge_rubric_path = "rubrics/iterative.md"
    probe.mappings = ProbeMappings(atlas=(), owasp_llm=(), nist_ai_rmf=(), eu_ai_act=())
    probe.should_halt = MagicMock(return_value=False)
    probe.next_prompt = AsyncMock(return_value="next prompt")
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        findings = [f async for f in runner.run_probe(probe)]

    assert [f.verdict for f in findings] == ["pass", VERDICT_ERROR]
    assert findings[1].reasoning == (
        "target could not deliver round 1 prompt: "
        "NoClientAgentError: No client_agent connected for redteam bridge"
    )
    assert ws.send_and_wait.await_count == 2


def test_sse_stream_ends_normally_when_one_browser_probe_fails(monkeypatch):
    from argus import api
    from argus.server import app

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    # Library order is run order.
    browser_ids = [
        p.id for p in api.load_probe_library(api.PROBES_DIR)
        if "browser-using" in p.target_class and not p.assertions and not p.conversation
    ][:2]
    assert len(browser_ids) == 2

    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=[
        NoClientAgentError("No client_agent connected for redteam bridge"),
        {"final_text": "ok", "latency_ms": 1.0, "trap_evidence": {"interaction_count": 0, "page_loads": 0, "trap_requests": []}},
    ])
    body = {
        "target": {"kind": "browser_use", "agent_url": "https://t.example.com/agent", "scenario_kind": "dom_injection"},
        "probe_ids": browser_ids,
    }
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws), \
         patch("argus.api.Judge", return_value=_judge()):
        with TestClient(app).stream("POST", "/redteam/run", json=body) as resp:
            assert resp.status_code == 200
            lines = list(resp.iter_lines())

    assert "event: error" not in lines
    assert "event: end" in lines
    findings = [json.loads(line[len("data: "):]) for line in lines if line.startswith("data: ")]
    findings = [f for f in findings if f.get("probe_id")]
    assert [(f["probe_id"], f["verdict"]) for f in findings] == [
        (browser_ids[0], "error"), (browser_ids[1], "pass"),
    ]
    assert "No client_agent connected" in findings[0]["reasoning"]
