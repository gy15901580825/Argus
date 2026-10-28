"""Server-mode browser_use: a bridge failure errors one probe, never the run."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from argus.probe import Probe, ProbeMappings
from argus.runner import VERDICT_ERROR, Runner
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget

ARGUS_DIR = Path(__file__).resolve().parents[1] / "argus"

# The three ways RedteamBridge.send_and_wait fails today.
BRIDGE_ERRORS = [
    pytest.param(Exception({"code": -32000, "message": "browser crashed"}), "browser crashed", id="jsonrpc-error"),
    pytest.param(asyncio.TimeoutError(), "TimeoutError", id="timeout"),
    pytest.param(RuntimeError("No client_agent connected for redteam bridge"), "No client_agent connected", id="no-client"),
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
    ws.send_and_wait = AsyncMock(side_effect=[exc, {"final_text": "ok", "latency_ms": 1.0}])
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
    assert len(findings[0].reasoning) < 300


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", [None, "ok", ["ok"]])
async def test_reply_without_a_result_object_errors_one_probe(reply):
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=[reply, {"final_text": "ok", "latency_ms": 1.0}])
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
async def test_cancellation_still_propagates():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=asyncio.CancelledError())
    runner = Runner(target=_target(), judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        with pytest.raises(asyncio.CancelledError):
            [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
async def test_server_only_trap_settings_still_abort_the_run():
    # A spec mistake is not a delivery failure; it must keep failing loudly.
    target = BrowserUseTarget(BrowserUseSpec(
        agent_url="https://t.example.com/agent", scenario_kind="dom_injection", trap_port=8765,
    ))
    runner = Runner(target=target, judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with pytest.raises(ValueError, match="only apply to --local"):
        [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
async def test_other_target_errors_still_abort_the_run():
    # Only the browser adapter's delivery failures are absorbed; an unreachable
    # HTTP target keeps failing the run (and `run --local` keeps exiting 1).
    import httpx
    target = MagicMock()
    target.send_prompt = AsyncMock(side_effect=httpx.ConnectError("refused"))
    runner = Runner(target=target, judge=_judge(), rubrics_dir=ARGUS_DIR / "rubrics")
    with pytest.raises(httpx.ConnectError):
        [f async for f in runner.run_probe(_probe("p"))]


@pytest.mark.asyncio
async def test_iterative_bridge_failure_ends_the_thread_with_an_error_finding():
    ws = MagicMock()
    ws.send_and_wait = AsyncMock(side_effect=[
        {"final_text": "ok", "latency_ms": 1.0},
        RuntimeError("No client_agent connected for redteam bridge"),
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
        "RuntimeError: No client_agent connected for redteam bridge"
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
        RuntimeError("No client_agent connected for redteam bridge"),
        {"final_text": "ok", "latency_ms": 1.0},
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
