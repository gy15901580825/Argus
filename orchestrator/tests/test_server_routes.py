"""L3 tests for orchestrator/server.py — routes exercised via TestClient.

We patch the deep agent pipeline (`stream_test_strategy`, `create_test_strategy`)
at the boundary: the server only calls these two functions from orchestrator.agent.
Everything downstream (Google ADK, MCP, LLM) is skipped.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """TestClient for the orchestrator FastAPI app."""
    import server
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------------------
# /orchestrator/v1/strategy/stream (SSE)
# ---------------------------------------------------------------------------

async def _fake_stream(*_args, **_kwargs):
    """Yields a short sequence that exercises both dict and non-dict branches."""
    # Dict with type=artifact → emitted as `event: artifact`
    yield {"type": "artifact", "url": "https://example.invalid/s.py"}
    # Plain dict → emitted as default `data:` line
    yield {"type": "log", "author": "agent", "text": "ok"}


def test_stream_strategy_returns_sse(client):
    """Hit the streaming endpoint and verify it streams SSE correctly."""
    with patch("server.stream_test_strategy", _fake_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "hello", "session_id": "s-1"},
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            body = "".join(resp.iter_text())

    assert "event: artifact" in body
    assert "https://example.invalid/s.py" in body
    # Default data line for the second event
    assert '"type": "log"' in body
    # Completion marker
    assert "event: done" in body


class _FakePart:
    def __init__(self, text: str):
        self.text = text


class _FakeContent:
    def __init__(self, text: str):
        self.parts = [_FakePart(text)]


class _FakeEvent:
    """Duck-typed ADK Event: has .content.parts[0].text and .author."""
    def __init__(self, text: str, author: str = "PlannerAgent"):
        self.content = _FakeContent(text)
        self.author = author


def test_stream_unwraps_planner_passthrough_result(client):
    """Planner passthrough {event_type, payload} → unwrapped to payload JSON."""
    import json as _json

    payload = {"type": "result", "task_id": "t1",
               "bug_counts": {"medium": 1, "critical": 0},
               "final_output": "FINAL REPORT"}
    wrapper_text = _json.dumps(
        {"event_type": "result", "payload": _json.dumps(payload)}
    )

    async def fake_stream(*_args, **_kwargs):
        yield _FakeEvent(wrapper_text)

    with patch("server.stream_test_strategy", fake_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "x", "session_id": "s"},
        ) as resp:
            body = "".join(resp.iter_text())

    # The payload's type survives the unwrap; the wrapper keys are gone.
    assert '"type": "result"' in body or '\\"type\\": \\"result\\"' in body
    assert "FINAL REPORT" in body
    assert '"event_type"' not in body  # wrapper shouldn't leak


def test_stream_unwraps_planner_log_event_to_plain_text(client):
    """Planner log passthrough → plain message (not raw JSON)."""
    import json as _json

    wrapper_text = _json.dumps(
        {"event_type": "log",
         "payload": _json.dumps({"type": "log", "message": "hello world"})}
    )

    async def fake_stream(*_args, **_kwargs):
        yield _FakeEvent(wrapper_text)

    with patch("server.stream_test_strategy", fake_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "x", "session_id": "s"},
        ) as resp:
            body = "".join(resp.iter_text())

    assert "hello world" in body
    assert '"event_type"' not in body


def test_stream_unwraps_planner_ssh_result_to_top_level(client):
    """Planner passthrough of an ssh_result tool event → SSE top-level type:ssh_result.

    The legacy ApiTestingAgent wire format was {type:"ssh_result", stdout, stderr, ...}
    at the SSE top level, which `lib/api.ts:756` synthesizes into an ssh_result typed
    chunk. The planner wraps as {event_type:"ssh_result", payload:{...}} — server.py
    must unwrap so the frontend's synthesis fires and renders the pytest result card.
    """
    import json as _json

    payload = {"type": "ssh_result", "success": True, "exit_code": 0,
               "stdout": "== 3 passed ==", "stderr": "",
               "allure_results_url": "https://allure.example/1"}
    wrapper_text = _json.dumps(
        {"event_type": "ssh_result", "payload": _json.dumps(payload)}
    )

    async def fake_stream(*_args, **_kwargs):
        yield _FakeEvent(wrapper_text)

    with patch("server.stream_test_strategy", fake_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "x", "session_id": "s"},
        ) as resp:
            body = "".join(resp.iter_text())

    # Top-level type is ssh_result, NOT progress.
    assert '"type": "ssh_result"' in body
    # Payload fields spread at top level so the frontend's `parsed.stdout` etc. work.
    assert "== 3 passed ==" in body
    assert '"exit_code": 0' in body
    assert "allure.example" in body
    # Planner wrapper must not leak.
    assert '"event_type"' not in body


def test_stream_keeps_planner_step_wrapper(client):
    """planner_step events must retain the {event_type, payload} wrapper
    — the frontend decodes it explicitly via tryParsePlannerStep."""
    import json as _json

    wrapper_text = _json.dumps(
        {"event_type": "planner_step",
         "payload": _json.dumps({"step_index": 0, "type": "thinking", "text": "..."})}
    )

    async def fake_stream(*_args, **_kwargs):
        yield _FakeEvent(wrapper_text)

    with patch("server.stream_test_strategy", fake_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "x", "session_id": "s"},
        ) as resp:
            body = "".join(resp.iter_text())

    # planner_step wrapper survives so tryParsePlannerStep on the frontend works
    assert "planner_step" in body
    assert "event_type" in body


@pytest.mark.parametrize("event_type,payload", [
    ("wizard_round", {"round_n": 1, "question": "Pick a test type",
                      "options": ["Web UI", "API"], "allow_free_text": False,
                      "allow_back": False, "round_label": "intent"}),
    ("wizard_aborted", {"at_round_label": "params", "rounds_used": 3}),
    ("wizard_guide", {"kind": "local_setup_check",
                      "markdown": "## Setup\nInstall Playwright."}),
])
def test_stream_hoists_wizard_event_to_top_level(client, event_type, payload):
    """Wizard events must be hoisted to top-level SSE with {event_type, payload}
    shape so the frontend's `parsed.event_type === 'wizard_round'` (api.ts:780)
    fires and api_service's `_parse_sse_frame` updates wizard_state. Without
    this, they'd fall through to the generic else branch and ship as
    `{type:"progress", text:"<escaped json>"}` — invisible to both consumers.
    """
    import json as _json

    wrapper_text = _json.dumps(
        {"event_type": event_type, "payload": _json.dumps(payload)}
    )

    async def fake_stream(*_args, **_kwargs):
        yield _FakeEvent(wrapper_text)

    with patch("server.stream_test_strategy", fake_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "x", "session_id": "s"},
        ) as resp:
            body = "".join(resp.iter_text())

    # Find the event-bearing SSE frame and decode it.
    frames = [f for f in body.split("\n\n") if f.startswith("data: ")
              and event_type in f and "progress" not in f.split("\n")[0]]
    assert frames, f"no top-level {event_type} frame in body:\n{body}"
    parsed = _json.loads(frames[0][len("data: "):])
    assert parsed["event_type"] == event_type
    # Frontend (api.ts:781) requires payload to be a *string*, not a dict.
    assert isinstance(parsed["payload"], str)
    assert _json.loads(parsed["payload"]) == payload
    # Must NOT be wrapped in a progress event with text-encoded JSON.
    assert '"type": "progress"' not in body or '"text"' not in body or \
        all(event_type not in (p.get("text") or "")
            for p in (_json.loads(f[len("data: "):])
                      for f in body.split("\n\n")
                      if f.startswith("data: ")
                      and '"type": "progress"' in f))


def test_stream_strategy_validation_error_no_content(client):
    resp = client.post("/orchestrator/v1/strategy/stream", json={})
    assert resp.status_code == 422


def test_stream_strategy_generator_exception_reported(client):
    """An exception raised inside the agent generator → `event: error`."""
    async def exploding(*_args, **_kwargs):
        yield {"type": "log", "text": "before"}
        raise RuntimeError("agent exploded")

    with patch("server.stream_test_strategy", exploding):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "hi"},
        ) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())

    assert "event: error" in body
    assert "agent exploded" in body


def test_stream_strategy_auto_generates_session_id(client):
    """When caller omits session_id, server generates one (no 4xx/5xx)."""
    captured = {}

    async def recording_stream(**kwargs):
        captured.update(kwargs)
        yield {"type": "progress", "text": "ack"}

    with patch("server.stream_test_strategy", recording_stream):
        with client.stream(
            "POST",
            "/orchestrator/v1/strategy/stream",
            json={"content": "x"},
        ) as resp:
            assert resp.status_code == 200
            # Drain the body to let the generator run
            "".join(resp.iter_text())

    assert captured.get("session_id")  # non-empty
    assert len(captured["session_id"]) >= 8


# ---------------------------------------------------------------------------
# /orchestrator/v1/strategy/create (non-streaming)
# ---------------------------------------------------------------------------

def test_create_strategy_success(client):
    async def fake_create(**_kwargs):
        return {
            "success": True,
            "response": "done",
            "generated_content": {"strategy": "..."},
        }

    with patch("server.create_test_strategy", AsyncMock(side_effect=fake_create)):
        resp = client.post(
            "/orchestrator/v1/strategy/create",
            json={"content": "test this"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["response"] == "done"
    assert body["generated_content"]["strategy"] == "..."
    assert body["error"] is None


def test_create_strategy_failure_returns_success_false(client):
    async def fake_create(**_kwargs):
        return {"success": False, "error": "no content"}

    with patch("server.create_test_strategy", AsyncMock(side_effect=fake_create)):
        resp = client.post(
            "/orchestrator/v1/strategy/create",
            json={"content": "test this"},
        )
    # The endpoint is explicit about returning 200 even on failure, with success=False
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is False
    assert body["error"] == "no content"


def test_create_strategy_internal_exception_is_500(client):
    async def boom(**_kwargs):
        raise ValueError("catastrophic")

    with patch("server.create_test_strategy", AsyncMock(side_effect=boom)):
        resp = client.post(
            "/orchestrator/v1/strategy/create",
            json={"content": "test"},
        )
    assert resp.status_code == 500
    assert "catastrophic" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# /orchestrator/run_command
# ---------------------------------------------------------------------------

def test_run_command_success(client):
    import server
    server.connection_manager.send_command = AsyncMock(return_value={"echo": 1})

    resp = client.post(
        "/orchestrator/run_command",
        json={"agent_id": "a1", "tool_name": "ping", "arguments": {"x": 1}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["result"] == {"echo": 1}

    server.connection_manager.send_command.assert_awaited_once_with(
        "a1", "tools/call", {"name": "ping", "arguments": {"x": 1}}
    )


def test_run_command_failure_returns_500(client):
    import server
    server.connection_manager.send_command = AsyncMock(
        side_effect=RuntimeError("ws dead")
    )

    resp = client.post(
        "/orchestrator/run_command",
        json={"agent_id": "a1", "tool_name": "ping", "arguments": {}},
    )
    assert resp.status_code == 500
    assert "ws dead" in resp.json()["detail"]


def test_run_command_validation_error(client):
    # Missing required fields
    resp = client.post("/orchestrator/run_command", json={"agent_id": "a1"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /orchestrator/v1/cancel-web-ui-test
# ---------------------------------------------------------------------------

def test_cancel_web_ui_test_not_found_when_no_active_task(client):
    from orchestrator.agents.common import client_web_ui_agent as cwua
    cwua._active_tasks.clear()

    resp = client.post(
        "/orchestrator/v1/cancel-web-ui-test",
        json={"user_id": "nobody"},
    )
    assert resp.status_code == 404
    assert "No active Web UI test" in resp.json()["detail"]


def test_cancel_web_ui_test_agent_disconnected(client):
    import server
    from orchestrator.agents.common import client_web_ui_agent as cwua

    cwua._active_tasks.clear()
    cwua._active_tasks["user-x"] = ("agent-gone", "task-1")
    # No active connection for agent-gone
    server.connection_manager.active_connections.pop("agent-gone", None)

    resp = client.post(
        "/orchestrator/v1/cancel-web-ui-test",
        json={"user_id": "user-x"},
    )
    assert resp.status_code == 404
    assert "no longer connected" in resp.json()["detail"]
    # active task was popped on the failed path
    assert "user-x" not in cwua._active_tasks


def test_cancel_web_ui_test_success(client):
    import server
    from orchestrator.agents.common import client_web_ui_agent as cwua

    cwua._active_tasks.clear()
    cwua._active_tasks["user-y"] = ("agent-here", "task-42")
    # Simulate an active WS connection — value content doesn't matter for this path
    server.connection_manager.active_connections["agent-here"] = object()
    server.connection_manager.send_command = AsyncMock(return_value={"ok": True})

    resp = client.post(
        "/orchestrator/v1/cancel-web-ui-test",
        json={"user_id": "user-y"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "cancelled", "task_id": "task-42"}
    # _active_tasks entry removed
    assert "user-y" not in cwua._active_tasks
    server.connection_manager.send_command.assert_awaited_once()
    args, _ = server.connection_manager.send_command.await_args
    assert args[0] == "agent-here"
    assert args[1] == "tools/call"
    assert args[2]["name"] == "cancel_web_ui_test"
    assert args[2]["arguments"]["task_id"] == "task-42"
    # Cleanup: remove fake active connection
    server.connection_manager.active_connections.pop("agent-here", None)


def test_cancel_web_ui_test_command_failure_returns_502(client):
    import server
    from orchestrator.agents.common import client_web_ui_agent as cwua

    cwua._active_tasks.clear()
    cwua._active_tasks["user-z"] = ("agent-here-2", "task-7")
    server.connection_manager.active_connections["agent-here-2"] = object()
    server.connection_manager.send_command = AsyncMock(side_effect=RuntimeError("ws err"))

    resp = client.post(
        "/orchestrator/v1/cancel-web-ui-test",
        json={"user_id": "user-z"},
    )
    assert resp.status_code == 502
    assert "Failed to cancel task" in resp.json()["detail"]
    # Cleanup
    server.connection_manager.active_connections.pop("agent-here-2", None)
    cwua._active_tasks.pop("user-z", None)


# ---------------------------------------------------------------------------
# App sanity — registered routes include the expected paths.
# (Intentionally NOT hitting /openapi.json: server.py's `...` example literals
#  break Pydantic v2 serialization — a known production-code quirk.)
# ---------------------------------------------------------------------------

def test_app_registers_expected_routes(client):
    import server

    paths = {getattr(r, "path", None) for r in server.app.routes}
    assert "/orchestrator/v1/strategy/stream" in paths
    assert "/orchestrator/v1/strategy/create" in paths
    assert "/orchestrator/run_command" in paths
    assert "/orchestrator/v1/cancel-web-ui-test" in paths
    assert "/agent/connect" in paths  # WebSocket route
