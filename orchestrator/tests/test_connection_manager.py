"""Unit tests for orchestrator/connection_manager.py."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import HTTPException


@pytest.fixture
def quiet_status_notify():
    """Stub out the outbound API Service status-update HTTP call.

    connect/disconnect post to API Service to flip agent status. In tests we
    don't want real HTTP — patch httpx.AsyncClient.post where it is used.
    """
    with patch("connection_manager.httpx.AsyncClient") as mock_client_cls:
        instance = AsyncMock()
        instance.post = AsyncMock(return_value=AsyncMock(status_code=200))
        # Context manager: async with httpx.AsyncClient() as client:
        mock_client_cls.return_value.__aenter__.return_value = instance
        mock_client_cls.return_value.__aexit__.return_value = False
        yield instance


async def test_connect_registers_agent(fresh_manager, fake_ws, quiet_status_notify):
    await fresh_manager.connect(fake_ws, "agent-1")

    assert "agent-1" in fresh_manager.active_connections
    assert fresh_manager.active_connections["agent-1"] is fake_ws
    fake_ws.accept.assert_awaited_once()
    # Status notification POSTed
    assert quiet_status_notify.post.await_count == 1
    args, kwargs = quiet_status_notify.post.await_args
    assert "/api/v1/internal/agent/status" in args[0]
    assert kwargs["json"]["agent_id"] == "agent-1"
    assert kwargs["json"]["status"] == "active"


async def test_disconnect_removes_agent(fresh_manager, fake_ws, quiet_status_notify):
    await fresh_manager.connect(fake_ws, "agent-2")
    quiet_status_notify.post.reset_mock()

    await fresh_manager.disconnect("agent-2")

    assert "agent-2" not in fresh_manager.active_connections
    # Offline status notified
    assert quiet_status_notify.post.await_count == 1
    _, kwargs = quiet_status_notify.post.await_args
    assert kwargs["json"]["status"] == "offline"


async def test_disconnect_unknown_agent_is_noop(fresh_manager, quiet_status_notify):
    # No connect first — disconnect should simply return without error.
    await fresh_manager.disconnect("ghost")
    assert fresh_manager.active_connections == {}
    # No status POST issued for unknown agents
    assert quiet_status_notify.post.await_count == 0


async def test_send_command_to_missing_agent_raises_404(fresh_manager):
    with pytest.raises(HTTPException) as exc_info:
        await fresh_manager.send_command("nobody", "tools/call", {})
    assert exc_info.value.status_code == 404
    assert "not connected" in exc_info.value.detail


async def test_send_command_round_trip(fresh_manager, fake_ws, quiet_status_notify):
    """send_command should send the JSON-RPC envelope and resolve via handle_response."""
    await fresh_manager.connect(fake_ws, "agent-3")

    async def _respond_when_sent():
        # Wait until send_json has been called, then simulate the agent responding.
        for _ in range(50):
            if fake_ws.send_json.await_count >= 1:
                break
            await asyncio.sleep(0.01)
        sent = fake_ws.send_json.await_args.args[0]
        fresh_manager.handle_response({
            "jsonrpc": "2.0",
            "id": sent["id"],
            "result": {"ok": True, "echo": sent["params"]},
        })

    responder = asyncio.create_task(_respond_when_sent())
    result = await fresh_manager.send_command(
        "agent-3", "tools/call", {"name": "ping", "arguments": {}}
    )
    await responder

    assert result == {"ok": True, "echo": {"name": "ping", "arguments": {}}}
    # Envelope shape
    sent = fake_ws.send_json.await_args.args[0]
    assert sent["jsonrpc"] == "2.0"
    assert sent["method"] == "tools/call"
    assert sent["params"] == {"name": "ping", "arguments": {}}
    assert sent["id"].startswith("cmd-")
    # pending_commands cleared by handle_response
    assert fresh_manager.pending_commands == {}


async def test_send_command_timeout_cleans_up(fresh_manager, fake_ws, quiet_status_notify, monkeypatch):
    """If the agent never responds, send_command must raise 504 and not leak futures."""
    await fresh_manager.connect(fake_ws, "agent-4")

    # Patch wait_for to immediately raise TimeoutError — avoid 30s sleep.
    async def instant_timeout(*_args, **_kwargs):
        raise asyncio.TimeoutError()

    monkeypatch.setattr("connection_manager.asyncio.wait_for", instant_timeout)

    with pytest.raises(HTTPException) as exc_info:
        await fresh_manager.send_command("agent-4", "tools/call", {})
    assert exc_info.value.status_code == 504
    # pending_commands cleaned up
    assert fresh_manager.pending_commands == {}


async def test_handle_response_error_propagates(fresh_manager, fake_ws, quiet_status_notify):
    """handle_response with an error payload should raise through the awaiting caller."""
    await fresh_manager.connect(fake_ws, "agent-5")

    async def _respond_error_when_sent():
        for _ in range(50):
            if fake_ws.send_json.await_count >= 1:
                break
            await asyncio.sleep(0.01)
        sent = fake_ws.send_json.await_args.args[0]
        fresh_manager.handle_response({
            "jsonrpc": "2.0",
            "id": sent["id"],
            "error": {"code": -1, "message": "boom"},
        })

    responder = asyncio.create_task(_respond_error_when_sent())
    with pytest.raises(Exception) as exc_info:
        await fresh_manager.send_command("agent-5", "tools/call", {})
    await responder

    # The exception message wraps the original error dict
    assert "boom" in str(exc_info.value)
    assert fresh_manager.pending_commands == {}


def test_handle_response_unknown_id_is_ignored(fresh_manager):
    # Should not raise, just log a warning and return.
    fresh_manager.handle_response({"jsonrpc": "2.0", "id": "no-such-cmd", "result": {}})
    fresh_manager.handle_response({"jsonrpc": "2.0", "result": {}})  # no id at all
    assert fresh_manager.pending_commands == {}


async def test_redteam_bridge_round_trip(fresh_manager, fake_ws, quiet_status_notify):
    """RedteamBridge.send_and_wait wraps the message in a UUID-keyed envelope and
    resolves via handle_response."""
    await fresh_manager.connect(fake_ws, "agent-rt-1")
    bridge = fresh_manager.get_redteam_bridge()

    async def _respond_when_sent():
        for _ in range(50):
            if fake_ws.send_json.await_count >= 1:
                break
            await asyncio.sleep(0.01)
        sent = fake_ws.send_json.await_args.args[0]
        fresh_manager.handle_response({
            "jsonrpc": "2.0",
            "id": sent["id"],
            "result": {"final_text": "ok", "latency_ms": 12.0},
        })

    msg = {"scenario_kind": "dom_injection", "agent_url": "http://x", "payload": "p"}
    responder = asyncio.create_task(_respond_when_sent())
    result = await bridge.send_and_wait(msg, timeout_s=2.0)
    await responder

    assert result == {"final_text": "ok", "latency_ms": 12.0}
    sent = fake_ws.send_json.await_args.args[0]
    assert sent["method"] == "redteam_browser_probe"
    assert sent["params"] == msg
    # UUID-shaped id (8-4-4-4-12)
    assert len(sent["id"].split("-")) == 5
    assert fresh_manager.pending_commands == {}


async def test_redteam_bridge_no_agent_raises(fresh_manager):
    bridge = fresh_manager.get_redteam_bridge()
    with pytest.raises(RuntimeError, match="No client_agent connected"):
        await bridge.send_and_wait({"scenario_kind": "x", "agent_url": "y", "payload": "z"})


async def test_redteam_bridge_timeout_cleans_up(fresh_manager, fake_ws, quiet_status_notify):
    """If the agent never responds, send_and_wait must raise TimeoutError and not leak futures."""
    await fresh_manager.connect(fake_ws, "agent-rt-2")
    bridge = fresh_manager.get_redteam_bridge()
    with pytest.raises(asyncio.TimeoutError):
        await bridge.send_and_wait({"scenario_kind": "x", "agent_url": "y", "payload": "z"}, timeout_s=0.05)
    assert fresh_manager.pending_commands == {}


async def test_connect_tolerates_api_service_failure(fresh_manager, fake_ws):
    """If the API Service status update fails, connection should still succeed."""
    with patch("connection_manager.httpx.AsyncClient") as mock_client_cls:
        instance = AsyncMock()
        instance.post = AsyncMock(side_effect=httpx.ConnectError("no route"))
        mock_client_cls.return_value.__aenter__.return_value = instance
        mock_client_cls.return_value.__aexit__.return_value = False

        await fresh_manager.connect(fake_ws, "agent-6")

    # Agent is still considered connected — we don't want a remote status call
    # failure to drop the WebSocket.
    assert "agent-6" in fresh_manager.active_connections
