"""/agent/connect: optional shared secret and refusal of duplicate agent ids."""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


@pytest.fixture
def hub(monkeypatch):
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    monkeypatch.delenv("AGENT_CONNECT_SECRET", raising=False)
    from connection_manager import connection_manager
    from server import app

    connection_manager.active_connections.clear()
    yield TestClient(app), connection_manager
    connection_manager.active_connections.clear()


def _refused(client, headers):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/agent/connect", headers=headers) as ws:
            # An accepted socket answers the ping; a refused one raises here.
            ws.send_json({"jsonrpc": "2.0", "method": "ping", "id": 0})
            ws.receive_json()
    return exc.value.code


def test_secret_set_and_header_missing_is_refused(hub, monkeypatch):
    client, manager = hub
    monkeypatch.setenv("AGENT_CONNECT_SECRET", "s3cret")
    assert _refused(client, {"x-agent-id": "a1"}) == 1008
    assert "a1" not in manager.active_connections


def test_secret_set_and_header_wrong_is_refused(hub, monkeypatch):
    client, manager = hub
    monkeypatch.setenv("AGENT_CONNECT_SECRET", "s3cret")
    assert _refused(client, {"x-agent-id": "a1", "x-agent-secret": "nope"}) == 1008
    assert "a1" not in manager.active_connections


def test_secret_set_and_header_matches_connects(hub, monkeypatch):
    client, manager = hub
    monkeypatch.setenv("AGENT_CONNECT_SECRET", "s3cret")
    with client.websocket_connect("/agent/connect", headers={"x-agent-id": "a1", "x-agent-secret": "s3cret"}) as ws:
        ws.send_json({"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert ws.receive_json()["result"] == "pong"
        assert "a1" in manager.active_connections


def test_no_secret_configured_connects_without_header(hub):
    client, manager = hub
    with client.websocket_connect("/agent/connect", headers={"x-agent-id": "a2"}) as ws:
        ws.send_json({"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert ws.receive_json()["result"] == "pong"
        assert "a2" in manager.active_connections


def test_second_connection_with_same_id_is_refused_and_first_kept(hub):
    client, manager = hub
    with client.websocket_connect("/agent/connect", headers={"x-agent-id": "dup"}) as first:
        first.send_json({"jsonrpc": "2.0", "method": "ping", "id": 1})
        first.receive_json()
        original = manager.active_connections["dup"]
        assert _refused(client, {"x-agent-id": "dup"}) == 1008
        assert manager.active_connections["dup"] is original
        first.send_json({"jsonrpc": "2.0", "method": "ping", "id": 2})
        assert first.receive_json()["result"] == "pong"


def test_startup_warns_when_no_secret(monkeypatch, caplog):
    from server import log_agent_auth_mode

    monkeypatch.delenv("AGENT_CONNECT_SECRET", raising=False)
    with caplog.at_level(logging.WARNING):
        log_agent_auth_mode()
    assert any("unauthenticated" in r.getMessage() for r in caplog.records)

    caplog.clear()
    monkeypatch.setenv("AGENT_CONNECT_SECRET", "s3cret")
    with caplog.at_level(logging.WARNING):
        log_agent_auth_mode()
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
