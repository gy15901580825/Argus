"""L3 tests for ClientAgent — init and register.

We mock httpx.AsyncClient for register so no real HTTP ever runs.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


# ---------------------------------------------------------------------------
# __init__ validation
# ---------------------------------------------------------------------------

def test_init_requires_credentials_or_api_token():
    import client_agent

    with pytest.raises(ValueError, match="Either credentials"):
        client_agent.ClientAgent(
            orchestrator_url="wss://o.invalid",
            api_service_url="http://a.invalid",
            agent_name="agent-x",
        )


def test_init_creates_oauth_client_when_username_password_given():
    import client_agent

    agent = client_agent.ClientAgent(
        orchestrator_url="wss://o.invalid",
        api_service_url="http://a.invalid",
        agent_name="agent-x",
        username="u",
        password="p",
    )
    assert agent.oauth_client is not None
    assert agent.oauth_client.username == "u"
    assert agent.api_token is None
    assert agent.agent_name == "agent-x"


def test_init_api_token_only_path_sets_no_oauth():
    import client_agent

    agent = client_agent.ClientAgent(
        orchestrator_url="wss://o.invalid",
        api_service_url="http://a.invalid",
        agent_name="agent-x",
        api_token="tk-1",
    )
    assert agent.oauth_client is None
    assert agent.api_token == "tk-1"


# ---------------------------------------------------------------------------
# register()
# ---------------------------------------------------------------------------

class _FakeAsyncClient:
    def __init__(self, post_response=None, raise_exc=None):
        self._post_response = post_response
        self._raise_exc = raise_exc
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "headers": dict(headers or {}), "json": json})
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._post_response


def _ok_register_response(agent_id="agent-42"):
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"agent_id": agent_id})
    return resp


def test_register_with_api_token_sends_x_api_token_header():
    import client_agent

    agent = client_agent.ClientAgent(
        orchestrator_url="wss://o.invalid",
        api_service_url="http://api.invalid",
        agent_name="agent-x",
        api_token="tok-xyz",
    )

    fake = _FakeAsyncClient(post_response=_ok_register_response("agent-42"))
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        asyncio.run(agent.register())

    assert agent.agent_id == "agent-42"
    call = fake.calls[0]
    assert call["url"] == "http://api.invalid/api/v1/agent/register"
    assert call["headers"].get("x-api-token") == "tok-xyz"
    assert "Authorization" not in call["headers"]
    # Body should describe the agent
    body = call["json"]
    assert body["agent_name"] == "agent-x"
    assert body["agent_type"] == "web_fetcher"


def test_register_with_oauth_uses_bearer_token_from_oauth_client():
    import client_agent

    agent = client_agent.ClientAgent(
        orchestrator_url="wss://o.invalid",
        api_service_url="http://api.invalid",
        agent_name="agent-y",
        username="u", password="p",
    )
    # Pre-seed the OAuth client's token so we don't hit the login endpoint.
    agent.oauth_client.access_token = "jwt-abcdef-1234567890-xyz"
    from datetime import datetime, timedelta
    agent.oauth_client.token_expires_at = datetime.now() + timedelta(hours=1)

    fake = _FakeAsyncClient(post_response=_ok_register_response("agent-99"))
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        asyncio.run(agent.register())

    assert agent.agent_id == "agent-99"
    call = fake.calls[0]
    assert call["headers"]["Authorization"] == "Bearer jwt-abcdef-1234567890-xyz"


def test_register_raises_descriptive_error_on_http_401():
    import client_agent

    err_resp = MagicMock()
    err_resp.status_code = 401
    err_resp.text = '{"detail": "invalid token"}'
    err_resp.json = MagicMock(return_value={"detail": "invalid token"})
    err_resp.headers = {}
    http_err = httpx.HTTPStatusError("401", request=MagicMock(), response=err_resp)

    raising_resp = MagicMock()
    raising_resp.raise_for_status = MagicMock(side_effect=http_err)
    raising_resp.status_code = 401

    fake = _FakeAsyncClient(post_response=raising_resp)

    agent = client_agent.ClientAgent(
        orchestrator_url="wss://o.invalid",
        api_service_url="http://api.invalid",
        agent_name="agent-x",
        api_token="bad-token",
    )
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        with pytest.raises(Exception, match="Registration failed"):
            asyncio.run(agent.register())

