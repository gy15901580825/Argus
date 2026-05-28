"""L3 tests for ClientAgent — init, register, tool dispatch, and tool listing.

We mock httpx.AsyncClient for register and patch web_ui_runner functions for
tool dispatch so no real browser/HTTP ever runs.
"""
from __future__ import annotations

import asyncio
import json
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


# ---------------------------------------------------------------------------
# handle_tool_call — dispatch table
# ---------------------------------------------------------------------------

def _agent():
    import client_agent
    return client_agent.ClientAgent(
        orchestrator_url="wss://o.invalid",
        api_service_url="http://api.invalid",
        agent_name="agent-x",
        api_token="tok",
    )


def test_handle_tool_call_fetch_url_missing_argument_returns_error():
    agent = _agent()
    result = asyncio.run(agent.handle_tool_call("fetch_url", {}))
    assert result == {"error": "Missing url argument"}


def test_handle_tool_call_fetch_url_delegates_to_fetch_url_impl():
    agent = _agent()

    async def _fake_fetch(url, cookie=None, token=None):
        return json.dumps({"got_url": url, "got_cookie": cookie, "got_token": token})

    with patch("client_agent.fetch_url_impl", _fake_fetch):
        out = asyncio.run(agent.handle_tool_call(
            "fetch_url",
            {"url": "http://x.invalid/", "cookies": "c=1", "token": "t"},
        ))

    parsed = json.loads(out)
    assert parsed["got_url"] == "http://x.invalid/"
    # fetch_url accepts either "cookie" or "cookies"
    assert parsed["got_cookie"] == "c=1"
    assert parsed["got_token"] == "t"


def test_handle_tool_call_unknown_tool_returns_error():
    agent = _agent()
    result = asyncio.run(agent.handle_tool_call("no_such_tool", {}))
    assert result == {"error": "Unknown tool: no_such_tool"}


def test_handle_tool_call_start_web_ui_test_delegates_to_runner():
    import client_agent
    agent = _agent()

    fake_start = MagicMock(return_value={"task_id": "T-1", "status": "pending"})
    with patch.object(client_agent, "_WEB_UI_ENABLED", True), \
         patch.object(client_agent.web_ui_runner, "start_web_ui_test", fake_start):
        out = asyncio.run(agent.handle_tool_call("start_web_ui_test", {
            "url": "http://t.invalid/",
            "max_steps": "50",
            "user_persona": "power_user",
        }))

    assert out == {"task_id": "T-1", "status": "pending"}
    # max_steps must have been coerced to int
    kwargs = fake_start.call_args.kwargs
    assert kwargs["max_steps"] == 50
    assert kwargs["url"] == "http://t.invalid/"
    assert kwargs["user_persona"] == "power_user"


def test_handle_tool_call_start_web_ui_test_missing_url_returns_error():
    agent = _agent()
    out = asyncio.run(agent.handle_tool_call("start_web_ui_test", {}))
    assert out == {"error": "Missing 'url' argument"}


def test_handle_tool_call_start_web_ui_test_errors_when_web_ui_disabled():
    import client_agent
    agent = _agent()

    with patch.object(client_agent, "_WEB_UI_ENABLED", False):
        out = asyncio.run(agent.handle_tool_call("start_web_ui_test", {"url": "http://t.invalid/"}))

    assert "not available" in out["error"].lower()


def test_handle_tool_call_status_missing_task_id_errors():
    agent = _agent()
    out = asyncio.run(agent.handle_tool_call("get_web_ui_test_status", {}))
    assert out == {"error": "Missing 'task_id' argument"}


def test_handle_tool_call_status_delegates_to_runner():
    import client_agent
    agent = _agent()

    fake_status = MagicMock(return_value={"task_id": "T-9", "status": "running"})
    with patch.object(client_agent, "_WEB_UI_ENABLED", True), \
         patch.object(client_agent.web_ui_runner, "get_web_ui_test_status", fake_status):
        out = asyncio.run(agent.handle_tool_call(
            "get_web_ui_test_status", {"task_id": "T-9"},
        ))
    assert out == {"task_id": "T-9", "status": "running"}
    fake_status.assert_called_once_with("T-9")


def test_handle_tool_call_result_delegates_to_runner():
    import client_agent
    agent = _agent()

    fake_result = MagicMock(return_value={"task_id": "T-9", "test_script": "def test_x():\n    pass\n"})
    with patch.object(client_agent, "_WEB_UI_ENABLED", True), \
         patch.object(client_agent.web_ui_runner, "get_web_ui_test_result", fake_result):
        out = asyncio.run(agent.handle_tool_call("get_web_ui_test_result", {"task_id": "T-9"}))
    assert out["test_script"].startswith("def test_x")


def test_handle_tool_call_cancel_delegates_to_runner():
    import client_agent
    agent = _agent()

    fake_cancel = MagicMock(return_value={"task_id": "T-9", "status": "cancelled"})
    with patch.object(client_agent, "_WEB_UI_ENABLED", True), \
         patch.object(client_agent.web_ui_runner, "cancel_web_ui_test", fake_cancel):
        out = asyncio.run(agent.handle_tool_call("cancel_web_ui_test", {"task_id": "T-9"}))
    assert out["status"] == "cancelled"


# ---------------------------------------------------------------------------
# handle_tools_list
# ---------------------------------------------------------------------------

def test_handle_tools_list_always_includes_fetch_url():
    import client_agent
    agent = _agent()

    with patch.object(client_agent, "_WEB_UI_ENABLED", False):
        tools = asyncio.run(agent.handle_tools_list({}))

    names = [t["name"] for t in tools]
    assert names == ["fetch_url"]


def test_handle_tools_list_adds_web_ui_tools_when_enabled():
    import client_agent
    agent = _agent()

    with patch.object(client_agent, "_WEB_UI_ENABLED", True):
        tools = asyncio.run(agent.handle_tools_list({}))

    names = {t["name"] for t in tools}
    # Original + 4 web UI tools
    assert names == {
        "fetch_url",
        "start_web_ui_test",
        "get_web_ui_test_status",
        "get_web_ui_test_result",
        "cancel_web_ui_test",
    }
    # Check schema shape of start_web_ui_test
    start = next(t for t in tools if t["name"] == "start_web_ui_test")
    assert start["parameters"]["url"]["required"] is True
    assert "user_persona" in start["parameters"]
