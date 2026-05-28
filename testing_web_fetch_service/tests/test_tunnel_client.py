"""
Unit tests for `tunnel_client.execute_tool` — the JSON-RPC tool dispatcher.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_execute_tool_dispatches_fetch_internal_page():
    import tunnel_client

    payload = {"status": "ok", "text": "hello"}

    async def _fake_impl(url, cookie=None, token=None):
        return json.dumps(payload)

    with patch.object(tunnel_client, "fetch_internal_page_impl", side_effect=_fake_impl):
        result = await tunnel_client.execute_tool(
            "fetch_internal_page",
            {"url": "https://example.com/"},
        )

    assert result == payload


@pytest.mark.asyncio
async def test_execute_tool_missing_url_returns_error():
    import tunnel_client

    result = await tunnel_client.execute_tool("fetch_internal_page", {})
    assert result == {"error": "Missing 'url' argument"}


@pytest.mark.asyncio
async def test_execute_tool_unknown_tool_returns_error():
    import tunnel_client

    result = await tunnel_client.execute_tool("no_such_tool", {"foo": 1})
    assert result == {"error": "Unknown tool: no_such_tool"}


@pytest.mark.asyncio
async def test_execute_tool_captures_impl_exception():
    import tunnel_client

    async def _boom(url, cookie=None, token=None):
        raise RuntimeError("kaboom")

    with patch.object(tunnel_client, "fetch_internal_page_impl", side_effect=_boom):
        result = await tunnel_client.execute_tool(
            "fetch_internal_page",
            {"url": "https://x/"},
        )

    assert "error" in result
    assert "kaboom" in result["error"]
