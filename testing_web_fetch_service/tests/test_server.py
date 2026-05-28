"""
Tests for `server.py` — the MCP tool wrapper and the /result/{id} cache.

We exercise:
  - fetch_internal_page (MCP tool): caches full result and returns a summary
  - fetch_internal_page fallback when impl returns non-JSON
  - get_cached_result (FastAPI endpoint): 200 on hit, 404 on miss
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


def _get_mcp_tool_fn(server):
    """The @mcp.tool() decorator wraps the function. Pull the real coroutine
    off the FastMCP server by looking it up in sys.modules."""
    # server.py defines `async def fetch_internal_page(...)` at module level;
    # the decorator in this version of FastMCP returns the original function,
    # so the module-level reference is still callable.
    return server.fetch_internal_page


# ---------------------------------------------------------------------------
# fetch_internal_page — happy path: impl returns JSON, summary is built
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_builds_summary_and_caches():
    import server

    full = {
        "text": "a" * 20000,  # larger than 10k truncation
        "links": ["https://a/1", "https://a/2"],
        "scripts": [],
        "api_spec": {"url": "x", "spec": {"openapi": "3.0.0"}},
        "crawled_apis": [{"method": "GET", "endpoint": "/x"}],
        "metadata": {"title": "Hello", "status_code": 200},
    }

    async def _fake_impl(url, cookie=None, token=None):
        return json.dumps(full)

    # Clear the cache to assert after the call.
    server.RESULT_CACHE.clear()

    with patch.object(server, "fetch_internal_page_impl", side_effect=_fake_impl):
        fn = _get_mcp_tool_fn(server)
        raw = await fn("https://example.com/")

    payload = json.loads(raw)
    assert payload["status"] == "success"
    assert payload["url"] == "https://example.com/"
    assert payload["summary"]["title"] == "Hello"
    assert payload["summary"]["status_code"] == 200
    assert payload["summary"]["api_spec_found"] is True
    assert payload["summary"]["crawled_apis_count"] == 1
    assert payload["summary"]["links_count"] == 2
    # text is truncated to 10 000
    assert len(payload["text"]) == 10000
    # result_id points at a cached entry with the original data
    assert payload["result_id"] in server.RESULT_CACHE
    assert server.RESULT_CACHE[payload["result_id"]]["data"] == full


# ---------------------------------------------------------------------------
# fetch_internal_page — non-JSON impl response is returned verbatim
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_returns_raw_string_when_not_json():
    import server

    async def _fake_impl(url, cookie=None, token=None):
        return "plain-text not json"

    with patch.object(server, "fetch_internal_page_impl", side_effect=_fake_impl):
        fn = _get_mcp_tool_fn(server)
        raw = await fn("https://example.com/")

    assert raw == "plain-text not json"


# ---------------------------------------------------------------------------
# GET /result/{id} — hit and miss
# ---------------------------------------------------------------------------
def test_cached_result_endpoint_returns_stored_data():
    import server

    server.RESULT_CACHE.clear()
    server.RESULT_CACHE["abc"] = {"timestamp": "t", "data": {"hello": "world"}}

    client = TestClient(server.app)
    resp = client.get("/result/abc")
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}


def test_cached_result_endpoint_404_on_missing_id():
    import server

    server.RESULT_CACHE.clear()
    client = TestClient(server.app)
    resp = client.get("/result/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Result ID not found or expired"
