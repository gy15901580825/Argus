"""
Unit tests for `tools_impl.fetch_internal_page_impl` and `_probe_openapi`.

We patch `httpx.AsyncClient` (and `ai_crawler.crawl_for_apis`) at the
boundary so no real network calls happen.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mock_response(status_code: int = 200, text: str = "", json_data=None, url: str = "https://example.com/"):
    """Build a MagicMock standing in for an httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = url
    if json_data is None:
        resp.json = MagicMock(side_effect=json.JSONDecodeError("no json", "", 0))
    else:
        resp.json = MagicMock(return_value=json_data)
    return resp


class _FakeAsyncClient:
    """Stand-in for `httpx.AsyncClient` used as an async context manager."""

    def __init__(self, responses_by_url=None, default_response=None):
        self._responses = responses_by_url or {}
        self._default = default_response
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None, timeout=None):
        self.requests.append({"url": url, "headers": headers, "timeout": timeout})
        if url in self._responses:
            return self._responses[url]
        if self._default is not None:
            return self._default
        raise RuntimeError(f"No mock response configured for {url}")


# ---------------------------------------------------------------------------
# fetch_internal_page_impl — HTML page with links/scripts
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_parses_html_links_and_scripts():
    import tools_impl

    html = """
    <html><head><title>Demo</title></head>
    <body>
      <a href="/about">About</a>
      <a href="https://external.com/x">Ext</a>
      <script src="/app.js"></script>
      <p>Hello  world</p>
    </body></html>
    """
    resp = _mock_response(status_code=200, text=html, url="https://example.com/")
    client = _FakeAsyncClient(default_response=resp)

    with patch.object(tools_impl.httpx, "AsyncClient", return_value=client), \
         patch.object(tools_impl, "crawl_for_apis", return_value=[]):
        # prevent asyncio.to_thread from actually running the crawler
        async def _fake_to_thread(fn, *args, **kwargs):
            return fn(*args, **kwargs)
        with patch.object(tools_impl.asyncio, "to_thread", side_effect=_fake_to_thread):
            raw = await tools_impl.fetch_internal_page_impl("https://example.com/")

    data = json.loads(raw)
    assert data["metadata"]["status_code"] == 200
    assert data["metadata"]["title"] == "Demo"
    assert "https://example.com/about" in data["links"]
    assert "https://external.com/x" in data["links"]
    assert "https://example.com/app.js" in data["scripts"]
    assert "Hello" in data["text"]
    assert "world" in data["text"]
    # No API spec should be produced for this HTML
    assert data["api_spec"] is None


# ---------------------------------------------------------------------------
# fetch_internal_page_impl — HTTP error early-exits
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_http_error_returns_early():
    import tools_impl

    resp = _mock_response(status_code=500, text="", url="https://example.com/")
    client = _FakeAsyncClient(default_response=resp)

    with patch.object(tools_impl.httpx, "AsyncClient", return_value=client):
        raw = await tools_impl.fetch_internal_page_impl("https://example.com/")

    data = json.loads(raw)
    assert data["metadata"]["status_code"] == 500
    # BeautifulSoup/links path skipped on 4xx/5xx
    assert data["links"] == []
    assert data["scripts"] == []
    assert data["text"] == ""


# ---------------------------------------------------------------------------
# fetch_internal_page_impl — JSON response is recognized as API spec
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_detects_openapi_json_response():
    import tools_impl

    spec = {"openapi": "3.0.0", "info": {"title": "t"}, "paths": {}}
    resp = _mock_response(status_code=200, text=json.dumps(spec), url="https://example.com/openapi.json")
    resp.json = MagicMock(return_value=spec)  # override to succeed
    client = _FakeAsyncClient(default_response=resp)

    with patch.object(tools_impl.httpx, "AsyncClient", return_value=client):
        raw = await tools_impl.fetch_internal_page_impl("https://example.com/openapi.json")

    data = json.loads(raw)
    assert data["api_spec"] is not None
    assert data["api_spec"]["url"] == "https://example.com/openapi.json"
    assert data["api_spec"]["spec"] == spec
    assert "JSON API Specification" in data["text"]


# ---------------------------------------------------------------------------
# fetch_internal_page_impl — cookie/token headers are threaded through
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_passes_cookie_and_bearer_token():
    import tools_impl

    resp = _mock_response(status_code=200, text="<html></html>", url="https://example.com/")
    client = _FakeAsyncClient(default_response=resp)

    async def _fake_to_thread(fn, *args, **kwargs):
        return []

    with patch.object(tools_impl.httpx, "AsyncClient", return_value=client), \
         patch.object(tools_impl, "crawl_for_apis", return_value=[]), \
         patch.object(tools_impl.asyncio, "to_thread", side_effect=_fake_to_thread):
        await tools_impl.fetch_internal_page_impl(
            "https://example.com/",
            cookie="sid=abc",
            token="jwt-value",
        )

    assert client.requests, "expected at least one request"
    headers = client.requests[0]["headers"]
    assert headers["Cookie"] == "sid=abc"
    assert headers["Authorization"] == "Bearer jwt-value"
    assert headers["User-Agent"] == "MCP-Agent/1.0"


# ---------------------------------------------------------------------------
# fetch_internal_page_impl — exception during fetch is captured in result
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_captures_network_exception():
    import tools_impl

    class _BoomClient(_FakeAsyncClient):
        async def get(self, *a, **kw):
            raise RuntimeError("dns fail")

    client = _BoomClient()

    with patch.object(tools_impl.httpx, "AsyncClient", return_value=client):
        raw = await tools_impl.fetch_internal_page_impl("https://bad.invalid/")

    data = json.loads(raw)
    assert data.get("error") == "dns fail"


# ---------------------------------------------------------------------------
# fetch_internal_page_impl — crawler fallback populates crawled_apis
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fetch_internal_page_uses_ai_crawler_fallback():
    import tools_impl

    html = "<html><body><a href='/x'>x</a></body></html>"
    resp = _mock_response(status_code=200, text=html, url="https://example.com/")
    client = _FakeAsyncClient(default_response=resp)

    fake_apis = [{"method": "GET", "endpoint": "/api/users", "domain": "example.com", "status": 200}]

    async def _fake_to_thread(fn, *args, **kwargs):
        # _probe_openapi iterates candidate URLs; since they all raise in our
        # fake client, the crawler path will be taken.
        return fake_apis

    # Make _probe_openapi's candidate gets fail so we fall through to crawler.
    class _NoSpecClient(_FakeAsyncClient):
        _call = 0

        async def get(self, url, headers=None, timeout=None):
            self.requests.append({"url": url})
            # First call — the page fetch — returns the html response.
            if not self.requests[:-1]:
                return resp
            # Subsequent calls (from _probe_openapi) error out.
            raise RuntimeError("probe fail")

    nc = _NoSpecClient(default_response=resp)
    with patch.object(tools_impl.httpx, "AsyncClient", return_value=nc), \
         patch.object(tools_impl.asyncio, "to_thread", side_effect=_fake_to_thread):
        raw = await tools_impl.fetch_internal_page_impl("https://example.com/")

    data = json.loads(raw)
    assert data["crawled_apis"] == fake_apis
    assert "AI Crawler Discovered 1 APIs" in data["text"]


# ---------------------------------------------------------------------------
# _probe_openapi — discovers spec via common paths
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_probe_openapi_finds_spec_on_common_path():
    import tools_impl

    spec = {"openapi": "3.0.0"}
    target = "https://example.com/openapi.json"
    ok_resp = _mock_response(status_code=200, json_data=spec, url=target)
    bad_resp = _mock_response(status_code=404, url="https://example.com/whatever")

    class _SelectiveClient(_FakeAsyncClient):
        async def get(self, url, headers=None, timeout=None):
            self.requests.append({"url": url})
            if url == target:
                return ok_resp
            return bad_resp

    client = _SelectiveClient()
    found = await tools_impl._probe_openapi(client, "https://example.com/", [])
    assert found is not None
    assert found["url"] == target
    assert found["spec"] == spec


@pytest.mark.asyncio
async def test_probe_openapi_returns_none_when_nothing_matches():
    import tools_impl

    bad_resp = _mock_response(status_code=404, url="https://example.com/x")
    client = _FakeAsyncClient(default_response=bad_resp)

    found = await tools_impl._probe_openapi(client, "https://example.com/", [])
    assert found is None


@pytest.mark.asyncio
async def test_probe_openapi_includes_extracted_json_links_as_candidates():
    """Links ending in .json containing 'swagger' should be probed."""
    import tools_impl

    spec = {"swagger": "2.0"}
    target = "https://example.com/swagger-api-v1.json"
    ok_resp = _mock_response(status_code=200, json_data=spec, url=target)
    miss_resp = _mock_response(status_code=404, url="x")

    class _SelectiveClient(_FakeAsyncClient):
        async def get(self, url, headers=None, timeout=None):
            self.requests.append({"url": url})
            if url == target:
                return ok_resp
            return miss_resp

    client = _SelectiveClient()
    found = await tools_impl._probe_openapi(
        client,
        "https://example.com/",
        ["https://example.com/swagger-api-v1.json"],
    )
    assert found is not None
    assert found["url"] == target
