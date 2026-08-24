"""L3 tests for client_agent.fetch_url_impl and _probe_openapi.

We mock httpx.AsyncClient at the module boundary so no real HTTP calls go out.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


def _make_response(
    *,
    status_code: int = 200,
    text: str = "",
    json_body=None,
    url: str = "http://example.invalid/",
):
    """Build a mock httpx.Response-like object that fetch_url_impl uses."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = url
    resp.headers = {}
    if json_body is not None:
        resp.json = MagicMock(return_value=json_body)
    else:
        # .json() raises JSONDecodeError when body isn't JSON
        resp.json = MagicMock(side_effect=json.JSONDecodeError("x", "x", 0))
    return resp


class _FakeAsyncClient:
    """Minimal async context manager mimicking httpx.AsyncClient."""

    def __init__(self, get_responses):
        # get_responses is a dict url -> Response OR a callable(url)->Response
        self._get_responses = get_responses
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {}})
        if callable(self._get_responses):
            return self._get_responses(url)
        if url in self._get_responses:
            return self._get_responses[url]
        # default 404
        return _make_response(status_code=404, url=url)


# ---------------------------------------------------------------------------
# fetch_url_impl
# ---------------------------------------------------------------------------

def test_fetch_url_impl_extracts_title_links_scripts_and_text():
    import client_agent

    html = """
    <html><head><title>My Test Page</title></head>
    <body>
      <a href="/about">About</a>
      <a href="https://other.invalid/external">Ext</a>
      <script src="/js/app.js"></script>
      <p>Hello  World</p>
      <style>.c{color:red}</style>
    </body></html>
    """
    fake = _FakeAsyncClient({
        "http://site.invalid/": _make_response(
            text=html,
            url="http://site.invalid/",
        ),
    })

    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        out = asyncio.run(client_agent.fetch_url_impl("http://site.invalid/"))

    parsed = json.loads(out)
    assert parsed["metadata"]["title"] == "My Test Page"
    assert parsed["metadata"]["status_code"] == 200
    assert "http://site.invalid/about" in parsed["links"]
    assert "https://other.invalid/external" in parsed["links"]
    assert "http://site.invalid/js/app.js" in parsed["scripts"]
    # Text should contain Hello World but no <script> / <style> content
    assert "Hello" in parsed["text"]
    assert "World" in parsed["text"]
    assert "color:red" not in parsed["text"]
    assert parsed["api_spec"] is None


def test_fetch_url_impl_returns_early_on_http_error_status():
    import client_agent

    fake = _FakeAsyncClient({
        "http://site.invalid/broken": _make_response(
            status_code=500,
            text="kaboom",
            url="http://site.invalid/broken",
        ),
    })
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        out = asyncio.run(client_agent.fetch_url_impl("http://site.invalid/broken"))

    parsed = json.loads(out)
    assert parsed["metadata"]["status_code"] == 500
    # No links/scripts/text were parsed (early return)
    assert parsed["links"] == []
    assert parsed["scripts"] == []
    assert parsed["text"] == ""


def test_fetch_url_impl_recognizes_openapi_spec_body():
    import client_agent

    spec_body = {"openapi": "3.0.0", "info": {"title": "x", "version": "1"}}
    # Response is still text-y HTML-free JSON; json_body makes .json() succeed.
    fake = _FakeAsyncClient({
        "http://api.invalid/openapi.json": _make_response(
            text=json.dumps(spec_body),
            json_body=spec_body,
            url="http://api.invalid/openapi.json",
        ),
    })
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        out = asyncio.run(client_agent.fetch_url_impl("http://api.invalid/openapi.json"))

    parsed = json.loads(out)
    assert parsed["api_spec"] is not None
    assert parsed["api_spec"]["spec"]["openapi"] == "3.0.0"
    assert parsed["text"] == "Fetched content is a JSON API Specification."


def test_fetch_url_impl_includes_cookie_and_bearer_headers():
    import client_agent

    captured_calls = []

    response = _make_response(
        text="<html><body></body></html>",
        url="http://site.invalid/",
    )

    class _CapturingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None, timeout=None):
            captured_calls.append({"url": url, "headers": dict(headers or {})})
            # First call (the target URL) gets HTML response; all probe
            # follow-ups return 404.
            if url == "http://site.invalid/":
                return response
            return _make_response(status_code=404, url=url)

    fake = _CapturingClient()
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        asyncio.run(
            client_agent.fetch_url_impl(
                "http://site.invalid/",
                cookie="sid=abc",
                token="my-jwt",
            )
        )

    # The first call — for the target URL — carries the auth headers.
    first = captured_calls[0]
    assert first["url"] == "http://site.invalid/"
    h = first["headers"]
    assert h["Cookie"] == "sid=abc"
    assert h["Authorization"] == "Bearer my-jwt"
    assert h["User-Agent"].startswith("Argus-Client-Agent/")


def test_fetch_url_impl_reports_exception_in_error_field():
    import client_agent

    class _BoomClient(_FakeAsyncClient):
        async def get(self, url, headers=None, timeout=None):
            raise httpx.ConnectError("no route")

    with patch("client_agent.httpx.AsyncClient", return_value=_BoomClient({})):
        out = asyncio.run(client_agent.fetch_url_impl("http://nope.invalid/"))

    parsed = json.loads(out)
    assert "error" in parsed
    assert "no route" in parsed["error"]


# ---------------------------------------------------------------------------
# _probe_openapi
# ---------------------------------------------------------------------------

def test_probe_openapi_returns_first_valid_spec():
    import client_agent

    spec = {"swagger": "2.0"}
    extracted_links = [
        "http://api.invalid/no_match.html",
        "http://api.invalid/docs/api.json",   # candidate (has 'api' + .json)
    ]

    responses = {
        "http://api.invalid/docs/api.json": _make_response(
            text=json.dumps(spec), json_body=spec, url="http://api.invalid/docs/api.json",
        ),
    }

    def _responder(url):
        return responses.get(url, _make_response(status_code=404, url=url))

    fake = _FakeAsyncClient(_responder)

    async def _driver():
        async with fake as client:
            return await client_agent._probe_openapi(
                client, "http://api.invalid/", extracted_links
            )

    result = asyncio.run(_driver())
    assert result is not None
    assert result["url"] == "http://api.invalid/docs/api.json"
    assert result["spec"]["swagger"] == "2.0"


def test_probe_openapi_returns_none_when_no_candidate_succeeds():
    import client_agent

    def _all_404(url):
        return _make_response(status_code=404, url=url)

    fake = _FakeAsyncClient(_all_404)

    async def _driver():
        async with fake as client:
            return await client_agent._probe_openapi(client, "http://api.invalid/", [])

    assert asyncio.run(_driver()) is None
