"""Tests for orchestrator/utils/web_ui_task_api.py.

Uses httpx.MockTransport so we exercise real client behavior — header
shaping, URL construction, JSON parsing, error swallowing — instead of
patching httpx itself.
"""
from __future__ import annotations

import json

import httpx
import pytest

from orchestrator.utils import web_ui_task_api as api_mod


def _make_client_with_handler(handler):
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    return fake_client


@pytest.mark.asyncio
async def test_post_task_returns_response_json_on_201(monkeypatch):
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["method"] = req.method
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.content)
        return httpx.Response(201, json={"id": "tid", "status": "running"})

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    result = await api_mod.post_task(
        api_base="http://api.local",
        auth_token="Bearer abc",
        user_id="u-1",
        body={"id": "tid", "target_url": "https://x", "status": "running"},
    )

    assert result == {"id": "tid", "status": "running"}
    assert captured["method"] == "POST"
    assert captured["url"] == "http://api.local/api/v1/web-ui-tasks"
    # Already has Bearer prefix → preserved verbatim, no double-prefix
    assert captured["headers"]["authorization"] == "Bearer abc"
    assert captured["body"]["id"] == "tid"


@pytest.mark.asyncio
async def test_post_task_falls_back_to_internal_headers_when_no_auth(monkeypatch):
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(req.headers)
        return httpx.Response(201, json={"id": "tid"})

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    await api_mod.post_task(
        api_base="http://api.local",
        auth_token=None,
        user_id="u-2",
        body={"id": "tid"},
    )
    assert captured["headers"]["x-internal-call"] == "true"
    assert captured["headers"]["x-user-id"] == "u-2"
    assert "authorization" not in captured["headers"]


@pytest.mark.asyncio
async def test_post_task_returns_none_on_4xx(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    result = await api_mod.post_task(
        api_base="http://api.local", auth_token="t", user_id="u", body={},
    )
    assert result is None


@pytest.mark.asyncio
async def test_post_task_returns_none_on_transport_error(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nope")

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    result = await api_mod.post_task(
        api_base="http://api.local", auth_token="t", user_id="u", body={},
    )
    assert result is None


@pytest.mark.asyncio
async def test_patch_task_returns_response_with_r2_urls(monkeypatch):
    """The api_service PATCH uploads test_script + final_output to R2 and
    returns tests_url / bug_report_url in the response — patch_task must
    surface that JSON body intact so callers can backfill the SSE payload."""
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["method"] = req.method
        captured["body"] = json.loads(req.content)
        return httpx.Response(200, json={
            "id": "tid", "status": "completed",
            "tests_url": "https://r2/test_script.py",
            "bug_report_url": "https://r2/bug_report.txt",
        })

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    result = await api_mod.patch_task(
        api_base="http://api.local",
        task_id="tid",
        auth_token="Bearer xyz",
        user_id="u-1",
        body={"status": "completed", "test_script": "code",
              "final_output": "txt"},
    )

    assert result is not None
    assert result["tests_url"] == "https://r2/test_script.py"
    assert result["bug_report_url"] == "https://r2/bug_report.txt"
    assert captured["method"] == "PATCH"
    assert captured["url"] == "http://api.local/api/v1/web-ui-tasks/tid"


@pytest.mark.asyncio
async def test_patch_task_returns_none_on_failure(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    result = await api_mod.patch_task(
        api_base="http://api.local", task_id="missing",
        auth_token="t", user_id="u", body={"status": "completed"},
    )
    assert result is None


@pytest.mark.asyncio
async def test_patch_task_normalizes_non_bearer_token(monkeypatch):
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(req.headers)
        return httpx.Response(200, json={"id": "tid"})

    monkeypatch.setattr(api_mod.httpx, "AsyncClient",
                        _make_client_with_handler(handler))

    await api_mod.patch_task(
        api_base="http://api.local", task_id="tid",
        auth_token="rawtoken",  # missing Bearer prefix
        user_id="u", body={"status": "completed"},
    )
    assert captured["headers"]["authorization"] == "Bearer rawtoken"
