"""Tests for the run_web_ui_cloud planner tool.

These tests exercise the real wire format: the tool POSTs JSON to the
configured WEB_UI_TESTING_SERVICE_URL and parses NDJSON lines. The mock
substitutes httpx's transport so we still validate the URL, the payload
shape, and the line-format handling — the bug class that produced empty
streams in production was a pure wire-format mismatch unit-tests with a
stubbed _stream_from_cloud_service could never catch.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

import importlib

cloud_mod = importlib.import_module(
    "orchestrator.planner.tools.run_web_ui_cloud"
)
run_web_ui_cloud = cloud_mod.run_web_ui_cloud


class _Ctx:
    def __init__(self, state=None):
        self.invocation_id = "inv-1"
        self.session = type("S", (), {"state": state or {}})()


def _ndjson(events: list[dict]) -> bytes:
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


def _build_transport(captured: dict, ndjson: bytes, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content)
        return httpx.Response(status, content=ndjson)

    return httpx.MockTransport(handler)


@pytest.fixture
def _stub_persistence(monkeypatch):
    """Default-stub the api_service POST/PATCH so legacy tests that focus on
    the streaming wire format don't accidentally hit the persistence helpers.
    Tests that need to assert on POST/PATCH override these inside the test."""
    async def _noop_post(**_):
        return None

    async def _noop_patch(**_):
        return None

    monkeypatch.setattr(cloud_mod, "post_task", _noop_post)
    monkeypatch.setattr(cloud_mod, "patch_task", _noop_patch)


@pytest.mark.asyncio
async def test_payload_shape_and_url(_stub_persistence):
    """The tool must POST {session_state, invocation_id, user_id} to the
    configured service URL — RemoteAgent contract for /agent/run."""
    captured: dict = {}
    transport = _build_transport(captured, _ndjson([
        {"type": "result", "task_id": "t-1", "url": "https://x.com",
         "bug_counts": {"low": 1}}
    ]))

    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    ctx = _Ctx({"user_id": "u-1", "browser_model": "gpt-5.4-mini",
                "user_persona": "buyer"})

    with patch.dict("os.environ", {
        "WEB_UI_TESTING_SERVICE_URL": "http://web-ui:8002/agent/run"
    }, clear=False), patch("httpx.AsyncClient", side_effect=fake_client):
        events = [e async for e in run_web_ui_cloud(
            url="https://x.com", persona="buyer", ctx=ctx)]

    assert captured["url"] == "http://web-ui:8002/agent/run"
    body = captured["payload"]
    # RemoteAgent envelope keys
    assert body["invocation_id"] == "inv-1"
    assert body["user_id"] == "u-1"
    # Flat session_state fields the testing-web-ui-service /agent/run reads
    assert body["session_state"]["url"] == "https://x.com"
    assert body["session_state"]["user_persona"] == "buyer"
    assert body["session_state"]["llm_model"] == "gpt-5.4-mini"
    # Terminal frame is the last event with summary JSON
    assert events[-1]["is_terminal"] is True
    summary = json.loads(events[-1]["result"])
    assert summary["bugs_found"] == 1


@pytest.mark.asyncio
async def test_log_progress_artifact_result_translation(_stub_persistence):
    """NDJSON event types from testing-web-ui-service get re-shaped into
    the orchestrator's {log/web_ui_artifact/web_ui_bug} envelope so the
    existing SSE serializer + frontend dispatcher light up. Upstream
    `result` is retyped to `web_ui_bug` so the dispatcher renders a
    BugReportArtifact card instead of an empty ResultMessage."""
    captured: dict = {}
    transport = _build_transport(captured, _ndjson([
        {"type": "log", "content": "task started"},
        {"type": "progress", "content": "exploring", "steps_done": 3,
         "max_steps": 30},
        {"type": "artifact", "artifact_type": "web_ui_tests",
         "name": "test_x.py", "content": "def test(): pass",
         "task_id": "t-1"},
        {"type": "result", "task_id": "t-1", "url": "https://x.com",
         "bug_counts": {"high": 2, "low": 1},
         "steps_done": 30, "final_output": "done",
         "screenshot_urls": ["a.png", "b.png"]},
    ]))

    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    ctx = _Ctx({"user_id": "u-1"})

    with patch("httpx.AsyncClient", side_effect=fake_client):
        events = [e async for e in run_web_ui_cloud(
            url="https://x.com", ctx=ctx)]

    types = [(e.get("event_type"), e.get("payload", {}).get("type"))
             for e in events if not e.get("is_terminal")]
    assert ("log", "log") in types
    assert ("web_ui_artifact", "web_ui_artifact") in types
    assert ("web_ui_bug", "web_ui_bug") in types
    # Upstream `result` is retyped to `web_ui_bug` — never leaks the old type
    assert ("result", "result") not in types

    # web_ui_bug payload carries the fields BugReportArtifact reads
    bug = next(e["payload"] for e in events
               if e.get("event_type") == "web_ui_bug")
    assert bug["source"] == "cloud"
    assert bug["task_id"] == "t-1"
    assert bug["bug_counts"] == {"high": 2, "low": 1}
    assert bug["steps_done"] == 30
    assert bug["screenshot_urls"] == ["a.png", "b.png"]

    # Progress mapped to a log event, with steps prefix
    log_msgs = [e["payload"]["message"] for e in events
                if not e.get("is_terminal") and e["event_type"] == "log"]
    assert any("[3/30]" in m for m in log_msgs)
    assert "task started" in log_msgs

    # Artifact carries the source tag the dispatcher uses
    artifact = next(e["payload"] for e in events
                    if e.get("event_type") == "web_ui_artifact")
    assert artifact["source"] == "cloud"
    assert artifact["artifact_type"] == "web_ui_tests"
    assert artifact["content"] == "def test(): pass"

    # Result carries bug_counts → summary aggregation = 2 + 1
    summary = json.loads(events[-1]["result"])
    assert summary["bugs_found"] == 3
    assert summary["script_generated"] is True
    assert summary["task_id"] == "t-1"


@pytest.mark.asyncio
async def test_upstream_404_yields_error_event(_stub_persistence):
    """If the service returns non-200 (e.g. wrong path → 404), surface an
    error event instead of silently terminating with empty summary —
    that's the failure mode the original prod bug exhibited."""
    captured: dict = {}
    transport = _build_transport(captured, b"Not Found", status=404)

    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    ctx = _Ctx({"user_id": "u-1"})

    with patch("httpx.AsyncClient", side_effect=fake_client):
        events = [e async for e in run_web_ui_cloud(
            url="https://x.com", ctx=ctx)]

    error_events = [e for e in events
                    if not e.get("is_terminal") and e["event_type"] == "error"]
    assert error_events, "expected an error event when upstream returns 404"
    assert "404" in error_events[0]["payload"]["message"]
    summary = json.loads(events[-1]["result"])
    assert "error" in summary


@pytest.mark.asyncio
async def test_post_patch_lifecycle_and_url_injection(monkeypatch):
    """End-to-end persistence wiring: as soon as upstream surfaces task_id
    (in the artifact event), a POST /api/v1/web-ui-tasks creates the row.
    On the result event a PATCH uploads test_script + final_output and
    returns R2 URLs; those URLs MUST land on the web_ui_bug payload that
    the frontend BugReportArtifact card reads.

    Reason for this test: the prior wiring's failure mode was that
    web_ui_bug.tests_url and bug_report_url stayed null in production
    even when api_service had successfully uploaded to R2 — purely
    because the orchestrator wasn't reading the PATCH response."""
    # Force a deterministic api_base via the lazy import in _resolve_api_base.
    monkeypatch.setattr(cloud_mod, "_resolve_api_base", lambda: "http://api.test")

    posts: list[dict] = []
    patches: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/agent/run"):
            return httpx.Response(200, content=_ndjson([
                {"type": "log", "content": "starting"},
                {"type": "artifact", "artifact_type": "web_ui_tests",
                 "name": "test_x.py", "content": "def test(): pass",
                 "task_id": "t-77"},
                {"type": "result", "task_id": "t-77",
                 "url": "https://target.example",
                 "bug_counts": {"critical": 1, "high": 0, "medium": 0, "low": 2},
                 "steps_done": 12,
                 "bugs": [
                     {"severity": "critical", "title": "Login button missing"},
                     {"severity": "low", "title": "Tooltip cut off"},
                 ]},
            ]))
        if path == "/api/v1/web-ui-tasks" and request.method == "POST":
            posts.append({
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": json.loads(request.content),
            })
            return httpx.Response(201, json={"id": "t-77", "status": "running"})
        if path.startswith("/api/v1/web-ui-tasks/") and request.method == "PATCH":
            patches.append({
                "url": str(request.url),
                "body": json.loads(request.content),
            })
            return httpx.Response(200, json={
                "id": "t-77",
                "status": "completed",
                "tests_url": "https://r2.example/web-ui/u-9/t-77/test_script.py",
                "bug_report_url": "https://r2.example/web-ui/u-9/t-77/bug_report.txt",
            })
        return httpx.Response(404, text=f"unmatched {request.method} {path}")

    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    ctx = _Ctx({"user_id": "u-9", "auth_token": "Bearer xyz"})

    with patch("httpx.AsyncClient", side_effect=fake_client):
        events = [e async for e in run_web_ui_cloud(
            url="https://target.example", persona="buyer", ctx=ctx)]

    # POST happened lazily on first task_id (the artifact event in this stream)
    assert len(posts) == 1
    post = posts[0]
    assert post["url"] == "http://api.test/api/v1/web-ui-tasks"
    assert post["body"]["id"] == "t-77"
    assert post["body"]["target_url"] == "https://target.example"
    assert post["body"]["status"] == "running"
    assert post["body"]["user_persona"] == "buyer"
    # Auth header preserved verbatim — Bearer prefix already present
    assert post["headers"].get("authorization") == "Bearer xyz"

    # PATCH carried test_script (so api_service uploads to R2) and final_output
    # (the flattened bug report)
    assert len(patches) == 1
    pbody = patches[0]["body"]
    assert patches[0]["url"] == "http://api.test/api/v1/web-ui-tasks/t-77"
    assert pbody["status"] == "completed"
    assert pbody["test_script"] == "def test(): pass"
    assert pbody["bug_counts"] == {"critical": 1, "high": 0, "medium": 0, "low": 2}
    assert pbody["steps_done"] == 12
    assert "Login button missing" in pbody["final_output"]
    assert "Tooltip cut off" in pbody["final_output"]

    # The crux: web_ui_bug payload carries the URLs returned by PATCH
    bug = next(e["payload"] for e in events
               if e.get("event_type") == "web_ui_bug")
    assert bug["tests_url"] == "https://r2.example/web-ui/u-9/t-77/test_script.py"
    assert bug["bug_report_url"] == "https://r2.example/web-ui/u-9/t-77/bug_report.txt"
    assert bug["has_tests"] is True


@pytest.mark.asyncio
async def test_patch_failure_leaves_urls_null_but_still_emits_bug(monkeypatch):
    """If api_service PATCH returns 5xx (R2 upload broken, DB locked, etc.),
    the runner must still emit web_ui_bug — just with null URL fields.
    Mirrors the same degradation guarantee in client_web_ui_runner."""
    monkeypatch.setattr(cloud_mod, "_resolve_api_base", lambda: "http://api.test")

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/agent/run"):
            return httpx.Response(200, content=_ndjson([
                {"type": "result", "task_id": "t-bad",
                 "url": "https://target.example",
                 "bug_counts": {"low": 1}, "steps_done": 1},
            ]))
        if path == "/api/v1/web-ui-tasks":
            return httpx.Response(201, json={"id": "t-bad"})
        if path.startswith("/api/v1/web-ui-tasks/"):
            return httpx.Response(503, text="r2 unavailable")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    ctx = _Ctx({"user_id": "u-9"})

    with patch("httpx.AsyncClient", side_effect=fake_client):
        events = [e async for e in run_web_ui_cloud(
            url="https://target.example", ctx=ctx)]

    bug = next(e["payload"] for e in events
               if e.get("event_type") == "web_ui_bug")
    # Original upstream values preserved (None) — no crash, no fabricated URL
    assert bug.get("tests_url") in (None, "")
    assert bug.get("bug_report_url") in (None, "")
