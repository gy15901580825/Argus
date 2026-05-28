"""Tests for /api/v1/redteam/runs endpoints."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from fastapi.testclient import TestClient

from server import app
from auth import get_current_user
from models import UserResponse, UserRole


@pytest.fixture
def fake_user_id():
    return uuid4()


@pytest.fixture
def authenticated_client(fake_user_id, mock_db):
    def _fake_user():
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        return UserResponse(
            id=fake_user_id, username="t", email="t@x.com",
            display_name="T", role=UserRole.ORDINARY_USER, is_active=True,
            created_at=now, updated_at=now,
        )
    app.dependency_overrides[get_current_user] = _fake_user
    yield TestClient(app)
    app.dependency_overrides.pop(get_current_user, None)


async def _empty_async_stream(*args, **kwargs):
    """Replacement for `orchestrator_client.stream_findings` — an empty async generator."""
    return
    yield  # unreachable; presence makes this an async generator function


async def _noop_create_run(*args, **kwargs):
    """Replacement for `orchestrator_client.create_run` — succeeds silently."""
    return


def test_post_redteam_run_creates_run_row(authenticated_client, mock_db):
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
            "api_key": "sk-test",
        },
        "probe_ids": ["owasp_01_prompt_injection_basic"],
    }
    run_uuid = uuid4()
    mock_db.fetch_one.return_value = {"id": run_uuid}

    with patch("redteam.orchestrator_client.create_run", _noop_create_run), \
         patch("redteam.orchestrator_client.stream_findings", _empty_async_stream):
        resp = authenticated_client.post("/api/v1/redteam/runs", json=body)
    assert resp.status_code in (200, 202)
    data = resp.json()
    assert "run_id" in data


def test_get_redteam_run_returns_status(authenticated_client, mock_db, fake_user_id):
    body = {
        "target": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "gpt-4", "api_key": "k"},
        "probe_ids": ["p1"],
    }
    run_uuid = uuid4()
    mock_db.fetch_one.side_effect = [
        {"id": run_uuid},  # create_run INSERT … RETURNING id
        {"id": run_uuid, "user_id": fake_user_id, "status": "running"},  # get_run SELECT
    ]

    with patch("redteam.orchestrator_client.create_run", _noop_create_run), \
         patch("redteam.orchestrator_client.stream_findings", _empty_async_stream):
        run_resp = authenticated_client.post("/api/v1/redteam/runs", json=body)
    run_id = run_resp.json()["run_id"]

    resp = authenticated_client.get(f"/api/v1/redteam/runs/{run_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == run_id
    assert "status" in data
    assert "findings" in data


@pytest.mark.asyncio
async def test_stream_findings_raises_on_error_event():
    """Orchestrator emits `event: error\\ndata: {...}` -> client raises OrchestratorError carrying the payload."""
    from redteam.orchestrator_client import OrchestratorError, stream_findings

    async def _aiter_lines():
        for line in [
            "event: error",
            'data: {"detail": "boom", "type": "RuntimeError"}',
            "",
        ]:
            yield line

    fake_resp = AsyncMock()
    fake_resp.raise_for_status = lambda: None
    fake_resp.aiter_lines = _aiter_lines

    fake_stream_cm = AsyncMock()
    fake_stream_cm.__aenter__ = AsyncMock(return_value=fake_resp)
    fake_stream_cm.__aexit__ = AsyncMock(return_value=None)

    fake_client = AsyncMock()
    fake_client.stream = lambda *args, **kwargs: fake_stream_cm
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=None)

    with patch("redteam.orchestrator_client.httpx.AsyncClient", return_value=fake_client):
        with pytest.raises(OrchestratorError, match="boom"):
            async for _ in stream_findings({"endpoint_url": "x", "model": "y"}, ["any"]):
                pass


def test_get_redteam_report_html(authenticated_client, mock_db, fake_user_id):
    body = {"target": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y"}, "probe_ids": ["p1"]}
    run_uuid = uuid4()
    mock_db.fetch_one.side_effect = [
        {"id": run_uuid},
        {"id": run_uuid, "user_id": fake_user_id, "status": "completed"},
    ]
    mock_db.fetch_all.return_value = [{
        "id": uuid4(), "probe_id": "p1", "verdict": "pass", "severity": "info",
        "confidence": 0.9, "attack_prompt": "x", "target_response": "y", "reasoning": "ok",
        "judge_model": "haiku", "escalated_model": None, "target_latency_ms": 100.0,
        "probed_at": None, "atlas_id": ["A1"], "owasp_id": ["LLM01"],
        "nist_id": ["MAP-2.3"], "eu_ai_act_id": [],
    }]
    async def _empty(*a, **k):
        return
        yield
    with patch("redteam.orchestrator_client.create_run", _noop_create_run), \
         patch("redteam.orchestrator_client.stream_findings", _empty):
        run_resp = authenticated_client.post("/api/v1/redteam/runs", json=body)
    rid = run_resp.json()["run_id"]

    resp = authenticated_client.get(f"/api/v1/redteam/runs/{rid}/report?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Argus" in resp.text


def test_get_redteam_report_sarif(authenticated_client, mock_db, fake_user_id):
    body = {"target": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y"}, "probe_ids": ["p1"]}
    run_uuid = uuid4()
    mock_db.fetch_one.side_effect = [
        {"id": run_uuid},
        {"id": run_uuid, "user_id": fake_user_id, "status": "completed"},
    ]
    mock_db.fetch_all.return_value = []
    async def _empty(*a, **k):
        return
        yield
    with patch("redteam.orchestrator_client.create_run", _noop_create_run), \
         patch("redteam.orchestrator_client.stream_findings", _empty):
        run_resp = authenticated_client.post("/api/v1/redteam/runs", json=body)
    rid = run_resp.json()["run_id"]

    resp = authenticated_client.get(f"/api/v1/redteam/runs/{rid}/report?format=sarif")
    assert resp.status_code == 200
    assert "application/sarif+json" in resp.headers["content-type"] or "application/json" in resp.headers["content-type"]
    import json
    obj = json.loads(resp.text)
    assert obj["version"] == "2.1.0"


def test_get_redteam_report_unknown_format_400(authenticated_client, mock_db, fake_user_id):
    run_uuid = uuid4()
    mock_db.fetch_one.return_value = {"id": run_uuid, "user_id": fake_user_id, "status": "completed"}
    mock_db.fetch_all.return_value = []
    resp = authenticated_client.get(f"/api/v1/redteam/runs/{run_uuid}/report?format=pdf")
    assert resp.status_code in (400, 422)


def test_get_redteam_probes_proxies_orchestrator(authenticated_client, mock_db):
    fake_probes = {"probe_ids": ["owasp_01", "garak_dan_dan_6_0", "browser_dom_inject_basic"]}
    fake_resp = MagicMock()
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json = lambda: fake_probes
    fake_client = AsyncMock()
    fake_client.get = AsyncMock(return_value=fake_resp)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=None)
    with patch("redteam.routes._httpx.AsyncClient", return_value=fake_client):
        resp = authenticated_client.get("/api/v1/redteam/probes")
    assert resp.status_code == 200
    assert resp.json() == fake_probes


@pytest.mark.parametrize("kind,minimal_spec", [
    ("openai_compat", {"endpoint_url": "https://x", "model": "y", "api_key": "k"}),
    ("anthropic_native", {"model": "claude-haiku-4-5-20251001", "api_key": "k"}),
    ("custom_http", {"request_url": "https://x", "request_body_template": "{}", "response_jsonpath": "$.x"}),
    ("grpc", {"endpoint": "host:50051", "service_method": "p.S/M"}),
    ("browser_use", {"agent_url": "https://x", "scenario_kind": "dom_injection"}),
])
def test_redteam_run_accepts_5_target_kinds(authenticated_client, mock_db, fake_user_id, kind, minimal_spec):
    body = {"target": {"kind": kind, **minimal_spec}, "probe_ids": ["owasp_07_system_prompt_leakage"]}
    mock_db.fetch_one.return_value = {"id": uuid4()}
    with patch("redteam.orchestrator_client.create_run", _noop_create_run), \
         patch("redteam.orchestrator_client.stream_findings", _empty_async_stream):
        response = authenticated_client.post("/api/v1/redteam/runs", json=body)
    assert response.status_code == 200, f"kind={kind} body={body!r}: {response.status_code} {response.text}"


def test_redteam_run_rejects_unknown_kind_with_422(authenticated_client):
    body = {"target": {"kind": "telepathy", "endpoint_url": "x"}, "probe_ids": ["p1"]}
    response = authenticated_client.post("/api/v1/redteam/runs", json=body)
    assert response.status_code == 422


def test_redteam_run_returns_402_when_orchestrator_rejects_for_cost(authenticated_client, mock_db):
    """Orchestrator 402 (cost cap) propagates to the client as 402."""
    import httpx
    body = {
        "target": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y", "api_key": "k"},
        "probe_ids": ["owasp_07_system_prompt_leakage"],
    }
    fake_request = httpx.Request("POST", "http://orchestrator/redteam/run")
    fake_response = httpx.Response(
        status_code=402,
        json={"detail": "estimated $1.50 > per_run_cap $0.50"},
        request=fake_request,
    )
    with patch(
        "redteam.orchestrator_client.create_run",
        new=AsyncMock(side_effect=httpx.HTTPStatusError("402", request=fake_request, response=fake_response)),
    ):
        response = authenticated_client.post("/api/v1/redteam/runs", json=body)
    assert response.status_code == 402
    assert "estimated" in response.text or "cost" in response.text.lower()
