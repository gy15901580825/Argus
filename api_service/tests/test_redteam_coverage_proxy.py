"""Tests for the api_service /redteam/coverage proxy."""

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


def test_get_redteam_coverage_proxies_orchestrator(authenticated_client, mock_db):
    fake_coverage = {"coverage": {"standards": {"owasp-llm-top10": {"cells": []}}, "totals": {"probes_run": 0}}}
    fake_resp = MagicMock()
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json = lambda: fake_coverage
    fake_client = AsyncMock()
    fake_client.get = AsyncMock(return_value=fake_resp)
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=None)
    with patch("redteam.routes._httpx.AsyncClient", return_value=fake_client):
        resp = authenticated_client.get("/api/v1/redteam/coverage")
    assert resp.status_code == 200
    assert resp.json() == fake_coverage


def test_get_redteam_coverage_requires_auth(mock_db):
    client = TestClient(app)
    resp = client.get("/api/v1/redteam/coverage")
    assert resp.status_code in (401, 403)
