"""Tests for /legacy-export endpoints (60-day sunset surface)."""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from uuid import uuid4

from server import app
from auth import get_current_user
from models import UserResponse, UserRole

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def fake_user_id():
    return uuid4()


@pytest.fixture
def authenticated_client(fake_user_id, mock_db):
    """TestClient with get_current_user dependency overridden to return a fake user."""
    fake_id = fake_user_id

    def _fake_user():
        return UserResponse(
            id=fake_id,
            username="testuser",
            email="test@example.com",
            display_name="Test User",
            role=UserRole.ORDINARY_USER,
            is_active=True,
            created_at=_NOW,
            updated_at=_NOW,
        )

    app.dependency_overrides[get_current_user] = _fake_user
    yield TestClient(app)
    app.dependency_overrides.pop(get_current_user, None)


def test_legacy_export_manifest_returns_table_list(authenticated_client):
    resp = authenticated_client.get("/legacy-export/manifest")
    assert resp.status_code == 200
    body = resp.json()
    assert "tables" in body
    assert "scripts" in body["tables"]
    assert "web_ui_tasks" in body["tables"]
    assert "available_until" in body


def test_legacy_export_dump_returns_user_scoped_data(authenticated_client, fake_user_id):
    resp = authenticated_client.get("/legacy-export/dump")
    assert resp.status_code == 200
    body = resp.json()
    assert "scripts" in body
    assert "web_ui_tasks" in body
    # Both lists should be empty for a fake user with no real data
    assert isinstance(body["scripts"], list)
    assert isinstance(body["web_ui_tasks"], list)


def test_legacy_export_requires_auth():
    """Without auth override, the endpoint must reject requests."""
    client = TestClient(app)
    resp = client.get("/legacy-export/manifest")
    # Either 401 or 403 acceptable depending on auth middleware
    assert resp.status_code in (401, 403)
