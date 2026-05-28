"""L3 tests for routers/profile.py — GET/PATCH /api/v1/profile."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest


@pytest.fixture
def auth_client(client, user_row):
    """TestClient with get_current_user overridden to return user_row."""
    from auth import get_current_user
    from models import UserResponse
    import server

    user = UserResponse(**user_row)
    server.app.dependency_overrides[get_current_user] = lambda: user
    yield client, user
    server.app.dependency_overrides.clear()


def _user_db_row(user_id: UUID, **overrides):
    base = {
        "id": user_id,
        "username": "alice",
        "email": "alice@example.com",
        "display_name": "Alice",
        "avatar": None,
        "role": "ORDINARY_USER",
        "is_active": True,
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime(2024, 1, 2, tzinfo=timezone.utc),
    }
    base.update(overrides)
    return base


def test_get_profile_ok(auth_client):
    client, user = auth_client

    resp = client.get("/api/v1/profile")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == str(user.id)
    assert body["username"] == user.username
    assert body["email"] == user.email
    assert body["role"] == user.role.value


def test_get_profile_requires_auth(client):
    resp = client.get("/api/v1/profile")
    assert resp.status_code == 401


def test_update_profile_no_fields_returns_400(auth_client):
    client, _ = auth_client

    resp = client.patch("/api/v1/profile", json={})
    assert resp.status_code == 400
    assert "No fields" in resp.json()["detail"]


def test_update_profile_empty_username_returns_400(auth_client):
    client, _ = auth_client

    resp = client.patch("/api/v1/profile", json={"username": "   "})
    assert resp.status_code == 400
    assert "Username" in resp.json()["detail"]


def test_update_profile_empty_email_returns_400(auth_client):
    client, _ = auth_client

    resp = client.patch("/api/v1/profile", json={"email": ""})
    assert resp.status_code == 400
    assert "Email" in resp.json()["detail"]


def test_update_profile_username_taken_returns_409(auth_client, mock_db):
    client, user = auth_client
    # First fetch_one returns an existing user with that username (taken)
    mock_db.fetch_one.return_value = {"id": UUID("99999999-9999-9999-9999-999999999999")}

    resp = client.patch("/api/v1/profile", json={"username": "bob"})
    assert resp.status_code == 409
    assert "Username" in resp.json()["detail"]


def test_update_profile_ok(auth_client, mock_db):
    client, user = auth_client
    # First fetch_one = uniqueness check (None = no conflict)
    # Second fetch_one = UPDATE RETURNING row
    updated_row = _user_db_row(user.id, display_name="Alice Updated")
    mock_db.fetch_one.side_effect = [None, updated_row]

    resp = client.patch(
        "/api/v1/profile",
        json={"username": "alice", "display_name": "Alice Updated"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["display_name"] == "Alice Updated"
    assert body["username"] == "alice"


def test_update_profile_user_not_found_returns_404(auth_client, mock_db):
    client, _ = auth_client
    # No uniqueness check (only updating display_name), so only 1 fetch_one = UPDATE RETURNING
    mock_db.fetch_one.return_value = None

    resp = client.patch("/api/v1/profile", json={"display_name": "New Name"})
    assert resp.status_code == 404


# ─── Synthetic email rejection + audit log ───────────────────────────────


def test_update_profile_rejects_synthetic_onmicrosoft_email(auth_client):
    """The whole point of self-service email change is to escape the
    @yourtenant.onmicrosoft.com fallback. Setting another synthetic value
    must be blocked at the API."""
    client, _ = auth_client
    resp = client.patch(
        "/api/v1/profile",
        json={"email": "fake-uuid@yourtenant.onmicrosoft.com"},
    )
    assert resp.status_code == 400
    assert "auto-generated" in resp.json()["detail"]


def test_update_profile_rejects_synthetic_local_email(auth_client):
    client, _ = auth_client
    resp = client.patch("/api/v1/profile", json={"email": "x@argus.local"})
    assert resp.status_code == 400


def test_update_profile_rejects_malformed_email(auth_client):
    client, _ = auth_client
    resp = client.patch("/api/v1/profile", json={"email": "not-an-email"})
    assert resp.status_code == 400
    assert "Invalid email format" in resp.json()["detail"]


def test_update_profile_accepts_real_email_and_audits(auth_client, mock_db, monkeypatch):
    """Real-email update succeeds, and an audit log row is written with
    from/to metadata."""
    client, user = auth_client
    updated_row = _user_db_row(user.id, email="real@acme.com")
    mock_db.fetch_one.side_effect = [None, updated_row]

    captured = []
    from redteam import audit as audit_module

    async def fake_log_audit(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(audit_module, "log_audit", fake_log_audit)
    # Profile imports log_audit by name, so patch the bound reference too:
    from routers import profile as profile_module
    monkeypatch.setattr(profile_module, "log_audit", fake_log_audit)

    resp = client.patch("/api/v1/profile", json={"email": "real@acme.com"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "real@acme.com"
    assert len(captured) == 1
    assert captured[0]["action"] == "email_changed"
    assert captured[0]["metadata"]["to_email"] == "real@acme.com"
