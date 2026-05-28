"""L3 tests for routers/trial.py — trial token create/validate/consume."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def trial_auth_client(client, admin_row):
    """Admin user is always allowed to create trial tokens."""
    from auth import get_current_user
    from models import UserResponse
    import server

    admin = UserResponse(**admin_row)
    server.app.dependency_overrides[get_current_user] = lambda: admin
    yield client, admin
    server.app.dependency_overrides.clear()


@pytest.fixture
def forbidden_user_client(client, user_row):
    """Ordinary user (not tester/w.lee) should be rejected by require_trial_create_permission."""
    from auth import get_current_user
    from models import UserResponse
    import server

    u = UserResponse(**user_row)  # username=alice, role=ORDINARY_USER
    server.app.dependency_overrides[get_current_user] = lambda: u
    yield client, u
    server.app.dependency_overrides.clear()


# ---------- /trial/create ----------


def test_create_trial_token_ok(trial_auth_client, mock_db):
    client, _ = trial_auth_client
    # count row returns 0 unconsumed tokens
    mock_db.fetch_one.return_value = {"cnt": 0}

    resp = client.post(
        "/api/v1/trial/create",
        json={"email": "tester@example.com", "target_url": "https://api.example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "token" in body
    assert body["trial_url"].startswith("http")
    assert "token=" in body["trial_url"]
    assert "trialUrl=" in body["trial_url"]


def test_create_trial_token_rate_limited_returns_429(trial_auth_client, mock_db):
    client, _ = trial_auth_client
    mock_db.fetch_one.return_value = {"cnt": 3}  # MAX_TOKENS_PER_EMAIL

    resp = client.post(
        "/api/v1/trial/create",
        json={"email": "spammy@example.com", "target_url": "https://api.example.com"},
    )
    assert resp.status_code == 429
    assert "active trial tokens" in resp.json()["detail"]


def test_create_trial_token_forbidden_for_ordinary_user(forbidden_user_client, mock_db):
    client, _ = forbidden_user_client

    resp = client.post(
        "/api/v1/trial/create",
        json={"email": "x@example.com", "target_url": "https://api.example.com"},
    )
    assert resp.status_code == 403
    assert "Permission denied" in resp.json()["detail"]


def test_create_trial_token_requires_auth(client):
    resp = client.post(
        "/api/v1/trial/create",
        json={"email": "x@example.com", "target_url": "https://api.example.com"},
    )
    assert resp.status_code == 401


# ---------- /trial/validate ----------


def test_validate_trial_token_not_found(client, mock_db):
    mock_db.fetch_one.return_value = None

    resp = client.post("/api/v1/trial/validate", json={"token": "nonexistent"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert body["reason"] == "not_found"


def test_validate_trial_token_consumed(client, mock_db):
    mock_db.fetch_one.return_value = {
        "token": "abc",
        "email": "e@example.com",
        "target_url": "https://api.example.com",
        "is_consumed": True,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
    }

    resp = client.post("/api/v1/trial/validate", json={"token": "abc"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert body["reason"] == "consumed"


def test_validate_trial_token_expired(client, mock_db):
    mock_db.fetch_one.return_value = {
        "token": "abc",
        "email": "e@example.com",
        "target_url": "https://api.example.com",
        "is_consumed": False,
        "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
    }

    resp = client.post("/api/v1/trial/validate", json={"token": "abc"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert body["reason"] == "expired"


def test_validate_trial_token_valid(client, mock_db):
    mock_db.fetch_one.return_value = {
        "token": "abc",
        "email": "e@example.com",
        "target_url": "https://api.example.com",
        "is_consumed": False,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
    }

    resp = client.post("/api/v1/trial/validate", json={"token": "abc"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["target_url"] == "https://api.example.com"
    assert body["email"] == "e@example.com"


# ---------- /trial/consume ----------


def test_consume_trial_token_not_found(client, mock_db):
    mock_db.fetch_one.return_value = None

    resp = client.post("/api/v1/trial/consume", json={"token": "nope"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is False
    assert body["reason"] == "not_found"


def test_consume_trial_token_ok(client, mock_db):
    mock_db.fetch_one.return_value = {
        "is_consumed": False,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
    }

    resp = client.post("/api/v1/trial/consume", json={"token": "goodtoken"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
