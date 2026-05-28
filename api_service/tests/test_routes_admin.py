"""Tests for /admin endpoints — token reveal/rotate + per-user run listing.

The flow we're covering: an Argus admin issues a token for a new
design-partner customer, later reveals it (or rotates it on compromise),
and inspects the customer's red-team run history to see if they're
actually using the product.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest


_CUSTOMER_ID = "33333333-3333-3333-3333-333333333333"


def _override_admin(client, admin_row):
    """Force /admin endpoints to authenticate as the admin fixture."""
    from auth import require_admin
    from models import UserResponse
    client.app.dependency_overrides[require_admin] = lambda: UserResponse(**admin_row)


def _override_ordinary(client, user_row):
    from auth import require_admin
    from models import UserResponse
    from fastapi import HTTPException

    def reject() -> UserResponse:
        raise HTTPException(status_code=403, detail="forbidden")

    client.app.dependency_overrides[require_admin] = reject


# ─── api-token-only user creation ──────────────────────────────────────────


def test_create_api_token_only_user_returns_token_and_skips_ciam(client, admin_row, mock_db):
    """api_token_only=True must mint a token, return it once, and NOT call CIAM."""
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = None  # no duplicate username/email
    mock_db.execute.return_value = None

    with patch("routers.admin.create_ciam_user", new_callable=AsyncMock) as ciam:
        resp = client.post("/api/v1/admin/users", json={
            "username": "acme",
            "email": "ops@acme.example",
            "display_name": "ACME design partner",
            "role": "ORDINARY_USER",
            "api_token_only": True,
        })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "api_token" in body and len(body["api_token"]) >= 32
    assert "api-token-only" in body["message"]
    assert ciam.await_count == 0, "CIAM must not be called in api_token_only mode"


# ─── reveal token ──────────────────────────────────────────────────────────


def test_reveal_token_returns_token_for_existing_user(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = {
        "id": UUID(_CUSTOMER_ID),
        "email": "ops@acme.example",
        "api_token": "tok-abcdef-1234567890",
    }
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/api-token")
    assert resp.status_code == 200
    body = resp.json()
    assert body["api_token"] == "tok-abcdef-1234567890"
    assert body["email"] == "ops@acme.example"


def test_reveal_token_404_when_user_missing(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = None
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/api-token")
    assert resp.status_code == 404


def test_reveal_token_409_when_user_has_no_token(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = {
        "id": UUID(_CUSTOMER_ID),
        "email": "x@y",
        "api_token": None,
    }
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/api-token")
    assert resp.status_code == 409


def test_reveal_token_rejects_non_admin(client, user_row, mock_db):
    _override_ordinary(client, user_row)
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/api-token")
    assert resp.status_code == 403


# ─── rotate token ──────────────────────────────────────────────────────────


def test_rotate_token_returns_fresh_token_and_writes_db(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = {
        "id": UUID(_CUSTOMER_ID),
        "email": "ops@acme.example",
    }
    resp = client.post(f"/api/v1/admin/users/{_CUSTOMER_ID}/rotate-token")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["api_token"]) >= 32
    # Verify the UPDATE was issued with the same token returned to the caller
    # (catches a regression where rotate would return a different value than
    # what got stored).
    update_calls = [c for c in mock_db.execute.await_args_list
                    if "UPDATE users SET api_token" in c.args[0]]
    assert len(update_calls) == 1
    assert update_calls[0].args[1]["t"] == body["api_token"]


def test_rotate_token_404_when_user_missing(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = None
    resp = client.post(f"/api/v1/admin/users/{_CUSTOMER_ID}/rotate-token")
    assert resp.status_code == 404


# ─── list user's redteam runs ──────────────────────────────────────────────


def test_list_user_runs_returns_summary_with_counts(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    # First fetch_one = user lookup; then fetch_all for runs; then fetch_one for total
    user_lookup = {"id": UUID(_CUSTOMER_ID), "email": "ops@acme.example"}
    total_row = {"c": 2}
    mock_db.fetch_one.side_effect = [user_lookup, total_row]
    mock_db.fetch_all.return_value = [
        {
            "id": UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "probe_suite": "all",
            "status": "completed",
            "started_at": datetime(2026, 5, 10, 0, 0, tzinfo=timezone.utc),
            "finished_at": datetime(2026, 5, 10, 0, 7, tzinfo=timezone.utc),
            "target_kind": "custom_http",
            "findings_count": 115,
            "fails_count": 4,
        },
        {
            "id": UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "probe_suite": "owasp_07_system_prompt_leakage",
            "status": "completed",
            "started_at": datetime(2026, 5, 9, 0, 0, tzinfo=timezone.utc),
            "finished_at": datetime(2026, 5, 9, 0, 1, tzinfo=timezone.utc),
            "target_kind": "openai_compat",
            "findings_count": 3,
            "fails_count": 2,
        },
    ]
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/redteam-runs")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["user"]["email"] == "ops@acme.example"
    assert len(body["runs"]) == 2
    first = body["runs"][0]
    assert first["findings_count"] == 115
    assert first["fails_count"] == 4
    assert first["target_kind"] == "custom_http"
    assert first["status"] == "completed"


def test_list_user_runs_404_when_user_missing(client, admin_row, mock_db):
    _override_admin(client, admin_row)
    mock_db.fetch_one.return_value = None  # user lookup misses
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/redteam-runs")
    assert resp.status_code == 404


def test_list_user_runs_clamps_limit(client, admin_row, mock_db):
    """Requesting a giant limit must be silently clamped to 200 to protect
    the DB from accidental full-table scans via the admin UI."""
    _override_admin(client, admin_row)
    user_lookup = {"id": UUID(_CUSTOMER_ID), "email": "x@y"}
    total_row = {"c": 0}
    mock_db.fetch_one.side_effect = [user_lookup, total_row]
    mock_db.fetch_all.return_value = []
    resp = client.get(f"/api/v1/admin/users/{_CUSTOMER_ID}/redteam-runs?limit=9999")
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 200
