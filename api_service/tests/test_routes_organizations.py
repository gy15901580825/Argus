"""Tests for /organizations (Y2) — member-scoped CRUD + role gating."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import UUID

import pytest


_ORG_ID = "44444444-4444-4444-4444-444444444444"
_OTHER_USER_ID = "55555555-5555-5555-5555-555555555555"


def _override_current_user(client, user_row):
    from auth import get_current_user
    from models import UserResponse
    client.app.dependency_overrides[get_current_user] = lambda: UserResponse(**user_row)


# ─── List my orgs ──────────────────────────────────────────────────────────


def test_list_my_organizations_returns_role(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_all.return_value = [
        {
            "id": UUID(_ORG_ID),
            "name": "ACME Corp",
            "slug": "acme-corp-ab12cd",
            "contact_email": "cto@acme.com",
            "plan_tier": "design_partner",
            "metadata": {"industry": "fintech"},
            "is_active": True,
            "created_at": datetime(2026, 5, 11, tzinfo=timezone.utc),
            "role": "OWNER",
        }
    ]
    resp = client.get("/api/v1/organizations")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["role"] == "OWNER"
    assert body[0]["plan_tier"] == "design_partner"
    assert body[0]["metadata"]["industry"] == "fintech"


# ─── Create org ────────────────────────────────────────────────────────────


def test_create_organization_makes_caller_owner(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.execute.return_value = None
    resp = client.post("/api/v1/organizations", json={
        "name": "ACME Corp",
        "contact_email": "cto@acme.com",
        "plan_tier": "design_partner",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["role"] == "OWNER"
    assert body["name"] == "ACME Corp"
    assert body["slug"].startswith("acme-corp-")
    # Two INSERTs: one for the org, one for the OWNER membership
    assert mock_db.execute.await_count == 2


def test_create_organization_rejects_invalid_plan_tier(client, user_row, mock_db):
    _override_current_user(client, user_row)
    resp = client.post("/api/v1/organizations", json={"name": "X", "plan_tier": "platinum"})
    assert resp.status_code == 400


def test_create_organization_rejects_empty_name(client, user_row, mock_db):
    _override_current_user(client, user_row)
    resp = client.post("/api/v1/organizations", json={"name": "   "})
    assert resp.status_code == 400


# ─── role gating via require_org_role ──────────────────────────────────────


def test_get_organization_rejects_non_member(client, user_row, mock_db):
    _override_current_user(client, user_row)
    # First fetch_one = membership check → None (not a member)
    mock_db.fetch_one.return_value = None
    resp = client.get(f"/api/v1/organizations/{_ORG_ID}")
    assert resp.status_code == 403
    assert "Not a member" in resp.json()["detail"]


def test_get_organization_rejects_insufficient_role(client, user_row, mock_db):
    """VIEWER can list/view, but PATCH requires ADMIN+."""
    _override_current_user(client, user_row)
    mock_db.fetch_one.return_value = {"role": "VIEWER"}
    resp = client.patch(f"/api/v1/organizations/{_ORG_ID}", json={"name": "New Name"})
    assert resp.status_code == 403
    assert "ADMIN or higher" in resp.json()["detail"] or "ADMIN" in resp.json()["detail"]


def test_get_organization_returns_data_for_viewer(client, user_row, mock_db):
    _override_current_user(client, user_row)
    # Order: membership, org row, member_count row
    mock_db.fetch_one.side_effect = [
        {"role": "VIEWER"},
        {
            "id": UUID(_ORG_ID),
            "name": "ACME Corp",
            "slug": "acme-corp-ab12cd",
            "contact_email": "cto@acme.com",
            "plan_tier": "design_partner",
            "metadata": {},
            "is_active": True,
            "created_at": datetime(2026, 5, 11, tzinfo=timezone.utc),
        },
        {"c": 3},
    ]
    resp = client.get(f"/api/v1/organizations/{_ORG_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["my_role"] == "VIEWER"
    assert body["member_count"] == 3


# ─── plan_tier change requires OWNER ───────────────────────────────────────


def test_update_organization_plan_tier_requires_owner(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.return_value = {"role": "ADMIN"}
    resp = client.patch(
        f"/api/v1/organizations/{_ORG_ID}",
        json={"plan_tier": "enterprise"},
    )
    assert resp.status_code == 403
    assert "OWNER" in resp.json()["detail"]


def test_update_organization_admin_can_change_name(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.return_value = {"role": "ADMIN"}
    resp = client.patch(
        f"/api/v1/organizations/{_ORG_ID}",
        json={"name": "ACME Corporation"},
    )
    assert resp.status_code == 200
    assert "name" in resp.json()["updated_fields"]


# ─── Members ───────────────────────────────────────────────────────────────


def test_add_member_404_if_email_not_registered(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.side_effect = [
        {"role": "OWNER"},  # caller's membership
        None,  # target user lookup
    ]
    resp = client.post(
        f"/api/v1/organizations/{_ORG_ID}/members",
        json={"user_email": "ghost@example.com", "role": "MEMBER"},
    )
    assert resp.status_code == 404
    assert "Email-invite" in resp.json()["detail"]


def test_add_member_409_if_already_member(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.side_effect = [
        {"role": "OWNER"},
        {"id": UUID(_OTHER_USER_ID)},
        {"id": "preexisting-membership-id"},
    ]
    resp = client.post(
        f"/api/v1/organizations/{_ORG_ID}/members",
        json={"user_email": "bob@example.com", "role": "MEMBER"},
    )
    assert resp.status_code == 409


def test_add_member_rejects_OWNER_role(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.return_value = {"role": "OWNER"}
    resp = client.post(
        f"/api/v1/organizations/{_ORG_ID}/members",
        json={"user_email": "bob@example.com", "role": "OWNER"},
    )
    assert resp.status_code == 400
    assert "Cannot add as OWNER" in resp.json()["detail"]


def test_update_member_role_blocks_last_owner_demotion(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.side_effect = [
        {"role": "OWNER"},     # caller membership
        {"role": "OWNER"},     # target's current role (also OWNER)
        {"c": 1},              # owner count = 1
    ]
    resp = client.patch(
        f"/api/v1/organizations/{_ORG_ID}/members/{_OTHER_USER_ID}",
        json={"role": "MEMBER"},
    )
    assert resp.status_code == 400
    assert "last OWNER" in resp.json()["detail"]


def test_remove_member_blocks_last_owner(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.side_effect = [
        {"role": "OWNER"},
        {"role": "OWNER"},
        {"c": 1},
    ]
    resp = client.delete(f"/api/v1/organizations/{_ORG_ID}/members/{_OTHER_USER_ID}")
    assert resp.status_code == 400
    assert "last OWNER" in resp.json()["detail"]


def test_remove_member_succeeds_for_non_last_owner(client, user_row, mock_db):
    _override_current_user(client, user_row)
    mock_db.fetch_one.side_effect = [
        {"role": "OWNER"},
        {"role": "OWNER"},
        {"c": 2},  # two owners exist; removing one is OK
    ]
    resp = client.delete(f"/api/v1/organizations/{_ORG_ID}/members/{_OTHER_USER_ID}")
    assert resp.status_code == 200
