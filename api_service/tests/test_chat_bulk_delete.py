"""L3 tests for routers/chat.py — POST /chat/sessions/bulk-delete.

Atomic per-user bulk delete. Ownership filter runs in SQL (id ANY + user_id),
so IDs not owned by the caller are silently dropped (no 401/403 leak).
"""
from __future__ import annotations

from uuid import UUID, uuid4

import pytest


URL = "/api/v1/chat/sessions/bulk-delete"


@pytest.fixture
def auth_client(client, user_row):
    """Mounts get_current_user → user_row."""
    from auth import get_current_user
    from models import UserResponse
    import server

    user = UserResponse(**user_row)
    server.app.dependency_overrides[get_current_user] = lambda: user
    yield client, user
    server.app.dependency_overrides.clear()


def test_bulk_delete_requires_auth(client):
    """No dependency override → get_current_user raises 401."""
    resp = client.post(URL, json={"ids": [str(uuid4())]})
    assert resp.status_code == 401


def test_bulk_delete_rejects_empty_ids(auth_client):
    c, _ = auth_client
    resp = c.post(URL, json={"ids": []})
    assert resp.status_code == 422


def test_bulk_delete_rejects_too_many_ids(auth_client):
    c, _ = auth_client
    ids = [str(uuid4()) for _ in range(101)]
    resp = c.post(URL, json={"ids": ids})
    assert resp.status_code == 422


def test_bulk_delete_rejects_malformed_uuid(auth_client):
    c, _ = auth_client
    resp = c.post(URL, json={"ids": ["not-a-uuid"]})
    assert resp.status_code == 422


def test_bulk_delete_owns_all_three(auth_client, mock_db):
    c, user = auth_client
    ids = [uuid4(), uuid4(), uuid4()]
    # SQL DELETE … RETURNING id returns the rows that matched
    mock_db.fetch_all.return_value = [{"id": i} for i in ids]

    resp = c.post(URL, json={"ids": [str(i) for i in ids]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted_count"] == 3
    assert sorted(body["deleted_ids"]) == sorted([str(i) for i in ids])
    # Verify SQL params: ids list + user_id from current_user
    args, kwargs = mock_db.fetch_all.call_args
    assert kwargs["values"]["user_id"] == user.id
    assert kwargs["values"]["ids"] == ids


def test_bulk_delete_silently_drops_non_owned_ids(auth_client, mock_db):
    """Mixed: 3 own + 2 belonging to others. Server returns only the 3 actually deleted."""
    c, _ = auth_client
    own_ids = [uuid4(), uuid4(), uuid4()]
    other_ids = [uuid4(), uuid4()]
    # The DB returns only own_ids because the WHERE user_id filter excluded the rest
    mock_db.fetch_all.return_value = [{"id": i} for i in own_ids]

    resp = c.post(URL, json={"ids": [str(i) for i in own_ids + other_ids]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["deleted_count"] == 3
    assert set(body["deleted_ids"]) == {str(i) for i in own_ids}


def test_bulk_delete_zero_matched(auth_client, mock_db):
    """All requested IDs were already gone or not owned. 200 with deleted_count=0."""
    c, _ = auth_client
    mock_db.fetch_all.return_value = []

    resp = c.post(URL, json={"ids": [str(uuid4()), str(uuid4())]})

    assert resp.status_code == 200
    body = resp.json()
    assert body == {"deleted_count": 0, "deleted_ids": []}
