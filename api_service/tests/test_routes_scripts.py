"""L3 tests for routers/scripts.py — full CRUD via TestClient + dependency override."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

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


def _script_row(owner_id: UUID, **overrides):
    base = {
        "id": uuid4(),
        "name": "my-script",
        "script_address": "s3://bucket/x.py",
        "description": "hello",
        "owner_id": owner_id,
        "version": "1.0.0",
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "owner_name": "alice",
    }
    base.update(overrides)
    return base


def test_create_script(auth_client, mock_db):
    client, user = auth_client
    mock_db.fetch_one.return_value = _script_row(user.id)

    resp = client.post(
        "/api/v1/scripts",
        json={"name": "my-script", "script_address": "s3://bucket/x.py", "version": "1.0.0"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "my-script"
    assert body["owner_name"] == "alice"


def test_list_scripts(auth_client, mock_db):
    client, user = auth_client
    mock_db.fetch_all.return_value = [_script_row(user.id), _script_row(user.id, name="s2")]

    resp = client.get("/api/v1/scripts")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    assert body[1]["name"] == "s2"


def test_get_script_not_found_returns_404(auth_client, mock_db):
    client, _ = auth_client
    mock_db.fetch_one.return_value = None

    resp = client.get(f"/api/v1/scripts/{uuid4()}")
    assert resp.status_code == 404


def test_get_script_ok(auth_client, mock_db):
    client, user = auth_client
    row = _script_row(user.id)
    mock_db.fetch_one.return_value = row

    resp = client.get(f"/api/v1/scripts/{row['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == str(row["id"])


def test_update_script_missing_fields_returns_400(auth_client, mock_db):
    client, _ = auth_client
    # First call (ownership check) returns truthy, second call shouldn't happen
    mock_db.fetch_one.return_value = {"id": uuid4()}

    resp = client.put(f"/api/v1/scripts/{uuid4()}", json={})
    assert resp.status_code == 400
    assert "No fields" in resp.json()["detail"]


def test_update_script_ok(auth_client, mock_db):
    client, user = auth_client
    sid = uuid4()
    mock_db.fetch_one.side_effect = [
        {"id": sid},                                 # ownership check
        _script_row(user.id, id=sid, name="renamed"),  # update RETURNING
    ]

    resp = client.put(f"/api/v1/scripts/{sid}", json={"name": "renamed"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed"


def test_update_script_not_found(auth_client, mock_db):
    client, _ = auth_client
    mock_db.fetch_one.return_value = None

    resp = client.put(f"/api/v1/scripts/{uuid4()}", json={"name": "x"})
    assert resp.status_code == 404


def test_delete_script_ok(auth_client, mock_db):
    client, _ = auth_client
    sid = uuid4()
    mock_db.fetch_one.return_value = {"id": sid}

    resp = client.delete(f"/api/v1/scripts/{sid}")
    assert resp.status_code == 200
    assert resp.json()["id"] == str(sid)


def test_delete_script_not_found(auth_client, mock_db):
    client, _ = auth_client
    mock_db.fetch_one.return_value = None

    resp = client.delete(f"/api/v1/scripts/{uuid4()}")
    assert resp.status_code == 404


def test_list_scripts_requires_auth(client):
    """Without auth dependency override, the endpoint must refuse."""
    resp = client.get("/api/v1/scripts")
    assert resp.status_code == 401
