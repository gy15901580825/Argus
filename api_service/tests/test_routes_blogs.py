"""L3 tests for routers/blogs.py — public list/get, auth create/update, admin delete."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest


@pytest.fixture
def author_client(client, user_row):
    """Ordinary user but granted blog_author — overrides get_current_user."""
    from auth import get_current_user
    from models import UserResponse
    import server

    user = UserResponse(**user_row)
    server.app.dependency_overrides[get_current_user] = lambda: user
    yield client, user
    server.app.dependency_overrides.clear()


@pytest.fixture
def admin_client(client, admin_row):
    """SUPER_ADMIN — overrides get_current_user (require_admin delegates to it)."""
    from auth import get_current_user
    from models import UserResponse
    import server

    admin = UserResponse(**admin_row)
    server.app.dependency_overrides[get_current_user] = lambda: admin
    yield client, admin
    server.app.dependency_overrides.clear()


def _blog_list_row(**overrides):
    base = {
        "id": uuid4(),
        "title": "Hello",
        "slug": "hello",
        "summary": "x",
        "author_id": UUID("11111111-1111-1111-1111-111111111111"),
        "is_published": True,
        "published_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "category_id": None,
        "cover_image_url": None,
        "reading_time_min": 3,
        "view_count": 5,
        "featured": False,
        "status": "published",
        "author_name": "alice",
        "category_name": None,
        "category_slug": None,
    }
    base.update(overrides)
    return base


def _blog_full_row(author_id: UUID, **overrides):
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    base = {
        "id": uuid4(),
        "title": "Hello",
        "content": "body",
        "slug": "hello",
        "summary": "sum",
        "author_id": author_id,
        "is_published": True,
        "published_at": now,
        "created_at": now,
        "updated_at": now,
        "category_id": None,
        "cover_image_url": None,
        "meta_title": None,
        "meta_description": None,
        "og_image_url": None,
        "canonical_url": None,
        "reading_time_min": 3,
        "view_count": 5,
        "content_format": "html",
        "featured": False,
        "status": "published",
        "scheduled_at": None,
        "locale": "en",
        "author_name": "alice",
        "category_name": None,
        "category_slug": None,
    }
    base.update(overrides)
    return base


# ---------- Public: list blogs ----------


def test_list_blogs_public_ok(client, mock_db):
    row = _blog_list_row()
    mock_db.fetch_all.side_effect = [
        [row],  # main query
        [],     # _attach_tags
    ]

    resp = client.get("/api/v1/blogs")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 1
    assert body[0]["title"] == "Hello"
    assert body[0]["tags"] == []


def test_list_blogs_empty(client, mock_db):
    mock_db.fetch_all.return_value = []

    resp = client.get("/api/v1/blogs")
    assert resp.status_code == 200
    assert resp.json() == []


# ---------- Public: get blog by id ----------


def test_get_blog_by_id_not_found(client, mock_db):
    mock_db.fetch_one.return_value = None

    resp = client.get(f"/api/v1/blogs/{uuid4()}")
    assert resp.status_code == 404


def test_get_blog_by_id_ok(client, mock_db):
    row = _blog_full_row(UUID("11111111-1111-1111-1111-111111111111"))
    mock_db.fetch_one.return_value = row
    mock_db.fetch_all.return_value = []  # _attach_tags

    resp = client.get(f"/api/v1/blogs/{row['id']}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == str(row["id"])
    assert body["title"] == "Hello"


# ---------- Create blog: 403 when not admin/author ----------


def test_create_blog_forbidden_for_non_author(author_client, mock_db):
    client, _ = author_client
    # _require_blog_author_or_admin: role is ORDINARY_USER, so it runs a blog_authors lookup
    mock_db.fetch_one.return_value = None  # not in blog_authors

    resp = client.post(
        "/api/v1/blogs",
        json={"title": "T", "content": "C"},
    )
    assert resp.status_code == 403
    assert "author" in resp.json()["detail"].lower()


def test_create_blog_ok_for_admin(admin_client, mock_db):
    client, admin = admin_client
    # Admin bypasses blog_authors check
    new_blog = _blog_full_row(admin.id, title="A new post", slug="a-new-post")
    mock_db.fetch_one.return_value = new_blog  # INSERT ... RETURNING *
    mock_db.fetch_all.return_value = []  # _attach_tags

    resp = client.post(
        "/api/v1/blogs",
        json={"title": "A new post", "content": "body"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["title"] == "A new post"


# ---------- Update blog ----------


def test_update_blog_not_found(admin_client, mock_db):
    client, _ = admin_client
    mock_db.fetch_one.return_value = None  # SELECT * FROM blogs -> None

    resp = client.put(
        f"/api/v1/blogs/{uuid4()}",
        json={"title": "new"},
    )
    assert resp.status_code == 404


# ---------- Delete blog (admin only) ----------


def test_delete_blog_not_found(admin_client, mock_db):
    client, _ = admin_client
    mock_db.fetch_one.return_value = None

    resp = client.delete(f"/api/v1/blogs/{uuid4()}")
    assert resp.status_code == 404


def test_delete_blog_ok(admin_client, mock_db):
    client, _ = admin_client
    bid = uuid4()
    mock_db.fetch_one.return_value = {"id": bid}

    resp = client.delete(f"/api/v1/blogs/{bid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"


def test_delete_blog_requires_auth(client):
    resp = client.delete(f"/api/v1/blogs/{uuid4()}")
    assert resp.status_code == 401
