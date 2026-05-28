"""Tests for api_service/auth.py."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# get_current_user
# ---------------------------------------------------------------------------
async def test_get_current_user_rejects_missing_token(mock_db):
    from auth import get_current_user

    with pytest.raises(HTTPException) as exc:
        await get_current_user(authorization=None, x_api_token=None)
    assert exc.value.status_code == 401


async def test_get_current_user_accepts_x_api_token(mock_db, user_row):
    from auth import get_current_user

    mock_db.fetch_one.return_value = user_row
    user = await get_current_user(authorization=None, x_api_token="tok-abc")
    assert str(user.id) == str(user_row["id"])
    mock_db.fetch_one.assert_awaited_once()


async def test_get_current_user_accepts_bearer_header(mock_db, user_row):
    from auth import get_current_user

    mock_db.fetch_one.return_value = user_row
    user = await get_current_user(authorization="Bearer tok-abc", x_api_token=None)
    assert user.username == "alice"


async def test_get_current_user_rejects_malformed_authorization(mock_db):
    from auth import get_current_user

    with pytest.raises(HTTPException) as exc:
        await get_current_user(authorization="Basic xxx", x_api_token=None)
    assert exc.value.status_code == 401


async def test_get_current_user_rejects_invalid_token(mock_db):
    from auth import get_current_user

    mock_db.fetch_one.return_value = None
    with pytest.raises(HTTPException) as exc:
        await get_current_user(authorization=None, x_api_token="wrong")
    assert exc.value.status_code == 401


async def test_get_current_user_rejects_inactive(mock_db, user_row):
    from auth import get_current_user

    mock_db.fetch_one.return_value = {**user_row, "is_active": False}
    with pytest.raises(HTTPException) as exc:
        await get_current_user(authorization=None, x_api_token="tok")
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# get_optional_user
# ---------------------------------------------------------------------------
async def test_get_optional_user_returns_none_without_token(mock_db):
    from auth import get_optional_user

    assert await get_optional_user(None, None) is None


async def test_get_optional_user_returns_none_on_invalid_token(mock_db):
    from auth import get_optional_user

    mock_db.fetch_one.return_value = None
    assert await get_optional_user(None, "bad") is None


async def test_get_optional_user_returns_user(mock_db, user_row):
    from auth import get_optional_user

    mock_db.fetch_one.return_value = user_row
    user = await get_optional_user(None, "tok")
    assert user is not None
    assert user.email == "alice@example.com"


# ---------------------------------------------------------------------------
# require_admin
# ---------------------------------------------------------------------------
async def test_require_admin_accepts_super_admin(admin_row):
    from auth import require_admin
    from models import UserResponse

    user = UserResponse(**admin_row)
    result = await require_admin(current_user=user)
    assert result.role.value == "SUPER_ADMIN"


async def test_require_admin_rejects_ordinary_user(user_row):
    from auth import require_admin
    from models import UserResponse

    user = UserResponse(**user_row)
    with pytest.raises(HTTPException) as exc:
        await require_admin(current_user=user)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# require_trial_create_permission
# ---------------------------------------------------------------------------
async def test_trial_permission_admin_allowed(admin_row):
    from auth import require_trial_create_permission
    from models import UserResponse

    user = UserResponse(**admin_row)
    assert (await require_trial_create_permission(user)).role.value == "SUPER_ADMIN"


async def test_trial_permission_allowlisted_username(user_row):
    from auth import require_trial_create_permission
    from models import UserResponse

    user = UserResponse(**{**user_row, "username": "tester"})
    assert (await require_trial_create_permission(user)).username == "tester"


async def test_trial_permission_rejected(user_row):
    from auth import require_trial_create_permission
    from models import UserResponse

    user = UserResponse(**user_row)
    with pytest.raises(HTTPException) as exc:
        await require_trial_create_permission(user)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# get_current_user_dual_auth — internal + API-token branches
# ---------------------------------------------------------------------------
async def test_dual_auth_internal_call(mock_db, user_row):
    from auth import get_current_user_dual_auth

    mock_db.fetch_one.return_value = user_row
    user, payload = await get_current_user_dual_auth(
        authorization=None,
        x_api_token=None,
        x_internal_call="true",
        x_user_id=str(user_row["id"]),
    )
    assert payload is None
    assert user.username == "alice"


async def test_dual_auth_internal_call_unknown_user(mock_db):
    from auth import get_current_user_dual_auth

    mock_db.fetch_one.return_value = None
    with pytest.raises(HTTPException) as exc:
        await get_current_user_dual_auth(None, None, "true", "missing-id")
    assert exc.value.status_code == 401


async def test_dual_auth_api_token(mock_db, user_row):
    from auth import get_current_user_dual_auth

    mock_db.fetch_one.return_value = user_row
    user, payload = await get_current_user_dual_auth(
        authorization=None, x_api_token="tok", x_internal_call=None, x_user_id=None
    )
    assert payload is None
    assert user.email == user_row["email"]


async def test_dual_auth_bearer_jwt_path(mock_db, user_row):
    """When Bearer header carries a JWT, dual_auth calls verify_b2c_jwt."""
    from auth import get_current_user_dual_auth

    with patch("auth.is_jwt_token", return_value=True), \
         patch("auth.verify_b2c_jwt", new=AsyncMock(return_value={"sub": "u"})), \
         patch(
            "auth.get_user_info_from_token",
            new=AsyncMock(return_value={"id": str(user_row["id"]), "username": "alice", "email": "a@b.c"}),
         ):
        mock_db.fetch_one.return_value = user_row
        user, payload = await get_current_user_dual_auth(
            authorization="Bearer eyJ.fake.jwt",
            x_api_token=None,
            x_internal_call=None,
            x_user_id=None,
        )
        assert payload == {"sub": "u"}
        assert user.username == "alice"


# ---------------------------------------------------------------------------
# require_scope
# ---------------------------------------------------------------------------
async def test_require_scope_api_token_bypasses(user_row):
    from auth import require_scope
    from models import UserResponse

    dep = require_scope("api:read")
    # Directly invoke returned coroutine with mocked auth_data (API token branch)
    auth_data = (UserResponse(**user_row), None)
    assert await dep(auth_data=auth_data) == auth_data


async def test_require_scope_jwt_with_missing_scope(user_row):
    from auth import require_scope
    from models import UserResponse

    dep = require_scope("api:write")
    auth_data = (UserResponse(**user_row), {"scope": "api:read"})
    with pytest.raises(HTTPException) as exc:
        await dep(auth_data=auth_data)
    assert exc.value.status_code == 403


async def test_require_scope_jwt_with_all_scopes(user_row):
    from auth import require_scope
    from models import UserResponse

    dep = require_scope("api:read")
    auth_data = (UserResponse(**user_row), {"scope": "api:read api:write"})
    assert await dep(auth_data=auth_data) == auth_data
