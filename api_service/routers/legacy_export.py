"""Legacy data-export endpoint for users on the deprecated web-UI-testing product.

Available during the 60-day sunset window only. Removed after the legacy tables
are dropped (see V18 migration + Plan 1 Task 18 + Plan 2 V19 drop).

Mounts at /legacy-export (NOT /api/v1/legacy-export) — the user-facing URL.
"""

from fastapi import APIRouter, Depends

from auth import get_current_user
from database import database
from models import UserResponse

router = APIRouter(prefix="/legacy-export")


@router.get("/manifest")
async def manifest(user: UserResponse = Depends(get_current_user)) -> dict:
    return {
        "user_id": str(user.id),
        "tables": ["scripts", "web_ui_tasks"],
        "available_until": "2026-07-01T00:00:00Z",
    }


@router.get("/dump")
async def dump(user: UserResponse = Depends(get_current_user)) -> dict:
    scripts_rows = await database.fetch_all(
        "SELECT * FROM scripts WHERE user_id = :user_id", {"user_id": user.id}
    )
    web_ui_rows = await database.fetch_all(
        "SELECT * FROM web_ui_tasks WHERE user_id = :user_id", {"user_id": user.id}
    )
    return {
        "scripts": [dict(r) for r in scripts_rows],
        "web_ui_tasks": [dict(r) for r in web_ui_rows],
    }
