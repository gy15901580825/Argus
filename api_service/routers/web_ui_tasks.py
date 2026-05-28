import json
import logging
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, File, Form, HTTPException, Depends, Query, UploadFile
from fastapi.responses import Response
from database import database
from models import WebUITaskCreate, WebUITaskResponse, WebUITaskUpdate, UserResponse
from auth import get_current_user, get_current_user_dual_auth, get_optional_user
from r2_storage import r2_storage

router = APIRouter()
logger = logging.getLogger("WebUITasksRouter")

_SELECT_COLS = """
    id, owner_id, target_url, status, user_persona, max_steps,
    created_at, started_at, finished_at, steps_done,
    tests_url, bug_report_url, features_url,
    bug_counts, test_summary, error_message,
    screenshot_urls, final_output
"""


@router.get("/web-ui-tasks", response_model=List[WebUITaskResponse])
async def list_web_ui_tasks(
    limit: int = 50,
    offset: int = 0,
    current_user: UserResponse = Depends(get_current_user),
):
    query = f"""
        SELECT {_SELECT_COLS}
        FROM web_ui_tasks
        WHERE owner_id = :owner_id
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """
    try:
        rows = await database.fetch_all(
            query=query,
            values={"owner_id": str(current_user.id), "limit": limit, "offset": offset},
        )
        return [WebUITaskResponse(**dict(row)) for row in rows]
    except Exception as e:
        logger.error("Error listing web_ui_tasks: %s", e)
        raise HTTPException(status_code=500, detail="Failed to list web UI tasks")


@router.get("/web-ui-tasks/{task_id}", response_model=WebUITaskResponse)
async def get_web_ui_task(
    task_id: UUID,
    current_user: UserResponse = Depends(get_current_user),
):
    query = f"""
        SELECT {_SELECT_COLS}
        FROM web_ui_tasks
        WHERE id = :task_id AND owner_id = :owner_id
    """
    try:
        row = await database.fetch_one(
            query=query,
            values={"task_id": task_id, "owner_id": str(current_user.id)},
        )
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        return WebUITaskResponse(**dict(row))
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error fetching web_ui_task %s: %s", task_id, e)
        raise HTTPException(status_code=500, detail="Failed to get web UI task")


@router.delete("/web-ui-tasks/{task_id}")
async def delete_web_ui_task(
    task_id: UUID,
    current_user: UserResponse = Depends(get_current_user),
):
    query = """
        DELETE FROM web_ui_tasks
        WHERE id = :task_id AND owner_id = :owner_id
        RETURNING id
    """
    try:
        result = await database.fetch_one(
            query=query,
            values={"task_id": task_id, "owner_id": str(current_user.id)},
        )
        if not result:
            raise HTTPException(status_code=404, detail="Task not found")
        return {"message": "Task deleted", "id": str(result["id"])}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting web_ui_task %s: %s", task_id, e)
        raise HTTPException(status_code=500, detail="Failed to delete web UI task")


# ---------------------------------------------------------------------------
# New persistence endpoints
# ---------------------------------------------------------------------------

@router.post("/web-ui-tasks", response_model=WebUITaskResponse, status_code=201)
async def create_web_ui_task(
    body: WebUITaskCreate,
    auth: tuple = Depends(get_current_user_dual_auth),
):
    """Create a DB record when a web UI task starts (called by orchestrator)."""
    current_user: UserResponse = auth[0]
    query = """
        INSERT INTO web_ui_tasks
            (id, owner_id, target_url, status, user_persona, max_steps, started_at, created_at)
        VALUES
            (:id, :owner_id, :target_url, :status, :user_persona, :max_steps, :started_at, NOW())
        ON CONFLICT (id) DO NOTHING
        RETURNING *
    """
    try:
        row = await database.fetch_one(
            query=query,
            values={
                "id": str(body.id),
                "owner_id": str(current_user.id),
                "target_url": body.target_url,
                "status": body.status,
                "user_persona": body.user_persona,
                "max_steps": body.max_steps,
                "started_at": body.started_at,
            },
        )
        if not row:
            # ON CONFLICT DO NOTHING — row already exists, fetch it
            row = await database.fetch_one(
                query=f"SELECT {_SELECT_COLS} FROM web_ui_tasks WHERE id = :id",
                values={"id": str(body.id)},
            )
        return WebUITaskResponse(**dict(row))
    except Exception as e:
        logger.error("Error creating web_ui_task: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create web UI task")


@router.patch("/web-ui-tasks/{task_id}", response_model=WebUITaskResponse)
async def update_web_ui_task(
    task_id: UUID,
    body: WebUITaskUpdate,
    auth: tuple = Depends(get_current_user_dual_auth),
):
    """Persist final results for a completed/failed task (called by orchestrator)."""
    current_user: UserResponse = auth[0]
    user_id = str(current_user.id)

    # Ownership check
    existing = await database.fetch_one(
        query="SELECT id FROM web_ui_tasks WHERE id = :task_id AND owner_id = :owner_id",
        values={"task_id": str(task_id), "owner_id": user_id},
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Task not found")

    # Upload text artifacts to R2 (best-effort)
    bug_report_url: Optional[str] = None
    tests_url: Optional[str] = None

    if body.final_output:
        key = f"web-ui/{user_id}/{task_id}/bug_report.txt"
        bug_report_url = await r2_storage.upload_bytes(
            body.final_output.encode("utf-8"), key, "text/plain"
        )

    if body.test_script:
        key = f"web-ui/{user_id}/{task_id}/test_script.py"
        tests_url = await r2_storage.upload_bytes(
            body.test_script.encode("utf-8"), key, "text/x-python"
        )

    # Build dynamic SET clause
    set_parts = []
    values: dict = {"task_id": str(task_id), "owner_id": user_id}

    if body.status is not None:
        set_parts.append("status = :status")
        values["status"] = body.status
    if body.steps_done is not None:
        set_parts.append("steps_done = :steps_done")
        values["steps_done"] = body.steps_done
    if body.finished_at is not None:
        set_parts.append("finished_at = :finished_at")
        values["finished_at"] = body.finished_at
    if body.bug_counts is not None:
        set_parts.append("bug_counts = :bug_counts")
        values["bug_counts"] = json.dumps(body.bug_counts)
    if body.final_output is not None:
        set_parts.append("final_output = :final_output")
        values["final_output"] = body.final_output
    if bug_report_url:
        set_parts.append("bug_report_url = :bug_report_url")
        values["bug_report_url"] = bug_report_url
    if tests_url:
        set_parts.append("tests_url = :tests_url")
        values["tests_url"] = tests_url
    if body.screenshot_urls is not None:
        set_parts.append("screenshot_urls = :screenshot_urls")
        values["screenshot_urls"] = json.dumps(body.screenshot_urls)
    if body.error_message is not None:
        set_parts.append("error_message = :error_message")
        values["error_message"] = body.error_message

    if not set_parts:
        # Nothing to update — return current state
        row = await database.fetch_one(
            query=f"SELECT {_SELECT_COLS} FROM web_ui_tasks WHERE id = :task_id",
            values={"task_id": str(task_id)},
        )
        return WebUITaskResponse(**dict(row))

    set_clause = ", ".join(set_parts)
    query = f"""
        UPDATE web_ui_tasks
        SET {set_clause}
        WHERE id = :task_id AND owner_id = :owner_id
        RETURNING {_SELECT_COLS}
    """
    try:
        row = await database.fetch_one(query=query, values=values)
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        return WebUITaskResponse(**dict(row))
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error updating web_ui_task %s: %s", task_id, e)
        raise HTTPException(status_code=500, detail="Failed to update web UI task")


@router.post("/web-ui-tasks/{task_id}/screenshots")
async def upload_screenshot(
    task_id: UUID,
    file: UploadFile = File(...),
    step_index: int = Form(...),
    auth: tuple = Depends(get_current_user_dual_auth),
):
    """Upload a single screenshot PNG for a running task (called by client agent)."""
    current_user: UserResponse = auth[0]
    user_id = str(current_user.id)

    img_bytes = await file.read()
    object_key = f"web-ui/{user_id}/{task_id}/screenshots/step_{step_index:03d}.png"

    url = await r2_storage.upload_bytes(img_bytes, object_key, "image/png")
    if not url:
        raise HTTPException(status_code=502, detail="R2 upload failed")

    logger.info("Screenshot upload: task=%s step=%d url=%s", task_id, step_index, url)
    return {"url": url, "step_index": step_index}


@router.get("/web-ui-tasks/{task_id}/screenshots/{step_index}")
async def get_screenshot(
    task_id: UUID,
    step_index: int,
    token: Optional[str] = Query(None),
    current_user: Optional[UserResponse] = Depends(get_optional_user),
):
    """Proxy a screenshot from R2 — resolves the public-access issue.

    Accepts auth via header (Authorization / x-api-token) OR ?token= query param.
    The query-param form is needed because <img src> tags cannot send headers.
    """
    # If header auth failed but query token is present, authenticate via query
    if current_user is None and token:
        row = await database.fetch_one(
            query="SELECT id, username, email, display_name, avatar, role, is_active, created_at, updated_at FROM users WHERE api_token = :token",
            values={"token": token},
        )
        if row and row["is_active"]:
            current_user = UserResponse(**row)

    if current_user is None:
        raise HTTPException(status_code=401, detail="Missing authentication token")

    user_id = str(current_user.id)

    # Verify task ownership
    row = await database.fetch_one(
        query="SELECT owner_id FROM web_ui_tasks WHERE id = :task_id",
        values={"task_id": str(task_id)},
    )
    if not row or str(row["owner_id"]) != user_id:
        raise HTTPException(status_code=404, detail="Task not found")

    object_key = f"web-ui/{user_id}/{task_id}/screenshots/step_{step_index:03d}.png"
    img_bytes = await r2_storage.download_bytes(object_key)
    if img_bytes is None:
        raise HTTPException(status_code=404, detail="Screenshot not found")

    return Response(
        content=img_bytes,
        media_type="image/png",
        headers={
            "Cache-Control": "public, max-age=86400",
            "Content-Disposition": f"inline; filename=step_{step_index:03d}.png",
        },
    )
