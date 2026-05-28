"""HTTP helpers for the api_service /api/v1/web-ui-tasks endpoints.

Both runners (client_agent runner + cloud runner) hit these endpoints to
persist task lifecycle. The api_service PATCH handler also uploads
``test_script`` and ``final_output`` to R2 and returns the resulting
``tests_url`` / ``bug_report_url`` in its response — callers should pass
those URLs back to the frontend via the SSE web_ui_bug payload so the
BugReportArtifact card can link to artifacts.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


def _auth_headers(auth_token: Optional[str], user_id: Optional[str]) -> dict:
    headers: dict = {}
    if auth_token:
        headers["Authorization"] = (
            auth_token if auth_token.startswith("Bearer ")
            else f"Bearer {auth_token}"
        )
    elif user_id:
        # Internal service-to-service path used when no end-user JWT is
        # available (e.g. cloud runner streaming from the orchestrator pod).
        headers["x-internal-call"] = "true"
        headers["x-user-id"] = user_id
    return headers


async def post_task(
    *,
    api_base: str,
    auth_token: Optional[str],
    user_id: Optional[str],
    body: dict,
) -> Optional[dict]:
    """POST /api/v1/web-ui-tasks. Returns response JSON on 2xx, None otherwise.

    Best-effort: never raises. Failures are logged at WARNING and surface as
    None so the caller can decide whether to continue without persistence.
    """
    headers = _auth_headers(auth_token, user_id)
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            resp = await client.post(
                f"{api_base}/api/v1/web-ui-tasks",
                headers=headers, json=body,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "POST web-ui-task returned %d: %s",
                    resp.status_code, resp.text[:200],
                )
                return None
            try:
                return resp.json()
            except Exception:
                return None
    except Exception as exc:
        logger.warning("POST web-ui-task failed: %s", exc)
        return None


async def patch_task(
    *,
    api_base: str,
    task_id: str,
    auth_token: Optional[str],
    user_id: Optional[str],
    body: dict,
) -> Optional[dict]:
    """PATCH /api/v1/web-ui-tasks/{task_id}. Returns response JSON on 2xx,
    None on failure.

    api_service uploads ``body['test_script']`` to ``web-ui/{user_id}/{task_id}/test_script.py``
    and ``body['final_output']`` to ``web-ui/{user_id}/{task_id}/bug_report.txt``
    on R2, and returns the resulting ``tests_url`` / ``bug_report_url`` in
    the response. Callers should read those URLs and surface them via the
    SSE web_ui_bug payload.

    Timeout is generous (30s) because the R2 upload happens server-side
    during this request.
    """
    headers = _auth_headers(auth_token, user_id)
    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.patch(
                f"{api_base}/api/v1/web-ui-tasks/{task_id}",
                headers=headers, json=body,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "PATCH web-ui-task %s returned %d: %s",
                    task_id, resp.status_code, resp.text[:200],
                )
                return None
            try:
                return resp.json()
            except Exception:
                return None
    except Exception as exc:
        logger.warning("PATCH web-ui-task %s failed: %s", task_id, exc)
        return None
