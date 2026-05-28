"""Shared driver for Web UI tests on the user's local client_agent.

Exports `run_client_web_ui(...)`, an async generator that:
  1. Resolves the user's connected client_agent via connection_manager.
  2. Calls start_web_ui_test, then polls get_web_ui_test_status.
  3. Fetches the final result via get_web_ui_test_result.
  4. Persists running / completed / failed state to the API service.

Yields protocol-agnostic dicts:
  {"event_type": "log" | "web_ui_artifact" | "web_ui_bug" | "error",
   "payload": {...}}

Terminal events are "web_ui_bug" (completion) or "error" (fatal failure).
Consumers (ADK agent, planner tool) wrap these dicts in their own envelope.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, AsyncGenerator, Optional

from orchestrator.utils.web_ui_task_api import patch_task as _patch_task
from orchestrator.utils.web_ui_task_api import post_task as _post_task

logger = logging.getLogger(__name__)

POLL_INTERVAL = 3
MAX_WAIT_SECONDS = 86400
STALL_TIMEOUT = 300

# user_id -> (agent_id, task_id); used by cancel endpoint.
_active_tasks: dict[str, tuple[str, str]] = {}


def get_active_task(user_id: str) -> Optional[tuple[str, str]]:
    return _active_tasks.get(user_id)


def _log(message: str) -> dict:
    return {"event_type": "log", "payload": {"type": "log", "message": message}}


def _error(message: str) -> dict:
    return {"event_type": "error", "payload": {"type": "error", "message": message}}


async def run_client_web_ui(
    *,
    url: str,
    user_id: Optional[str],
    auth_token: Optional[str],
    cdp_url: Optional[str] = None,
    max_steps: int = 100,
    user_persona: str = "new_user",
    credentials: Optional[dict] = None,
    business_context: Optional[str] = None,
    browser_model: Optional[str] = None,
    script_model: Optional[str] = None,
) -> AsyncGenerator[dict, None]:
    """Run a Web UI test on the user's local client_agent and stream events.

    Final event is always either `result` (happy path) or `error` (fatal).
    """
    # Late imports: these modules live at the orchestrator entry-point root,
    # not inside the `orchestrator` package, so they can only be resolved
    # at runtime (when server.py has been loaded as `__main__`).
    try:
        from connection_manager import connection_manager  # type: ignore  # noqa: PLC0415
        from server import API_SERVICE_URL, get_user_agent_id  # type: ignore  # noqa: PLC0415
    except ImportError as exc:
        yield _error(f"Import error: {exc}")
        return

    api_base = API_SERVICE_URL.rstrip("/")

    # 1. Resolve agent
    agent_id: Optional[str] = await get_user_agent_id(user_id, auth_token)
    if not agent_id:
        yield _error(
            f"No active client agent found for user {user_id}. "
            "Please start the client_agent on your machine first."
        )
        return
    if agent_id not in connection_manager.active_connections:
        yield _error(
            f"Client agent {agent_id} is registered but not connected. "
            "Check that the client agent container is running."
        )
        return

    yield _log(
        f"Found active client agent {agent_id}. "
        f"Starting Web UI exploration of {url} via CDP ({cdp_url})..."
    )

    # 2. Start
    start_args: dict = {
        "url": url, "cdp_url": cdp_url,
        "max_steps": max_steps, "user_persona": user_persona,
    }
    if browser_model:
        start_args["llm_model"] = browser_model
    if script_model:
        start_args["script_model"] = script_model
    if credentials:
        start_args["credentials"] = credentials
    if business_context:
        start_args["business_context"] = business_context

    try:
        start_result = await connection_manager.send_command(
            agent_id, "tools/call",
            {"name": "start_web_ui_test", "arguments": start_args},
        )
    except Exception as exc:
        logger.exception("send_command start_web_ui_test failed")
        yield _error(f"Failed to start test: {exc}")
        return

    if isinstance(start_result, dict) and start_result.get("error") is not None:
        yield _error(f"Client agent error: {start_result['error']}")
        return

    task_id: str = start_result.get("task_id", "") if isinstance(start_result, dict) else ""
    if not task_id:
        yield _error("No task_id returned from client agent.")
        return

    if user_id:
        _active_tasks[user_id] = (agent_id, task_id)

    # web_ui_tasks.user_persona is VARCHAR(50); the planner may hand us a
    # longer narrative persona. Truncate for persistence only — the full
    # persona string is already passed to the client agent in start_args.
    await _post_task(
        api_base=api_base, auth_token=auth_token, user_id=user_id,
        body={
            "id": task_id, "target_url": url, "status": "running",
            "user_persona": (user_persona or "")[:50],
            "max_steps": max_steps,
            "started_at": datetime.utcnow().isoformat(),
        },
    )

    yield _log(
        f"Task {task_id} running on client agent — "
        f"polling every {POLL_INTERVAL}s (max {MAX_WAIT_SECONDS}s)..."
    )

    # 3. Poll
    async def _send_cancel() -> None:
        try:
            await asyncio.wait_for(
                connection_manager.send_command(
                    agent_id, "tools/call",
                    {"name": "cancel_web_ui_test", "arguments": {"task_id": task_id}},
                ),
                timeout=5.0,
            )
        except Exception as exc:
            logger.warning("cancel_web_ui_test for %s failed: %s", task_id, exc)

    elapsed = 0
    last_steps = -1
    stall_elapsed = 0

    try:
        while elapsed < MAX_WAIT_SECONDS:
            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

            try:
                status_result = await connection_manager.send_command(
                    agent_id, "tools/call",
                    {"name": "get_web_ui_test_status", "arguments": {"task_id": task_id}},
                )
            except Exception as exc:
                logger.warning("Status poll error for %s: %s", task_id, exc)
                continue

            if isinstance(status_result, dict) and status_result.get("error") is not None:
                yield _log(f"⚠️ Status poll error: {status_result['error']}")
                continue

            current_status: str = status_result.get("status", "unknown")
            steps_done: int = status_result.get("steps_done", 0)
            max_s = status_result.get("max_steps", max_steps)

            if steps_done != last_steps:
                last_steps = steps_done
                stall_elapsed = 0
                yield _log(f"Step {steps_done}/{max_s} — {current_status}")
            else:
                stall_elapsed += POLL_INTERVAL
                if int(stall_elapsed) % 15 == 0:
                    yield _log(
                        f"Step {steps_done}/{max_s} — {current_status} "
                        "(waiting for browser action...)"
                    )
                if stall_elapsed >= STALL_TIMEOUT:
                    yield _log(
                        f"⚠️ No step progress for {STALL_TIMEOUT}s "
                        f"(stuck at step {steps_done}). Cancelling..."
                    )
                    await _send_cancel()
                    await asyncio.sleep(10)
                    break

            if current_status == "completed":
                break
            if current_status == "failed":
                err_msg = status_result.get("error", "Unknown error")
                await _patch_task(
                    api_base=api_base, task_id=task_id,
                    auth_token=auth_token, user_id=user_id,
                    body={"status": "failed", "error_message": err_msg,
                          "finished_at": datetime.utcnow().isoformat()},
                )
                if user_id:
                    _active_tasks.pop(user_id, None)
                yield _error(f"Exploration failed: {err_msg}")
                return
            if current_status == "cancelled":
                await _patch_task(
                    api_base=api_base, task_id=task_id,
                    auth_token=auth_token, user_id=user_id,
                    body={"status": "cancelled",
                          "finished_at": datetime.utcnow().isoformat()},
                )
                if user_id:
                    _active_tasks.pop(user_id, None)
                yield _error("Task was cancelled.")
                return
        else:
            await _send_cancel()
            await _patch_task(
                api_base=api_base, task_id=task_id,
                auth_token=auth_token, user_id=user_id,
                body={"status": "failed", "error_message": "Timed out",
                      "finished_at": datetime.utcnow().isoformat()},
            )
            if user_id:
                _active_tasks.pop(user_id, None)
            yield _error(f"Absolute timeout reached after {MAX_WAIT_SECONDS}s.")
            return

    except (asyncio.CancelledError, GeneratorExit):
        # Consumer disconnected — keep the task running remotely. Don't pop
        # _active_tasks so an explicit cancel from the user still works.
        logger.info("Consumer disconnected for task %s — task continues", task_id)
        raise

    if user_id:
        _active_tasks.pop(user_id, None)

    # 4. Fetch full result
    try:
        full_result = await connection_manager.send_command(
            agent_id, "tools/call",
            {"name": "get_web_ui_test_result", "arguments": {"task_id": task_id}},
        )
    except Exception as exc:
        yield _error(f"Failed to retrieve result: {exc}")
        return

    if isinstance(full_result, dict) and full_result.get("error") is not None:
        yield _error(f"Result error: {full_result['error']}")
        return
    if not isinstance(full_result, dict):
        yield _error("Client agent returned a non-dict result.")
        return

    test_script: str = full_result.get("test_script") or ""
    bug_counts: dict = full_result.get("bug_counts") or {}
    screenshot_count: int = full_result.get("screenshot_count", 0) or 0
    screenshot_urls = [
        f"{api_base}/api/v1/web-ui-tasks/{task_id}/screenshots/{i}"
        for i in range(screenshot_count)
    ]

    # api_service uploads test_script + final_output to R2 during PATCH and
    # returns the resulting tests_url / bug_report_url in the response. We
    # surface those URLs via the web_ui_bug payload so the frontend's
    # BugReportArtifact card can link out to the artifacts.
    patch_resp = await _patch_task(
        api_base=api_base, task_id=task_id,
        auth_token=auth_token, user_id=user_id,
        body={
            "status": full_result.get("status", "completed"),
            "steps_done": full_result.get("steps_done", 0),
            "finished_at": datetime.utcnow().isoformat(),
            "bug_counts": bug_counts,
            "final_output": full_result.get("final_output") or "",
            "test_script": test_script,
            "screenshot_urls": screenshot_urls,
            "error_message": full_result.get("error"),
        },
    )
    tests_url = (patch_resp or {}).get("tests_url")
    bug_report_url = (patch_resp or {}).get("bug_report_url")

    yield _log(
        f"Exploration complete. "
        f"Bugs — Critical: {bug_counts.get('critical', 0)}, "
        f"High: {bug_counts.get('high', 0)}, "
        f"Medium: {bug_counts.get('medium', 0)}, "
        f"Low: {bug_counts.get('low', 0)}. "
        f"Test script: {'generated' if test_script else 'not generated'} "
        f"({len(test_script)} chars)"
    )

    if test_script:
        yield {
            "event_type": "web_ui_artifact",
            "payload": {
                "type": "web_ui_artifact",
                "artifact_type": "web_ui_tests",
                "name": f"web_ui_test_{task_id}.py",
                "content": test_script,
                "task_id": task_id,
                "url": url,
                "source": "local_client_agent",
            },
        }

    yield {
        "event_type": "web_ui_bug",
        "payload": {
            "type": "web_ui_bug",
            "task_id": task_id,
            "url": url,
            "status": "completed",
            "source": "local_client_agent",
            "cdp_url": cdp_url,
            "bug_counts": bug_counts,
            "has_tests": bool(test_script),
            "steps_done": full_result.get("steps_done", 0),
            "final_output": full_result.get("final_output") or "",
            "screenshot_urls": screenshot_urls,
            "tests_url": tests_url,
            "bug_report_url": bug_report_url,
        },
    }
