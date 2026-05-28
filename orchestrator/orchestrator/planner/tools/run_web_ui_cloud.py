"""run_web_ui_cloud tool — stream NDJSON from testing_web_ui_service.

The testing-web-ui-service exposes POST /agent/run that streams NDJSON
events ({"type": "log"|"progress"|"artifact"|"result"|"error", ...}).
This tool translates the orchestrator's tool-call envelope into the
RemoteAgent-compatible {"session_state", "invocation_id", "user_id"}
payload, then re-shapes each event to match the wire format the
api_service SSE proxy and frontend chat page already understand
(mirroring run_web_ui_local / client_web_ui_runner).

In addition to streaming, this tool persists task lifecycle to the
api_service so cloud-mode runs are listable via /api/v1/web-ui-tasks
and their R2 artifacts are accessible the same way client_agent runs are:
  - POST /api/v1/web-ui-tasks at start (lazy: as soon as upstream gives
    us a task_id, which is in the artifact/result events).
  - PATCH /api/v1/web-ui-tasks/{task_id} on completion. The api_service
    PATCH handler uploads test_script + final_output (a flattened bug
    summary) to R2 and returns tests_url + bug_report_url; we read those
    out of the response and inject them into the web_ui_bug SSE payload
    so the frontend BugReportArtifact card renders artifact links.

Cloud mode does NOT capture per-step screenshots — testing-web-ui-service's
_on_new_step callback only updates record.steps_done. So screenshot_urls
stays empty for cloud tasks; only the client_agent path produces them.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, AsyncGenerator, Optional

from orchestrator.utils.web_ui_task_api import patch_task, post_task

logger = logging.getLogger(__name__)


def _session_state(ctx: Any) -> dict:
    try:
        return ctx.session.state  # type: ignore[attr-defined]
    except AttributeError:
        return {}


def _invocation_id(ctx: Any) -> str:
    return getattr(ctx, "invocation_id", "") or ""


def _service_url() -> str:
    # Helm values point this at .../agent/run on the in-cluster service.
    return os.getenv(
        "WEB_UI_TESTING_SERVICE_URL",
        "http://argus-testing-web-ui-service:8002/agent/run",
    )


def _resolve_api_base() -> Optional[str]:
    """Return the api_service base URL if available, else None.

    Late import: server.py loads as __main__ in production, so the symbol
    only resolves at call time. In unit tests where server is not on
    sys.path, we return None and skip persistence — the tool still streams
    correctly, just without DB/R2 side-effects.
    """
    try:
        from server import API_SERVICE_URL  # type: ignore  # noqa: PLC0415
    except ImportError:
        return None
    if not API_SERVICE_URL:
        return None
    return API_SERVICE_URL.rstrip("/")


_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _format_bug_report(bugs: list, bug_counts: dict, url: str) -> str:
    """Flatten the upstream bugs[] array into a human-readable text block
    suitable for storing as bug_report.txt on R2.

    Format mirrors the testing-web-ui-service inline summary log so
    operators reading the report can correlate with the SSE stream.
    """
    if not bugs and not bug_counts:
        return ""

    lines: list[str] = []
    lines.append(f"Web UI Test — Bug Report")
    lines.append(f"Target: {url}")
    lines.append("")
    lines.append(
        "Counts — "
        + ", ".join(
            f"{sev.capitalize()}: {int(bug_counts.get(sev, 0) or 0)}"
            for sev in _SEVERITY_ORDER
        )
    )
    lines.append("")

    if not bugs:
        return "\n".join(lines)

    by_sev: dict[str, list[dict]] = {sev: [] for sev in _SEVERITY_ORDER}
    other: list[dict] = []
    for b in bugs:
        if not isinstance(b, dict):
            continue
        sev = str(b.get("severity") or "").lower()
        (by_sev[sev] if sev in by_sev else other).append(b)

    for sev in _SEVERITY_ORDER:
        items = by_sev[sev]
        if not items:
            continue
        lines.append(f"## {sev.upper()} ({len(items)})")
        for i, b in enumerate(items, 1):
            title = b.get("title") or b.get("description") or "(no title)"
            lines.append(f"  {i}. {title}")
            steps = b.get("steps_to_reproduce") or b.get("steps")
            if steps:
                if isinstance(steps, list):
                    for step in steps:
                        lines.append(f"     - {step}")
                else:
                    lines.append(f"     {steps}")
        lines.append("")

    if other:
        lines.append(f"## OTHER ({len(other)})")
        for i, b in enumerate(other, 1):
            lines.append(f"  {i}. {b.get('title') or b.get('description') or '(no title)'}")

    return "\n".join(lines).rstrip() + "\n"


async def run_web_ui_cloud(
    *,
    url: str,
    persona: str | None = None,
    max_steps: int = 30,
    auth: dict | None = None,
    ctx: Any,
) -> AsyncGenerator[dict, None]:
    state = _session_state(ctx)
    user_id = state.get("user_id") or ""
    auth_token = state.get("auth_token")
    api_base = _resolve_api_base()

    persona_value = persona or state.get("user_persona") or "new_user"

    session_state: dict[str, Any] = {
        "url": url,
        "max_steps": int(max_steps),
        "headless": True,
        "use_vision": True,
        "user_persona": persona_value,
    }
    if state.get("business_context"):
        session_state["business_context"] = state["business_context"]
    if state.get("browser_model"):
        session_state["llm_model"] = state["browser_model"]
    creds = (auth or {}).get("credentials") or state.get("credentials")
    if isinstance(creds, dict) and creds.get("username"):
        session_state["credentials"] = {
            "username": creds["username"],
            "password": creds.get("password", ""),
        }

    payload = {
        "session_state": session_state,
        "invocation_id": _invocation_id(ctx),
        "user_id": user_id,
    }

    summary: dict[str, Any] = {
        "bugs_found": 0,
        "script_generated": False,
        "task_id": None,
        "status": None,
    }
    fatal_error: str | None = None

    # Streaming-time captures used to persist + backfill on result.
    captured_task_id: Optional[str] = None
    captured_test_script: str = ""
    captured_tests_url: Optional[str] = None
    captured_bug_report_url: Optional[str] = None
    posted = False

    async for sub in _stream_from_cloud_service(_service_url(), payload):
        # POST web_ui_tasks the moment we first see a task_id, so the row
        # exists by the time the result event triggers PATCH below.
        tid = sub.get("task_id")
        if tid and not posted and api_base and user_id:
            await post_task(
                api_base=api_base,
                auth_token=auth_token,
                user_id=user_id,
                body={
                    "id": tid,
                    "target_url": url,
                    "status": "running",
                    "user_persona": (persona_value or "")[:50],
                    "max_steps": int(max_steps),
                    "started_at": datetime.utcnow().isoformat(),
                },
            )
            captured_task_id = tid
            posted = True

        if sub.get("type") == "artifact":
            captured_test_script = sub.get("content") or ""

        # When the result event arrives, finalize via PATCH and capture URLs
        # BEFORE we shape the event into web_ui_bug — so the URLs land on the
        # same payload we yield below.
        if sub.get("type") == "result" and api_base and user_id and (
            captured_task_id or sub.get("task_id")
        ):
            tid_final = captured_task_id or sub.get("task_id")
            assert tid_final  # guaranteed by the and-clause above
            bugs = sub.get("bugs") or []
            bug_counts = sub.get("bug_counts") or {}
            final_output = _format_bug_report(bugs, bug_counts, url)

            patch_body: dict[str, Any] = {
                "status": sub.get("status") or "completed",
                "steps_done": int(sub.get("steps_done") or 0),
                "finished_at": datetime.utcnow().isoformat(),
                "bug_counts": bug_counts,
                "screenshot_urls": [],  # cloud path captures none
            }
            # Only send the script body if upstream actually produced one,
            # otherwise an empty string would still trigger an R2 upload.
            if captured_test_script:
                patch_body["test_script"] = captured_test_script
            if final_output:
                patch_body["final_output"] = final_output

            patch_resp = await patch_task(
                api_base=api_base,
                task_id=tid_final,
                auth_token=auth_token,
                user_id=user_id,
                body=patch_body,
            )
            if isinstance(patch_resp, dict):
                captured_tests_url = patch_resp.get("tests_url") or captured_tests_url
                captured_bug_report_url = (
                    patch_resp.get("bug_report_url") or captured_bug_report_url
                )

        envelope = _shape_event(sub, url=url)
        if envelope is None:
            continue
        et = envelope["event_type"]
        body = envelope["payload"]

        if et == "web_ui_bug":
            # Backfill the R2 URLs returned by the api_service PATCH so the
            # frontend BugReportArtifact card can link to artifacts.
            # screenshot_urls is left as whatever _shape_event extracted from
            # upstream — testing-web-ui-service doesn't emit any in cloud mode
            # so it defaults to [], and we don't override the field in case a
            # future upstream addition does want to populate it.
            if captured_tests_url:
                body["tests_url"] = captured_tests_url
            if captured_bug_report_url:
                body["bug_report_url"] = captured_bug_report_url
            # has_tests reflects the actual presence of an artifact
            body["has_tests"] = bool(captured_tests_url) or body.get("has_tests", False)

            summary["task_id"] = body.get("task_id")
            summary["status"] = body.get("status")
            counts = body.get("bug_counts") or {}
            summary["bugs_found"] = sum(
                int(counts.get(k, 0) or 0)
                for k in ("critical", "high", "medium", "low")
            )
        elif et == "web_ui_artifact":
            summary["script_generated"] = True
        elif et == "error":
            fatal_error = body.get("message") or "cloud Web UI test failed"

        yield {"is_terminal": False, "event_type": et, "payload": body}

    if fatal_error:
        yield {"is_terminal": True, "result": json.dumps(
            {"error": fatal_error, **summary}, default=str)}
    else:
        yield {"is_terminal": True, "result": json.dumps(summary, default=str)}


def _shape_event(raw: dict, *, url: str) -> dict | None:
    """Translate a testing-web-ui-service NDJSON event into the orchestrator's
    {event_type, payload} envelope. Field-name conventions follow
    client_web_ui_runner so the existing SSE serializer, api_service proxy,
    and frontend chat dispatcher all light up unchanged."""
    et = raw.get("type")
    if et == "log":
        msg = raw.get("content") or raw.get("message") or ""
        return {"event_type": "log",
                "payload": {"type": "log", "message": msg}}
    if et == "progress":
        msg = raw.get("content") or ""
        steps = raw.get("steps_done")
        total = raw.get("max_steps")
        if steps is not None and total is not None:
            msg = f"[{steps}/{total}] {msg}"
        return {"event_type": "log",
                "payload": {"type": "log", "message": msg}}
    if et == "artifact":
        return {"event_type": "web_ui_artifact",
                "payload": {
                    "type": "web_ui_artifact",
                    "artifact_type": raw.get("artifact_type", "web_ui_tests"),
                    "name": raw.get("name", ""),
                    "content": raw.get("content", ""),
                    "task_id": raw.get("task_id"),
                    "url": url,
                    "source": "cloud",
                }}
    if et == "result":
        # Re-typed as web_ui_bug so the frontend renders BugReportArtifact
        # (severity-tinted card + screenshot strip + Re-run button). The old
        # event_type=result emitted the same payload but the chat dispatcher
        # had no useful text/content fields and emitted an empty ResultMessage.
        # The planner still gets the dispatch summary via the terminal
        # `is_terminal: True` yield in run_web_ui_cloud(), unaffected.
        return {"event_type": "web_ui_bug",
                "payload": {
                    "type": "web_ui_bug",
                    "task_id": raw.get("task_id"),
                    "url": raw.get("url") or url,
                    "status": raw.get("status", "completed"),
                    "source": "cloud",
                    "bug_counts": raw.get("bug_counts") or {},
                    "has_tests": bool(raw.get("tests_url")
                                       or raw.get("has_tests")),
                    "steps_done": raw.get("steps_done", 0),
                    "final_output": raw.get("final_output") or "",
                    "screenshot_urls": raw.get("screenshot_urls") or [],
                    "tests_url": raw.get("tests_url"),
                    "bug_report_url": raw.get("bug_report_url"),
                }}
    if et == "error":
        return {"event_type": "error",
                "payload": {"type": "error",
                            "message": raw.get("content")
                            or raw.get("message")
                            or "cloud Web UI test errored"}}
    return None


async def _stream_from_cloud_service(
    service_url: str, payload: dict,
) -> AsyncGenerator[dict, None]:
    import httpx

    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("POST", service_url, json=payload) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield {"type": "error",
                           "content": f"testing-web-ui-service "
                                       f"{resp.status_code}: {body!r}"}
                    return
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("data: "):
                        line = line[len("data: "):]
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("non-JSON line from cloud: %r", line)
                        continue
    except Exception as e:
        logger.exception("run_web_ui_cloud upstream failed")
        yield {"type": "error", "content": f"upstream connection failed: {e}"}
