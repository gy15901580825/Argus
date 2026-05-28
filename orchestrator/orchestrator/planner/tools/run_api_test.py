"""run_api_test tool — execute pytest against discovered APIs.

Dispatch rule:
  - if `remote` is provided with all 3 fields → SSH path
  - else → in-cluster test-runner path (POST to API_TESTING_SERVICE_URL)

Internal helpers _run_via_test_runner / _run_via_ssh are also tested
independently and can be swapped via patching.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, AsyncGenerator

logger = logging.getLogger(__name__)


async def run_api_test(
    *,
    apis: list[dict] | str,
    auth: dict | None = None,
    remote: dict | None = None,
    ctx: Any,
) -> AsyncGenerator[dict, None]:
    use_ssh = bool(
        remote
        and remote.get("host")
        and remote.get("username")
        and remote.get("pem_key_base64")
    )

    final_summary: dict[str, Any] = {"success": False, "stdout": "", "stderr": ""}

    runner = _run_via_ssh if use_ssh else _run_via_test_runner
    runner_kwargs = dict(apis=apis, auth=auth)
    if use_ssh:
        runner_kwargs["remote"] = remote

    async for sub in runner(**runner_kwargs):
        et = sub.get("event_type")
        if et == "ssh_result":
            final_summary = sub["payload"]
        yield {"is_terminal": False, **sub}

    yield {"is_terminal": True, "result": json.dumps(final_summary, default=str)}


async def _run_via_test_runner(
    *, apis, auth
) -> AsyncGenerator[dict, None]:
    """Call in-cluster testing_api_service to run pytest. Yields SSE sub-events."""
    import httpx

    base = os.getenv("API_TESTING_SERVICE_URL", "http://testing-api-service:8000")
    payload = {"apis": apis, "auth": auth or {}}
    yield {"event_type": "progress", "payload": {
        "type": "progress", "stage": "api_test_start", "message": "Dispatching to test-runner"}}
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", f"{base}/run-pytest", json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                try:
                    obj = json.loads(line[6:])
                except Exception:
                    continue
                yield {"event_type": obj.get("type", "log"), "payload": obj}


async def _run_via_ssh(
    *, apis, auth, remote
) -> AsyncGenerator[dict, None]:
    """Call in-cluster testing_api_service with SSH delegation config."""
    import httpx

    base = os.getenv("API_TESTING_SERVICE_URL", "http://testing-api-service:8000")
    payload = {"apis": apis, "auth": auth or {}, "remote": remote}
    yield {"event_type": "progress", "payload": {
        "type": "progress", "stage": "api_test_ssh_start",
        "message": f"Dispatching to SSH host {remote['host']}"}}
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("POST", f"{base}/run-pytest-ssh", json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                try:
                    obj = json.loads(line[6:])
                except Exception:
                    continue
                yield {"event_type": obj.get("type", "log"), "payload": obj}
