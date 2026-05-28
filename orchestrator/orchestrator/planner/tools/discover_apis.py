"""discover_apis tool — wraps orchestrator.tools.api_discover.dynamic_discovery.

Runs the (sync) crawler in a thread, bridges progress_callback events to
the async generator output, returns a JSON-serializable dict as terminal result.
"""

from __future__ import annotations

import asyncio
import json
import queue
import threading
import traceback
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

from orchestrator.tools import api_discover


async def discover_apis(
    *, url: str, auth: dict | None = None, ctx: Any
) -> AsyncGenerator[dict, None]:
    parsed = urlparse(url)
    domain = parsed.netloc

    auth_cfg = api_discover.AuthConfig(
        mode=(auth or {}).get("mode", "none"),
        cookie=(auth or {}).get("cookie"),
        jwt=(auth or {}).get("jwt"),
        username=(auth or {}).get("username"),
        password=(auth or {}).get("password"),
        login_url=(auth or {}).get("login_url"),
        login_button_text=(auth or {}).get("login_button_text"),
    )

    progress_queue: queue.Queue = queue.Queue()
    dynamic_result: dict[str, Any] = {"result": None, "error": None}

    def progress_callback(stage: str, message: str, data: dict):
        progress_queue.put({"stage": stage, "message": message, "data": data})

    def run_discovery():
        try:
            dynamic_result["result"] = api_discover.dynamic_discovery(
                base_url=url,
                auth=auth_cfg,
                progress_callback=progress_callback,
                max_response_chars=2000,
            )
        except Exception as e:
            dynamic_result["error"] = e
        finally:
            progress_queue.put(None)

    t = threading.Thread(target=run_discovery, daemon=True)
    t.start()

    while True:
        try:
            item = progress_queue.get_nowait()
            if item is None:
                break
            yield {
                "is_terminal": False,
                "event_type": "log",
                "payload": {
                    "type": "log",
                    "category": "discovery_progress",
                    "stage": item["stage"],
                    "message": item["message"],
                    "data": item["data"],
                },
            }
        except queue.Empty:
            if not t.is_alive():
                break
            await asyncio.sleep(0.1)

    t.join(timeout=5)

    if dynamic_result["error"]:
        yield {
            "is_terminal": True,
            "result": json.dumps({
                "error": f"Discovery failed: {dynamic_result['error']}",
                "apis": [],
            }),
        }
        return

    raw = dynamic_result["result"] or {"requests": []}
    apis = api_discover.filter_dynamic_requests_by_domain({"dynamic": raw}, domain)

    is_api_doc = any(
        "swagger" in a.get("url", "").lower()
        or "openapi" in a.get("url", "").lower()
        or "api-docs" in a.get("url", "").lower()
        for a in apis
    )

    yield {
        "is_terminal": True,
        "result": json.dumps({
            "apis": apis,
            "domain": domain,
            "is_api_doc": is_api_doc,
            "count": len(apis),
        }, default=str),
    }
