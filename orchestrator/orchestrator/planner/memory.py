"""Planner chat history loader.

Queries api_service's /chat/sessions/{id}/planner-history endpoint for up to N
prior core-summary turns. Returns a compact list of {"role", "content"} dicts
suitable for direct inclusion in Anthropic `messages`.

Fails open: on any error (timeout, non-2xx, malformed JSON), returns [] so the
planner starts cold. Treated as "no history" rather than a hard failure.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_MAX_CONTENT_CHARS = 500


async def load_core_history(
    *,
    session_id: str,
    user_id: str,
    limit: int,
    api_service_base_url: str,
    service_secret: str,
    timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Return up to `limit * 2` messages (N pairs) or [] on failure."""
    url = f"{api_service_base_url}/chat/sessions/{session_id}/planner-history"
    params = {"limit": limit}
    headers = {
        "x-user-id": user_id,
        "x-service-secret": service_secret,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params, headers=headers)
        if resp.status_code != 200:
            logger.warning(
                "planner-history %s returned %s; starting planner with empty history",
                session_id, resp.status_code,
            )
            return []
        data = resp.json()
        messages = data.get("messages", [])
        cleaned: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role")
            content = m.get("content", "")
            if role not in ("user", "assistant"):
                continue
            if not isinstance(content, str):
                continue
            cleaned.append({"role": role, "content": content[:_MAX_CONTENT_CHARS]})
        return cleaned
    except Exception as e:
        logger.warning("planner-history fetch failed: %s; starting cold", e)
        return []
