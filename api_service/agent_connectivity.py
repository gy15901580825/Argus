"""Read-only connectivity checks for the wizard bound_context.

Queries the client_agent table for a recent online heartbeat; HEAD-pings the CDP
URL if the user provided one. Both are best-effort; failures return False, not
raise, because these are UX hints, not hard errors."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from database import database

logger = logging.getLogger(__name__)

_HEARTBEAT_WINDOW = timedelta(seconds=60)


async def check_client_agent_connected(user_id) -> bool:
    # client_agent schema: (user_id, status, updated_at, ...). The orchestrator
    # WebSocket hub flips status to 'online'/'offline' and refreshes updated_at
    # on every heartbeat — so a connected agent looks like status='online' with
    # updated_at inside the heartbeat window.
    try:
        row = await database.fetch_one(
            "SELECT status, updated_at FROM client_agent "
            "WHERE user_id = :uid ORDER BY updated_at DESC LIMIT 1",
            {"uid": str(user_id)},
        )
    except Exception:
        logger.warning("client_agent connectivity check failed", exc_info=True)
        return False
    if not row:
        return False
    status = row["status"]
    last = row["updated_at"]
    if last is None or status != "online":
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last < _HEARTBEAT_WINDOW


async def check_cdp_reachable(user_id, cdp_url: Optional[str]) -> bool:
    if not cdp_url:
        return False
    version_url = cdp_url.rstrip("/") + "/json/version"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(version_url)
            return r.status_code == 200
    except httpx.HTTPError:
        return False
