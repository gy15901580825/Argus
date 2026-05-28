"""Audit log shim — fire-and-forget writes to the audit_logs table.

Phase Y4 of the multi-tenant spec. Every state-changing admin or org action
calls log_audit() with the caller, the action verb, the resource it touched,
and any structured metadata worth keeping (severity excerpts, etc).

Design principles:
  - NEVER block the request: a failed audit insert logs to stderr and returns.
    Customer-facing latency must not depend on this table.
  - The table is queried by /api/v1/admin/organizations/{id}/audit-logs and
    /api/v1/organizations/{id}/audit-logs (Y4 admin viewer); ad-hoc psql is
    the escape hatch.
  - Schema is intentionally loose (action + resource_type + jsonb metadata)
    so new actions don't need migrations.
"""
from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from database import database

logger = logging.getLogger("audit")


async def log_audit(
    *,
    action: str,
    organization_id: Optional[str] = None,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Insert a single audit-log row. Errors are swallowed (logged to stderr)."""
    import json
    try:
        # The `databases` library can't disambiguate `:param::cast` (it tries
        # to bind a parameter named "param" but the trailing `::jsonb` syntax
        # breaks the parser). Use CAST() instead.
        await database.execute(
            """INSERT INTO audit_logs
                (organization_id, user_id, action, resource_type, resource_id, metadata)
               VALUES (:org, :uid, :a, :rt, :rid, CAST(:m AS jsonb))""",
            {
                "org": str(organization_id) if organization_id else None,
                "uid": str(user_id) if user_id else None,
                "a": action,
                "rt": resource_type,
                "rid": str(resource_id) if resource_id else None,
                "m": json.dumps(metadata or {}),
            },
        )
    except Exception as e:
        # Stderr is the safety net so we can grep audit failures later.
        logger.warning(
            "AUDIT_WRITE_FAILED action=%s org=%s user=%s err=%s",
            action, organization_id, user_id, e,
        )


async def list_audit_logs(
    *,
    organization_id: Optional[str] = None,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Query audit logs with simple filters. Caller is responsible for
    permission checks (e.g. require_org_role('ADMIN'))."""
    where = []
    params: dict = {"lim": min(limit, 200), "off": offset}
    if organization_id:
        where.append("organization_id = :org")
        params["org"] = organization_id
    if user_id:
        where.append("user_id = :uid")
        params["uid"] = user_id
    if action:
        where.append("action = :a")
        params["a"] = action
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = await database.fetch_all(
        f"""
        SELECT id, organization_id, user_id, action, resource_type, resource_id,
               metadata, created_at
        FROM audit_logs
        {where_sql}
        ORDER BY created_at DESC
        LIMIT :lim OFFSET :off
        """,
        params,
    )
    return [
        {
            "id": str(r["id"]),
            "organization_id": str(r["organization_id"]) if r["organization_id"] else None,
            "user_id": str(r["user_id"]) if r["user_id"] else None,
            "action": r["action"],
            "resource_type": r["resource_type"],
            "resource_id": str(r["resource_id"]) if r["resource_id"] else None,
            "metadata": r["metadata"] or {},
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]
