"""Organization + membership endpoints (Phase Y2 of the multi-tenant rollout).

See docs/superpowers/specs/2026-05-11-multi-tenant-organizations-design.md
for the full design. This module ships the customer-facing surface for:

  - listing the orgs the caller is a member of
  - creating new orgs (caller becomes OWNER)
  - viewing org details
  - viewing / managing members + roles
  - patching org name / contact_email / metadata
  - soft-deleting (OWNER only)

What's intentionally NOT here:
  - Multi-token-per-org (Phase Y4)
  - Audit log writes (Phase Y4)
  - Email invitations to non-existent users (Y2 only handles already-registered)
  - Stripe / billing wiring per org (Plan 9+)
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel

from auth import get_current_user
from database import database
from models import UserResponse
from redteam.audit import log_audit, list_audit_logs

logger = logging.getLogger("Organizations")

router = APIRouter(prefix="/organizations", tags=["Organizations"])


# ─── Models ────────────────────────────────────────────────────────────────


class OrganizationCreate(BaseModel):
    name: str
    contact_email: Optional[str] = None
    plan_tier: str = "free"


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    contact_email: Optional[str] = None
    plan_tier: Optional[str] = None
    metadata: Optional[dict] = None


class MemberAdd(BaseModel):
    # Add an EXISTING user to the org. Email-based invitation of unknown users
    # is deferred to Y4 (requires transactional email infrastructure).
    user_email: str
    role: str = "MEMBER"


class MemberRoleUpdate(BaseModel):
    role: str


VALID_ROLES = {"OWNER", "ADMIN", "MEMBER", "VIEWER"}
VALID_PLAN_TIERS = {"free", "team", "enterprise", "design_partner"}
ROLE_ORDER = {"VIEWER": 1, "MEMBER": 2, "ADMIN": 3, "OWNER": 4}


def _slugify(name: str) -> str:
    """Convert "ACME Corp" to "acme-corp"; suffix with random hex on collision."""
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "org"
    return f"{base}-{uuid.uuid4().hex[:6]}"


async def _membership(user_id: str, org_id: str) -> Optional[dict]:
    return await database.fetch_one(
        "SELECT role FROM organization_members WHERE user_id = :u AND organization_id = :o",
        {"u": user_id, "o": org_id},
    )


def _role_gte(actual: str, minimum: str) -> bool:
    return ROLE_ORDER.get(actual, 0) >= ROLE_ORDER.get(minimum, 0)


# ─── Auth helper: require_org_role ─────────────────────────────────────────


def require_org_role(min_role: str):
    """FastAPI dependency factory: gate an endpoint behind org membership +
    minimum role. Used by routes nested under /organizations/{org_id}/..."""
    assert min_role in VALID_ROLES, f"invalid min_role: {min_role}"

    async def _check(
        org_id: str,
        current_user: UserResponse = Depends(get_current_user),
    ) -> dict:
        member = await _membership(str(current_user.id), org_id)
        if not member:
            raise HTTPException(status_code=403, detail="Not a member of this organization")
        if not _role_gte(member["role"], min_role):
            raise HTTPException(
                status_code=403,
                detail=f"Requires role {min_role} or higher; you are {member['role']}",
            )
        return {
            "user_id": str(current_user.id),
            "organization_id": org_id,
            "role": member["role"],
        }

    return _check


# ─── Organization CRUD ─────────────────────────────────────────────────────


@router.get("")
async def list_my_organizations(current_user: UserResponse = Depends(get_current_user)) -> list[dict]:
    """List organizations the caller is a member of, with their role."""
    rows = await database.fetch_all(
        """
        SELECT o.id, o.name, o.slug, o.contact_email, o.plan_tier, o.metadata,
               o.is_active, o.created_at, om.role
        FROM organization_members om
        JOIN organizations o ON o.id = om.organization_id
        WHERE om.user_id = :uid AND o.is_active = TRUE
        ORDER BY om.joined_at ASC
        """,
        {"uid": str(current_user.id)},
    )
    return [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "slug": r["slug"],
            "contact_email": r["contact_email"],
            "plan_tier": r["plan_tier"],
            "metadata": r["metadata"] or {},
            "role": r["role"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@router.post("")
async def create_organization(
    data: OrganizationCreate,
    current_user: UserResponse = Depends(get_current_user),
) -> dict:
    """Create a new organization. Caller becomes OWNER."""
    if data.plan_tier not in VALID_PLAN_TIERS:
        raise HTTPException(400, f"Invalid plan_tier. Must be one of: {VALID_PLAN_TIERS}")
    if not data.name.strip():
        raise HTTPException(400, "name cannot be empty")

    org_id = str(uuid.uuid4())
    slug = _slugify(data.name)
    await database.execute(
        """INSERT INTO organizations (id, name, slug, contact_email, plan_tier, metadata)
           VALUES (:id, :name, :slug, :ce, :pt, '{}'::jsonb)""",
        {
            "id": org_id,
            "name": data.name.strip(),
            "slug": slug,
            "ce": data.contact_email,
            "pt": data.plan_tier,
        },
    )
    await database.execute(
        """INSERT INTO organization_members (organization_id, user_id, role)
           VALUES (:o, :u, 'OWNER'::org_member_role)""",
        {"o": org_id, "u": str(current_user.id)},
    )
    logger.info(f"User {current_user.id} created org {org_id} ({slug})")
    return {"id": org_id, "slug": slug, "name": data.name, "role": "OWNER"}


@router.get("/{org_id}")
async def get_organization(
    org_id: str,
    membership: dict = Depends(require_org_role("VIEWER")),
) -> dict:
    """Get organization details. Any member can view."""
    org = await database.fetch_one(
        "SELECT * FROM organizations WHERE id = :id AND is_active = TRUE",
        {"id": org_id},
    )
    if not org:
        raise HTTPException(404, "Organization not found")
    count_row = await database.fetch_one(
        "SELECT COUNT(*) AS c FROM organization_members WHERE organization_id = :o",
        {"o": org_id},
    )
    member_count = count_row["c"] if count_row else 0
    return {
        "id": str(org["id"]),
        "name": org["name"],
        "slug": org["slug"],
        "contact_email": org["contact_email"],
        "plan_tier": org["plan_tier"],
        "metadata": org["metadata"] or {},
        "is_active": org["is_active"],
        "created_at": org["created_at"].isoformat() if org["created_at"] else None,
        "member_count": member_count,
        "my_role": membership["role"],
    }


@router.patch("/{org_id}")
async def update_organization(
    org_id: str,
    data: OrganizationUpdate,
    membership: dict = Depends(require_org_role("ADMIN")),
) -> dict:
    """Update org attributes. ADMIN or OWNER. plan_tier requires OWNER."""
    fields = {}
    if data.name is not None:
        if not data.name.strip():
            raise HTTPException(400, "name cannot be empty")
        fields["name"] = data.name.strip()
    if data.contact_email is not None:
        fields["contact_email"] = data.contact_email
    if data.metadata is not None:
        # JSONB merge via PG operator; use plain SET for simplicity here
        import json as _json
        fields["metadata"] = _json.dumps(data.metadata)
    if data.plan_tier is not None:
        if data.plan_tier not in VALID_PLAN_TIERS:
            raise HTTPException(400, f"Invalid plan_tier. Must be one of: {VALID_PLAN_TIERS}")
        if membership["role"] != "OWNER":
            raise HTTPException(403, "Only OWNER can change plan_tier")
        fields["plan_tier"] = data.plan_tier
    if not fields:
        raise HTTPException(400, "No fields to update")
    set_parts = ", ".join(f"{k} = :{k}" for k in fields)
    set_parts += ", updated_at = NOW()"
    await database.execute(
        f"UPDATE organizations SET {set_parts} WHERE id = :id",
        {**fields, "id": org_id},
    )
    return {"message": "Organization updated", "updated_fields": list(fields.keys())}


@router.delete("/{org_id}")
async def soft_delete_organization(
    org_id: str,
    membership: dict = Depends(require_org_role("OWNER")),
) -> dict:
    """Soft-delete (sets is_active=false). Hard-delete via DB after 14 days; not yet automated."""
    await database.execute(
        "UPDATE organizations SET is_active = FALSE, updated_at = NOW() WHERE id = :id",
        {"id": org_id},
    )
    logger.warning(f"User {membership['user_id']} soft-deleted org {org_id}")
    return {"message": "Organization soft-deleted"}


# ─── Members ───────────────────────────────────────────────────────────────


@router.get("/{org_id}/members")
async def list_members(
    org_id: str,
    membership: dict = Depends(require_org_role("VIEWER")),
) -> list[dict]:
    rows = await database.fetch_all(
        """
        SELECT om.id, om.user_id, om.role, om.joined_at,
               u.username, u.email, u.display_name
        FROM organization_members om
        JOIN users u ON u.id = om.user_id
        WHERE om.organization_id = :o
        ORDER BY om.joined_at ASC
        """,
        {"o": org_id},
    )
    return [
        {
            "id": str(r["id"]),
            "user_id": str(r["user_id"]),
            "username": r["username"],
            "email": r["email"],
            "display_name": r["display_name"],
            "role": r["role"],
            "joined_at": r["joined_at"].isoformat() if r["joined_at"] else None,
        }
        for r in rows
    ]


@router.post("/{org_id}/members")
async def add_member(
    org_id: str,
    data: MemberAdd,
    membership: dict = Depends(require_org_role("ADMIN")),
) -> dict:
    """Add an existing user by email. Email-invite to unknown users deferred to Y4."""
    if data.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {VALID_ROLES}")
    if data.role == "OWNER":
        raise HTTPException(400, "Cannot add as OWNER via this endpoint; use PATCH to promote")

    target = await database.fetch_one(
        "SELECT id FROM users WHERE LOWER(email) = LOWER(:e)",
        {"e": data.user_email.strip()},
    )
    if not target:
        raise HTTPException(
            404,
            f"No user found with email {data.user_email!r}. "
            "Email-invite to non-registered users is not yet supported — "
            "create the user via /admin/users first, then add them.",
        )

    existing = await database.fetch_one(
        "SELECT id FROM organization_members WHERE organization_id = :o AND user_id = :u",
        {"o": org_id, "u": str(target["id"])},
    )
    if existing:
        raise HTTPException(409, "User is already a member of this organization")

    await database.execute(
        """INSERT INTO organization_members (organization_id, user_id, role, invited_by)
           VALUES (:o, :u, CAST(:r AS org_member_role), :ib)""",
        {"o": org_id, "u": str(target["id"]), "r": data.role, "ib": membership["user_id"]},
    )
    await log_audit(
        action="member_added",
        organization_id=org_id,
        user_id=membership["user_id"],
        resource_type="organization_member",
        resource_id=str(target["id"]),
        metadata={"added_email": data.user_email, "role": data.role},
    )
    return {"message": f"Added {data.user_email} as {data.role}"}


@router.patch("/{org_id}/members/{user_id}")
async def update_member_role(
    org_id: str,
    user_id: str,
    data: MemberRoleUpdate,
    membership: dict = Depends(require_org_role("OWNER")),
) -> dict:
    if data.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {VALID_ROLES}")

    target = await database.fetch_one(
        "SELECT role FROM organization_members WHERE organization_id = :o AND user_id = :u",
        {"o": org_id, "u": user_id},
    )
    if not target:
        raise HTTPException(404, "Member not found")

    # Enforce: cannot demote the last OWNER
    if target["role"] == "OWNER" and data.role != "OWNER":
        owner_count = (
            await database.fetch_one(
                "SELECT COUNT(*) AS c FROM organization_members WHERE organization_id = :o AND role = 'OWNER'",
                {"o": org_id},
            )
        )["c"]
        if owner_count <= 1:
            raise HTTPException(400, "Cannot demote the last OWNER")

    await database.execute(
        "UPDATE organization_members SET role = CAST(:r AS org_member_role) WHERE organization_id = :o AND user_id = :u",
        {"o": org_id, "u": user_id, "r": data.role},
    )
    await log_audit(
        action="member_role_changed",
        organization_id=org_id,
        user_id=membership["user_id"],
        resource_type="organization_member",
        resource_id=user_id,
        metadata={"from_role": target["role"], "to_role": data.role},
    )
    return {"message": f"Member role updated to {data.role}"}


@router.delete("/{org_id}/members/{user_id}")
async def remove_member(
    org_id: str,
    user_id: str,
    membership: dict = Depends(require_org_role("ADMIN")),
) -> dict:
    target = await database.fetch_one(
        "SELECT role FROM organization_members WHERE organization_id = :o AND user_id = :u",
        {"o": org_id, "u": user_id},
    )
    if not target:
        raise HTTPException(404, "Member not found")

    if target["role"] == "OWNER":
        owner_count = (
            await database.fetch_one(
                "SELECT COUNT(*) AS c FROM organization_members WHERE organization_id = :o AND role = 'OWNER'",
                {"o": org_id},
            )
        )["c"]
        if owner_count <= 1:
            raise HTTPException(400, "Cannot remove the last OWNER")

    await database.execute(
        "DELETE FROM organization_members WHERE organization_id = :o AND user_id = :u",
        {"o": org_id, "u": user_id},
    )
    await log_audit(
        action="member_removed",
        organization_id=org_id,
        user_id=membership["user_id"],
        resource_type="organization_member",
        resource_id=user_id,
        metadata={"removed_role": target["role"]},
    )
    return {"message": "Member removed"}


# ─── Audit log read endpoint ───────────────────────────────────────────────


@router.get("/{org_id}/audit-logs")
async def get_org_audit_logs(
    org_id: str,
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    membership: dict = Depends(require_org_role("ADMIN")),
) -> dict:
    """View org's audit log. ADMIN+ only — VIEWER/MEMBER can't see who's done what."""
    logs = await list_audit_logs(
        organization_id=org_id,
        action=action,
        limit=limit,
        offset=offset,
    )
    return {
        "organization_id": org_id,
        "limit": limit,
        "offset": offset,
        "logs": logs,
    }
