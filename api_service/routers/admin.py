import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from database import database
from auth import require_admin
from models import UserResponse
from graph_api import create_ciam_user, update_ciam_user, delete_ciam_user
from subscription_period import ensure_active_period
from redteam.audit import log_audit

logger = logging.getLogger("Admin")

router = APIRouter(prefix="/admin")


class UserListItem(BaseModel):
    id: str
    username: str
    email: str
    display_name: Optional[str] = None
    role: str
    is_active: bool
    plan: Optional[str] = None
    terms_accepted_at: Optional[str] = None
    created_at: str
    updated_at: str


class UserCreate(BaseModel):
    username: str
    email: str
    display_name: Optional[str] = None
    role: str = "ORDINARY_USER"
    # When True, skip the Azure CIAM directory write and only create the DB
    # user + mint an api_token. Use for design-partner customers who don't
    # need web-UI login and only consume the API via CLI / CI.
    api_token_only: bool = False


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserPlanUpdate(BaseModel):
    plan: str  # 'free', 'starter', 'pro'


VALID_ROLES = {"ORDINARY_USER", "CONTENT_ADMIN", "SUPER_ADMIN"}
VALID_PLANS = {"free", "starter", "pro"}


@router.get("/users")
async def list_users(current_user: UserResponse = Depends(require_admin)):
    """List all users with their subscription plan."""
    query = """
        SELECT u.id, u.username, u.email, u.display_name, u.role, u.is_active,
               u.terms_accepted_at, u.created_at, u.updated_at,
               COALESCE(s.plan_id, 'free') AS plan
        FROM users u
        LEFT JOIN subscriptions s ON s.user_id = u.id
            AND s.status IN ('active', 'trialing', 'past_due')
        ORDER BY u.created_at DESC
    """
    rows = await database.fetch_all(query=query)
    return [
        UserListItem(
            id=str(r["id"]),
            username=r["username"],
            email=r["email"],
            display_name=r["display_name"],
            role=r["role"],
            is_active=r["is_active"],
            plan=r["plan"],
            terms_accepted_at=r["terms_accepted_at"].isoformat() if r["terms_accepted_at"] else None,
            created_at=r["created_at"].isoformat(),
            updated_at=r["updated_at"].isoformat(),
        )
        for r in rows
    ]


@router.post("/users")
async def create_user_endpoint(
    data: UserCreate,
    current_user: UserResponse = Depends(require_admin),
):
    """Create a new user in both DB and Azure CIAM."""
    if data.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {VALID_ROLES}")

    # Check uniqueness in DB
    existing = await database.fetch_one(
        "SELECT id FROM users WHERE username = :u OR email = :e",
        {"u": data.username, "e": data.email},
    )
    if existing:
        raise HTTPException(409, "Username or email already exists")

    import secrets
    import uuid as _uuid
    api_token = secrets.token_urlsafe(32)

    if data.api_token_only:
        # API-only user (typical design-partner shape). Skip CIAM entirely;
        # generate a local UUID for the DB primary key.
        new_user_id = str(_uuid.uuid4())
        await database.execute(
            """INSERT INTO users (id, username, email, display_name, api_token, role, is_active, created_at, updated_at)
               VALUES (:id, :username, :email, :display_name, :api_token, :role, true, NOW(), NOW())""",
            {
                "id": new_user_id,
                "username": data.username,
                "email": data.email,
                "display_name": data.display_name,
                "api_token": api_token,
                "role": data.role,
            },
        )
        logger.info(f"Admin {current_user.id} created api-only user {new_user_id}")
        return {
            "id": new_user_id,
            "api_token": api_token,
            "message": "User created (api-token-only mode; no CIAM sync). Save this token — it will not be shown again.",
        }

    # 1. Create user in Azure CIAM first
    display_name = data.display_name or data.username
    ciam_user = await create_ciam_user(display_name=display_name, email=data.email)
    if not ciam_user:
        raise HTTPException(502, "Failed to create user in Azure CIAM. The email may already exist in the directory.")

    ciam_user_id = ciam_user["id"]

    # 2. Create user in DB with CIAM oid as the primary key
    await database.execute(
        """INSERT INTO users (id, username, email, display_name, api_token, role, is_active, created_at, updated_at)
           VALUES (:id, :username, :email, :display_name, :api_token, :role, true, NOW(), NOW())""",
        {
            "id": ciam_user_id,
            "username": data.username,
            "email": data.email,
            "display_name": data.display_name,
            "api_token": api_token,
            "role": data.role,
        },
    )
    logger.info(f"Admin {current_user.id} created user {ciam_user_id} (synced to CIAM)")
    return {"id": ciam_user_id, "api_token": api_token, "message": "User created (synced to Azure CIAM). Save this token — it will not be shown again."}


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    data: UserUpdate,
    current_user: UserResponse = Depends(require_admin),
):
    """Update a user's info in both DB and Azure CIAM."""
    if data.role is not None and data.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {VALID_ROLES}")

    fields = {}
    if data.username is not None:
        fields["username"] = data.username.strip()
    if data.email is not None:
        fields["email"] = data.email.strip()
    if data.display_name is not None:
        fields["display_name"] = data.display_name.strip() or None
    if data.role is not None:
        fields["role"] = data.role
    if data.is_active is not None:
        fields["is_active"] = data.is_active

    if not fields:
        raise HTTPException(400, "No fields to update")

    # Uniqueness checks
    if "username" in fields:
        dup = await database.fetch_one(
            "SELECT id FROM users WHERE username = :u AND id != :uid",
            {"u": fields["username"], "uid": user_id},
        )
        if dup:
            raise HTTPException(409, "Username already taken")

    if "email" in fields:
        dup = await database.fetch_one(
            "SELECT id FROM users WHERE email = :e AND id != :uid",
            {"e": fields["email"], "uid": user_id},
        )
        if dup:
            raise HTTPException(409, "Email already in use")

    # Sync to Azure CIAM (displayName, accountEnabled)
    ciam_updates = {}
    if "display_name" in fields:
        ciam_updates["display_name"] = fields["display_name"] or fields.get("username", "")
    if "is_active" in fields:
        ciam_updates["is_active"] = fields["is_active"]
    if ciam_updates:
        synced = await update_ciam_user(user_id, ciam_updates)
        if not synced:
            logger.warning(f"CIAM sync failed for user {user_id}, DB update will proceed")

    # Update DB
    set_parts = [f"{k} = :{k}" for k in fields]
    set_parts.append("updated_at = NOW()")
    set_clause = ", ".join(set_parts)

    await database.execute(
        f"UPDATE users SET {set_clause} WHERE id = :uid",
        {**fields, "uid": user_id},
    )
    logger.info(f"Admin {current_user.id} updated user {user_id}: {list(fields.keys())}")
    return {"message": "User updated (synced to Azure CIAM)"}


@router.delete("/users/{user_id}")
async def delete_user_endpoint(
    user_id: str,
    current_user: UserResponse = Depends(require_admin),
):
    """Delete a user from both DB and Azure CIAM."""
    if str(current_user.id) == user_id:
        raise HTTPException(400, "Cannot delete your own account")

    # 1. Delete from Azure CIAM
    ciam_deleted = await delete_ciam_user(user_id)
    if not ciam_deleted:
        logger.warning(f"CIAM delete failed for user {user_id}, proceeding with DB delete")

    # 2. Clean up all related DB data (order matters for FK constraints)
    related_tables = [
        ("comments", "user_id"),
        ("scripts", "owner_id"),
        ("blogs", "author_id"),
        ("documents", "owner_id"),
        ("chat_sessions", "user_id"),
        ("client_agent", "user_id"),
        ("user_trials", "user_id"),
        ("ai_token_usage", "user_id"),
        ("ai_token_usage_summary", "user_id"),
        ("subscriptions", "user_id"),
        ("usage_quotas", "user_id"),
    ]
    for table, col in related_tables:
        await database.execute(f"DELETE FROM {table} WHERE {col} = :uid", {"uid": user_id})

    await database.execute("DELETE FROM users WHERE id = :uid", {"uid": user_id})
    logger.info(f"Admin {current_user.id} deleted user {user_id} (synced to CIAM)")
    return {"message": "User deleted (synced to Azure CIAM)"}


@router.patch("/users/{user_id}/plan")
async def update_user_plan(
    user_id: str,
    data: UserPlanUpdate,
    current_user: UserResponse = Depends(require_admin),
):
    """Assign a subscription plan to a user (admin override, bypasses Stripe)."""
    if data.plan not in VALID_PLANS:
        raise HTTPException(400, f"Invalid plan. Must be one of: {VALID_PLANS}")

    # Verify plan exists
    plan_row = await database.fetch_one(
        "SELECT id, test_cases_limit FROM subscription_plans WHERE id = :plan",
        {"plan": data.plan},
    )
    if not plan_row:
        raise HTTPException(404, f"Plan '{data.plan}' not found")

    # Verify user exists
    user = await database.fetch_one("SELECT id FROM users WHERE id = :uid", {"uid": user_id})
    if not user:
        raise HTTPException(404, "User not found")

    # Upsert subscription
    existing = await database.fetch_one(
        "SELECT id FROM subscriptions WHERE user_id = :uid",
        {"uid": user_id},
    )

    import uuid
    from datetime import datetime
    from dateutil.relativedelta import relativedelta

    now = datetime.utcnow()
    # Admin-granted plans use a normal monthly cycle. They're not billed
    # via Stripe, so subscription_period.ensure_active_period auto-advances
    # the period each month.
    period_end = now + relativedelta(months=1)

    if existing:
        await database.execute(
            """UPDATE subscriptions
               SET plan_id = :plan, status = 'active',
                   stripe_subscription_id = NULL,
                   current_period_start = :now, current_period_end = :period_end,
                   cancel_at_period_end = false, updated_at = :now
               WHERE user_id = :uid""",
            {"plan": data.plan, "uid": user_id, "now": now, "period_end": period_end},
        )
    else:
        await database.execute(
            """INSERT INTO subscriptions (id, user_id, plan_id, status,
                   current_period_start, current_period_end, created_at, updated_at)
               VALUES (:id, :uid, :plan, 'active', :now, :period_end, :now, :now)""",
            {
                "id": str(uuid.uuid4()),
                "uid": user_id,
                "plan": data.plan,
                "now": now,
                "period_end": period_end,
            },
        )

    # Upsert usage quota for current period
    test_limit = plan_row["test_cases_limit"]
    period_start, quota_end, _plan = await ensure_active_period(user_id)

    existing_quota = await database.fetch_one(
        """SELECT id FROM usage_quotas
           WHERE user_id = :uid AND period_start = :ps""",
        {"uid": user_id, "ps": period_start},
    )
    if existing_quota:
        await database.execute(
            """UPDATE usage_quotas SET test_cases_limit = :lim, updated_at = :now
               WHERE user_id = :uid AND period_start = :ps""",
            {"lim": test_limit, "now": now, "uid": user_id, "ps": period_start},
        )
    else:
        await database.execute(
            """INSERT INTO usage_quotas (id, user_id, period_start, period_end,
                   test_cases_used, test_cases_limit, created_at, updated_at)
               VALUES (:id, :uid, :ps, :pe, 0, :lim, :now, :now)""",
            {
                "id": str(uuid.uuid4()),
                "uid": user_id,
                "ps": period_start,
                "pe": quota_end,
                "lim": test_limit,
                "now": now,
            },
        )

    logger.info(f"Admin {current_user.id} set user {user_id} plan to '{data.plan}'")
    return {"message": f"Plan updated to '{data.plan}'"}


# ─── Token issuance / rotation / runs view ──────────────────────────────────


@router.get("/users/{user_id}/api-token")
async def reveal_user_api_token(
    user_id: str,
    current_user: UserResponse = Depends(require_admin),
):
    """Reveal a user's current api_token. Audit-logged; admins only.

    Operators run this when a design-partner customer reports they've lost
    the token from the welcome email and need it again. Each reveal is
    written to the application log with caller + target IDs so we can review
    later who looked at what.
    """
    row = await database.fetch_one(
        "SELECT id, email, api_token FROM users WHERE id = :uid",
        {"uid": user_id},
    )
    if not row:
        raise HTTPException(404, "User not found")
    if not row["api_token"]:
        raise HTTPException(409, "User has no api_token yet (run rotate-token to mint one)")
    logger.warning(
        "TOKEN_REVEAL admin=%s viewed_user=%s viewed_email=%s",
        current_user.id, user_id, row["email"],
    )
    await log_audit(
        action="token_reveal",
        user_id=str(current_user.id),
        resource_type="user_api_token",
        resource_id=user_id,
        metadata={"viewed_user_email": row["email"]},
    )
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "api_token": row["api_token"],
    }


@router.post("/users/{user_id}/rotate-token")
async def rotate_user_api_token(
    user_id: str,
    current_user: UserResponse = Depends(require_admin),
):
    """Mint a fresh api_token for the user; the old one stops working immediately.

    Returns the new token in the response — admin must capture it now and
    pass it to the customer; subsequent GETs of /api-token will also work
    until the next rotate.
    """
    row = await database.fetch_one(
        "SELECT id, email FROM users WHERE id = :uid",
        {"uid": user_id},
    )
    if not row:
        raise HTTPException(404, "User not found")
    import secrets
    new_token = secrets.token_urlsafe(32)
    await database.execute(
        "UPDATE users SET api_token = :t, updated_at = NOW() WHERE id = :uid",
        {"t": new_token, "uid": user_id},
    )
    logger.warning(
        "TOKEN_ROTATE admin=%s rotated_user=%s rotated_email=%s",
        current_user.id, user_id, row["email"],
    )
    await log_audit(
        action="token_rotate",
        user_id=str(current_user.id),
        resource_type="user_api_token",
        resource_id=user_id,
        metadata={"rotated_user_email": row["email"]},
    )
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "api_token": new_token,
        "message": "Token rotated. The previous token is no longer valid.",
    }


@router.get("/users/{user_id}/redteam-runs")
async def list_user_redteam_runs(
    user_id: str,
    limit: int = 50,
    offset: int = 0,
    current_user: UserResponse = Depends(require_admin),
):
    """List a customer's red-team runs, newest first. Used by the admin UI
    to surface design-partner activity (cadence + finding volume) at a glance."""
    if limit > 200:
        limit = 200
    user = await database.fetch_one("SELECT id, email FROM users WHERE id = :uid", {"uid": user_id})
    if not user:
        raise HTTPException(404, "User not found")
    rows = await database.fetch_all(
        """
        SELECT r.id, r.probe_suite, r.status, r.started_at, r.finished_at,
               r.target_spec->>'kind' AS target_kind,
               (SELECT COUNT(*) FROM redteam_findings f WHERE f.run_id = r.id) AS findings_count,
               (SELECT COUNT(*) FROM redteam_findings f WHERE f.run_id = r.id AND f.verdict = 'fail') AS fails_count
        FROM redteam_runs r
        WHERE r.user_id = :uid
        ORDER BY r.started_at DESC
        LIMIT :lim OFFSET :off
        """,
        {"uid": user_id, "lim": limit, "off": offset},
    )
    total_row = await database.fetch_one(
        "SELECT COUNT(*) AS c FROM redteam_runs WHERE user_id = :uid",
        {"uid": user_id},
    )
    return {
        "user": {"id": str(user["id"]), "email": user["email"]},
        "total": total_row["c"],
        "limit": limit,
        "offset": offset,
        "runs": [
            {
                "id": str(r["id"]),
                "probe_suite": r["probe_suite"],
                "status": r["status"],
                "target_kind": r["target_kind"],
                "started_at": r["started_at"].isoformat() if r["started_at"] else None,
                "finished_at": r["finished_at"].isoformat() if r["finished_at"] else None,
                "findings_count": r["findings_count"],
                "fails_count": r["fails_count"],
            }
            for r in rows
        ],
    }


# ─── Cross-org admin views (Y2) ─────────────────────────────────────────────


@router.get("/organizations")
async def admin_list_organizations(current_user: UserResponse = Depends(require_admin)) -> list[dict]:
    """Platform admin view of all organizations. Different from
    /api/v1/organizations (which only shows ones the caller is a member of)."""
    rows = await database.fetch_all(
        """
        SELECT o.id, o.name, o.slug, o.contact_email, o.plan_tier,
               o.is_active, o.created_at,
               (SELECT COUNT(*) FROM organization_members m WHERE m.organization_id = o.id) AS member_count,
               (SELECT COUNT(*) FROM redteam_runs r WHERE r.organization_id = o.id) AS run_count
        FROM organizations o
        ORDER BY o.created_at DESC
        """
    )
    return [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "slug": r["slug"],
            "contact_email": r["contact_email"],
            "plan_tier": r["plan_tier"],
            "is_active": r["is_active"],
            "member_count": r["member_count"],
            "run_count": r["run_count"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@router.get("/organizations/{org_id}/members")
async def admin_list_org_members(
    org_id: str,
    current_user: UserResponse = Depends(require_admin),
) -> dict:
    """Platform admin view of an org's members (bypasses membership check)."""
    org = await database.fetch_one(
        "SELECT id, name, slug FROM organizations WHERE id = :id",
        {"id": org_id},
    )
    if not org:
        raise HTTPException(404, "Organization not found")
    rows = await database.fetch_all(
        """
        SELECT om.user_id, om.role, om.joined_at,
               u.username, u.email, u.display_name
        FROM organization_members om
        JOIN users u ON u.id = om.user_id
        WHERE om.organization_id = :o
        ORDER BY om.joined_at ASC
        """,
        {"o": org_id},
    )
    return {
        "organization": {"id": str(org["id"]), "name": org["name"], "slug": org["slug"]},
        "members": [
            {
                "user_id": str(r["user_id"]),
                "username": r["username"],
                "email": r["email"],
                "display_name": r["display_name"],
                "role": r["role"],
                "joined_at": r["joined_at"].isoformat() if r["joined_at"] else None,
            }
            for r in rows
        ],
    }


@router.get("/organizations/{org_id}/redteam-runs")
async def admin_list_org_runs(
    org_id: str,
    limit: int = 50,
    offset: int = 0,
    current_user: UserResponse = Depends(require_admin),
) -> dict:
    """Platform admin view of all runs for an org (regardless of which member submitted)."""
    if limit > 200:
        limit = 200
    org = await database.fetch_one(
        "SELECT id, name FROM organizations WHERE id = :id",
        {"id": org_id},
    )
    if not org:
        raise HTTPException(404, "Organization not found")
    rows = await database.fetch_all(
        """
        SELECT r.id, r.user_id, r.probe_suite, r.status, r.started_at, r.finished_at,
               r.target_spec->>'kind' AS target_kind,
               u.email AS submitter_email,
               (SELECT COUNT(*) FROM redteam_findings f WHERE f.run_id = r.id) AS findings_count,
               (SELECT COUNT(*) FROM redteam_findings f WHERE f.run_id = r.id AND f.verdict = 'fail') AS fails_count
        FROM redteam_runs r
        LEFT JOIN users u ON u.id = r.user_id
        WHERE r.organization_id = :o
        ORDER BY r.started_at DESC
        LIMIT :lim OFFSET :off
        """,
        {"o": org_id, "lim": limit, "off": offset},
    )
    total_row = await database.fetch_one(
        "SELECT COUNT(*) AS c FROM redteam_runs WHERE organization_id = :o",
        {"o": org_id},
    )
    return {
        "organization": {"id": str(org["id"]), "name": org["name"]},
        "total": total_row["c"],
        "limit": limit,
        "offset": offset,
        "runs": [
            {
                "id": str(r["id"]),
                "submitter_email": r["submitter_email"],
                "probe_suite": r["probe_suite"],
                "status": r["status"],
                "target_kind": r["target_kind"],
                "started_at": r["started_at"].isoformat() if r["started_at"] else None,
                "finished_at": r["finished_at"].isoformat() if r["finished_at"] else None,
                "findings_count": r["findings_count"],
                "fails_count": r["fails_count"],
            }
            for r in rows
        ],
    }
