"""Subscription quota enforcement helpers."""

import logging
from datetime import datetime
from uuid import UUID

import stripe
from fastapi import HTTPException

from database import database
from subscription_period import ensure_active_period

logger = logging.getLogger("SubscriptionMiddleware")


async def _report_stripe_usage(user_id: UUID, quantity: int = 1):
    """Report metered usage to Stripe for enterprise plan via Billing Meter."""
    try:
        row = await database.fetch_one(
            """SELECT s.stripe_customer_id
               FROM subscriptions s
               WHERE s.user_id = :uid AND s.plan_id = 'enterprise'
                 AND s.status IN ('active', 'trialing')""",
            {"uid": user_id},
        )
        if not row or not row["stripe_customer_id"]:
            return

        import time
        stripe.billing.MeterEvent.create(
            event_name="test_case_usage",
            payload={
                "value": str(quantity),
                "stripe_customer_id": row["stripe_customer_id"],
            },
            timestamp=int(time.time()),
        )
        logger.info(f"Stripe meter event reported: user={user_id} qty={quantity}")
    except Exception as e:
        logger.error(f"Failed to report Stripe usage for user {user_id}: {e}")


async def get_user_plan(user_id: UUID) -> str:
    """Return the user's current plan ID (falls back to 'free')."""
    row = await database.fetch_one(
        """SELECT plan_id FROM subscriptions
           WHERE user_id = :uid AND status IN ('active', 'trialing', 'past_due')
           LIMIT 1""",
        {"uid": user_id},
    )
    return row["plan_id"] if row else "free"


async def get_plan_features(plan_id: str) -> dict:
    """Return features JSONB for a plan."""
    row = await database.fetch_one(
        "SELECT features FROM subscription_plans WHERE id = :pid",
        {"pid": plan_id},
    )
    if not row:
        return {"models": ["gpt-5.4-mini"], "smart_routing": False, "test_cases_limit": 10}
    features = row["features"]
    if isinstance(features, str):
        import json
        features = json.loads(features)
    return features


async def check_and_increment_quota(user_id: UUID) -> bool:
    """
    Atomically check quota and increment usage.
    Returns True if allowed, raises HTTPException(429) if quota exceeded.
    """
    # Make sure the user's subscription period is current and a usage_quotas
    # row exists for it. ensure_active_period seeds free-plan subscription
    # rows; we still need to seed the usage_quotas row.
    period_start, period_end, plan_id = await ensure_active_period(user_id)
    await _ensure_quota_row(user_id, plan_id, period_start, period_end)

    row = await database.fetch_one(
        "SELECT increment_usage_if_allowed(:uid) AS allowed",
        {"uid": user_id},
    )
    if row and row["allowed"]:
        if plan_id == "enterprise":
            await _report_stripe_usage(user_id)
        return True

    # Quota exceeded — pull current numbers for the error message.
    quota_row = await database.fetch_one(
        """SELECT test_cases_used, test_cases_limit FROM usage_quotas
           WHERE user_id = :uid AND period_start = :ps""",
        {"uid": user_id, "ps": period_start},
    )
    used = quota_row["test_cases_used"] if quota_row else 0
    limit = quota_row["test_cases_limit"] if quota_row else 0
    logger.warning(f"Quota exceeded for user {user_id}: {used}/{limit}")
    raise HTTPException(
        status_code=429,
        detail={
            "error": "quota_exceeded",
            "message": f"Monthly test case limit reached ({used}/{limit}). Upgrade your plan for more.",
            "plan": plan_id,
            "test_cases_used": used,
            "test_cases_limit": limit,
            "period_end": period_end.isoformat(),
        },
    )


async def _ensure_quota_row(
    user_id: UUID,
    plan_id: str,
    period_start: datetime,
    period_end: datetime,
) -> None:
    plan_row = await database.fetch_one(
        "SELECT test_cases_limit FROM subscription_plans WHERE id = :pid",
        {"pid": plan_id},
    )
    limit = plan_row["test_cases_limit"] if plan_row else 10
    await database.execute(
        """INSERT INTO usage_quotas (user_id, period_start, period_end, test_cases_limit)
           VALUES (:uid, :ps, :pe, :lim)
           ON CONFLICT (user_id, period_start) DO NOTHING""",
        {"uid": user_id, "ps": period_start, "pe": period_end, "lim": limit},
    )


async def validate_model_access(user_id: UUID, model: str) -> bool:
    """
    Check if user's plan allows access to the requested model.
    Returns True if allowed, raises HTTPException(403) if not.
    """
    plan_id = await get_user_plan(user_id)
    features = await get_plan_features(plan_id)
    allowed_models = features.get("models", ["gpt-5.4-mini"])

    if model not in allowed_models:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "model_not_allowed",
                "message": f"Model '{model}' is not available on the '{plan_id}' plan. Upgrade to access this model.",
                "current_plan": plan_id,
                "allowed_models": allowed_models,
            },
        )
    return True
