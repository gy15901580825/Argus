"""Subscription management: Stripe Checkout, Portal, Webhook, Status."""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from auth import get_current_user, get_optional_user
from database import database
from models import UserResponse
from stripe_config import (
    PRICE_ID_MAP, STRIPE_WEBHOOK_SECRET,
    SUCCESS_URL, CANCEL_URL,
)
from subscription_period import ensure_active_period

router = APIRouter()
logger = logging.getLogger("Subscription")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CheckoutRequest(BaseModel):
    plan: str  # "starter" or "pro"

class SubscriptionStatus(BaseModel):
    plan: str
    status: str
    test_cases_used: int
    test_cases_limit: int  # 0 = unlimited
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool = False

class UsageDetails(BaseModel):
    test_cases_used: int
    test_cases_limit: int
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    llm_cost_usd: float = 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_or_create_stripe_customer(user: UserResponse) -> str:
    """Return existing Stripe customer ID or create a new one."""
    row = await database.fetch_one(
        "SELECT stripe_customer_id FROM users WHERE id = :uid",
        {"uid": user.id},
    )
    if row and row["stripe_customer_id"]:
        return row["stripe_customer_id"]

    customer = stripe.Customer.create(
        email=user.email,
        name=user.username,
        metadata={"user_id": str(user.id)},
    )
    await database.execute(
        "UPDATE users SET stripe_customer_id = :cid WHERE id = :uid",
        {"cid": customer.id, "uid": user.id},
    )
    return customer.id


async def _ensure_subscription_row(user_id: UUID) -> dict:
    """Return subscription row, creating a free one if missing."""
    row = await database.fetch_one(
        "SELECT * FROM subscriptions WHERE user_id = :uid", {"uid": user_id}
    )
    if row:
        return dict(row._mapping)

    await database.execute(
        """INSERT INTO subscriptions (user_id, plan_id, status)
           VALUES (:uid, 'free', 'active')
           ON CONFLICT (user_id) DO NOTHING""",
        {"uid": user_id},
    )
    row = await database.fetch_one(
        "SELECT * FROM subscriptions WHERE user_id = :uid", {"uid": user_id}
    )
    return dict(row._mapping)


async def _ensure_usage_quota(user_id: UUID, plan_id: str,
                              period_start: datetime, period_end: datetime):
    """Create/update usage quota row for the given subscription period."""
    plan_row = await database.fetch_one(
        "SELECT test_cases_limit FROM subscription_plans WHERE id = :pid", {"pid": plan_id}
    )
    limit = plan_row["test_cases_limit"] if plan_row else 10

    await database.execute(
        """INSERT INTO usage_quotas (user_id, period_start, period_end, test_cases_limit)
           VALUES (:uid, :ps, :pe, :lim)
           ON CONFLICT (user_id, period_start) DO UPDATE SET test_cases_limit = :lim""",
        {"uid": user_id, "ps": period_start, "pe": period_end, "lim": limit},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/subscription/create-checkout")
async def create_checkout(
    req: CheckoutRequest,
    current_user: UserResponse = Depends(get_current_user),
):
    """Create a Stripe Checkout session and return the URL."""
    if req.plan not in PRICE_ID_MAP:
        raise HTTPException(400, f"Invalid plan: {req.plan}")

    customer_id = await _get_or_create_stripe_customer(current_user)

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": PRICE_ID_MAP[req.plan], "quantity": 1}],
        success_url=SUCCESS_URL,
        cancel_url=CANCEL_URL,
        metadata={"user_id": str(current_user.id), "plan": req.plan},
        subscription_data={"metadata": {"user_id": str(current_user.id), "plan": req.plan}},
    )
    return {"checkout_url": session.url}


@router.post("/subscription/create-portal")
async def create_portal(current_user: UserResponse = Depends(get_current_user)):
    """Create a Stripe Customer Portal session for subscription management."""
    row = await database.fetch_one(
        "SELECT stripe_customer_id FROM users WHERE id = :uid", {"uid": current_user.id}
    )
    if not row or not row["stripe_customer_id"]:
        raise HTTPException(404, "No billing account found. Please subscribe first.")

    session = stripe.billing_portal.Session.create(
        customer=row["stripe_customer_id"],
        return_url="https://www.example.com/dashboard",
    )
    return {"portal_url": session.url}


@router.get("/subscription/status", response_model=SubscriptionStatus)
async def get_status(current_user: UserResponse = Depends(get_current_user)):
    """Return current subscription status and usage."""
    sub = await _ensure_subscription_row(current_user.id)
    period_start, period_end, _plan = await ensure_active_period(current_user.id)

    usage_row = await database.fetch_one(
        """SELECT test_cases_used, test_cases_limit FROM usage_quotas
           WHERE user_id = :uid AND period_start = :ps""",
        {"uid": current_user.id, "ps": period_start},
    )

    return SubscriptionStatus(
        plan=sub["plan_id"],
        status=sub["status"],
        test_cases_used=usage_row["test_cases_used"] if usage_row else 0,
        test_cases_limit=usage_row["test_cases_limit"] if usage_row else 10,
        current_period_end=period_end,
        cancel_at_period_end=sub.get("cancel_at_period_end", False),
    )


@router.get("/subscription/cost-alert")
async def check_cost_alert(current_user: UserResponse = Depends(get_current_user)):
    """Check if user's LLM cost is approaching concerning levels."""
    period_start, _pe, _plan = await ensure_active_period(current_user.id)

    row = await database.fetch_one(
        """SELECT COALESCE(SUM(cost_usd), 0) AS total_cost,
                  COUNT(*) AS request_count
           FROM ai_token_usage
           WHERE user_id = :uid AND created_at >= :start""",
        {"uid": current_user.id, "start": period_start},
    )

    total_cost = float(row["total_cost"]) if row else 0.0
    request_count = row["request_count"] if row else 0

    # Cost thresholds per plan
    sub = await _ensure_subscription_row(current_user.id)
    plan = sub["plan_id"]
    thresholds = {"free": 2.50, "starter": 30.0, "pro": 100.0, "enterprise": 500.0}
    threshold = thresholds.get(plan, 5.0)

    alert_level = "normal"
    if total_cost > threshold:
        alert_level = "critical"
        logger.warning(f"Cost alert CRITICAL: user={current_user.id} plan={plan} cost=${total_cost:.4f} threshold=${threshold}")
    elif total_cost > threshold * 0.8:
        alert_level = "warning"

    return {
        "plan": plan,
        "period_cost_usd": round(total_cost, 6),
        "request_count": request_count,
        "threshold_usd": threshold,
        "alert_level": alert_level,
    }


@router.get("/subscription/usage", response_model=UsageDetails)
async def get_usage(current_user: UserResponse = Depends(get_current_user)):
    """Return detailed usage for current billing period."""
    period_start, period_end, _plan = await ensure_active_period(current_user.id)

    row = await database.fetch_one(
        """SELECT test_cases_used, test_cases_limit
           FROM usage_quotas
           WHERE user_id = :uid AND period_start = :ps""",
        {"uid": current_user.id, "ps": period_start},
    )

    cost_row = await database.fetch_one(
        """SELECT COALESCE(SUM(cost_usd), 0) as total_cost FROM ai_token_usage
           WHERE user_id = :uid AND created_at >= :start""",
        {"uid": current_user.id, "start": period_start},
    )

    return UsageDetails(
        test_cases_used=row["test_cases_used"] if row else 0,
        test_cases_limit=row["test_cases_limit"] if row else 10,
        period_start=period_start,
        period_end=period_end,
        llm_cost_usd=float(cost_row["total_cost"]) if cost_row else 0.0,
    )


@router.get("/subscription/plans")
async def get_plans():
    """Return all active subscription plans (public endpoint)."""
    rows = await database.fetch_all(
        """SELECT id, name, description, price_cents, test_cases_limit, features
           FROM subscription_plans WHERE is_active = true ORDER BY price_cents"""
    )
    return [dict(r._mapping) for r in rows]


@router.get("/subscription/admin/cost-summary")
async def get_cost_summary(current_user: UserResponse = Depends(get_current_user)):
    """Admin endpoint: aggregate cost and usage stats. Requires SUPER_ADMIN role."""
    # Check admin role
    user_row = await database.fetch_one(
        "SELECT role FROM users WHERE id = :uid", {"uid": current_user.id}
    )
    if not user_row or user_row["role"] != "SUPER_ADMIN":
        raise HTTPException(403, "Admin access required")

    # Aggregate stats
    stats = await database.fetch_one(
        """SELECT
               COUNT(DISTINCT user_id) AS total_users,
               COUNT(*) AS total_requests,
               COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
               COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
               COALESCE(SUM(cost_usd), 0) AS total_cost_usd
           FROM ai_token_usage
           WHERE created_at >= NOW() - INTERVAL '30 days'"""
    )

    # Per-plan breakdown
    plan_rows = await database.fetch_all(
        """SELECT
               COALESCE(subscription_plan, 'unknown') AS plan,
               COUNT(*) AS requests,
               COALESCE(SUM(cost_usd), 0) AS cost_usd
           FROM ai_token_usage
           WHERE created_at >= NOW() - INTERVAL '30 days'
           GROUP BY subscription_plan ORDER BY cost_usd DESC"""
    )

    # Per-model breakdown
    model_rows = await database.fetch_all(
        """SELECT
               model_name AS model,
               COUNT(*) AS requests,
               COALESCE(SUM(input_tokens), 0) AS input_tokens,
               COALESCE(SUM(output_tokens), 0) AS output_tokens,
               COALESCE(SUM(cost_usd), 0) AS cost_usd
           FROM ai_token_usage
           WHERE created_at >= NOW() - INTERVAL '30 days'
           GROUP BY model_name ORDER BY cost_usd DESC"""
    )

    # Active subscriptions count
    sub_counts = await database.fetch_all(
        """SELECT plan_id, COUNT(*) AS count
           FROM subscriptions WHERE status = 'active'
           GROUP BY plan_id ORDER BY plan_id"""
    )

    return {
        "period": "last_30_days",
        "summary": dict(stats._mapping) if stats else {},
        "by_plan": [dict(r._mapping) for r in plan_rows],
        "by_model": [dict(r._mapping) for r in model_rows],
        "active_subscriptions": [dict(r._mapping) for r in sub_counts],
    }


# ---------------------------------------------------------------------------
# Stripe Webhook
# ---------------------------------------------------------------------------

@router.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events. No auth — verified by Stripe signature."""
    body = await request.body()
    sig = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(body, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.SignatureVerificationError:
        logger.warning("Stripe webhook signature verification failed")
        raise HTTPException(400, "Invalid signature")
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        raise HTTPException(400, str(e))

    # Idempotency check
    existing = await database.fetch_one(
        "SELECT id FROM stripe_events WHERE event_id = :eid", {"eid": event.id}
    )
    if existing:
        return {"status": "already_processed"}

    # Store event
    await database.execute(
        """INSERT INTO stripe_events (event_id, event_type, payload)
           VALUES (:eid, :etype, :payload)
           ON CONFLICT (event_id) DO NOTHING""",
        {"eid": event.id, "etype": event.type, "payload": str(event.data)},
    )

    handler = _WEBHOOK_HANDLERS.get(event.type)
    if handler:
        try:
            await handler(event)
        except Exception as exc:
            logger.error(f"Webhook handler error for {event.type}: {exc}", exc_info=True)
            # Return 200 to Stripe to prevent retries on our logic errors
    else:
        logger.info(f"Unhandled Stripe event type: {event.type}")

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Webhook handlers
# ---------------------------------------------------------------------------

async def _handle_checkout_completed(event):
    """checkout.session.completed — user finished Stripe Checkout."""
    session = event.data.object
    user_id = session.metadata.get("user_id")
    plan = session.metadata.get("plan", "starter")
    customer_id = session.customer
    subscription_id = session.subscription

    if not user_id:
        logger.warning("checkout.session.completed missing user_id in metadata")
        return

    logger.info(f"Checkout completed: user={user_id}, plan={plan}, sub={subscription_id}")

    # Ensure stripe_customer_id on user
    await database.execute(
        "UPDATE users SET stripe_customer_id = :cid WHERE id = :uid",
        {"cid": customer_id, "uid": user_id},
    )

    # Retrieve subscription details from Stripe
    sub = stripe.Subscription.retrieve(subscription_id)
    period_start = datetime.fromtimestamp(sub.current_period_start, tz=timezone.utc)
    period_end = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc)

    # Upsert subscription
    await database.execute(
        """INSERT INTO subscriptions (user_id, plan_id, stripe_customer_id, stripe_subscription_id,
               status, current_period_start, current_period_end)
           VALUES (:uid, :plan, :cid, :sid, 'active', :ps, :pe)
           ON CONFLICT (user_id) DO UPDATE SET
               plan_id = :plan, stripe_customer_id = :cid, stripe_subscription_id = :sid,
               status = 'active', current_period_start = :ps, current_period_end = :pe,
               cancel_at_period_end = false, canceled_at = NULL, updated_at = NOW()""",
        {"uid": user_id, "plan": plan, "cid": customer_id, "sid": subscription_id,
         "ps": period_start, "pe": period_end},
    )

    # Create usage quota for the period
    await _ensure_usage_quota(user_id, plan, period_start, period_end)


async def _handle_subscription_updated(event):
    """customer.subscription.updated — plan change, renewal, etc."""
    sub = event.data.object
    user_id = sub.metadata.get("user_id")
    if not user_id:
        # Try to find by stripe_subscription_id
        row = await database.fetch_one(
            "SELECT user_id FROM subscriptions WHERE stripe_subscription_id = :sid",
            {"sid": sub.id},
        )
        if not row:
            logger.warning(f"subscription.updated: no user found for sub {sub.id}")
            return
        user_id = str(row["user_id"])

    plan = sub.metadata.get("plan") or sub.get("items", {}).get("data", [{}])[0].get("price", {}).get("metadata", {}).get("plan", "starter")
    status = sub.status  # active, past_due, canceled, etc.
    period_start = datetime.fromtimestamp(sub.current_period_start, tz=timezone.utc)
    period_end = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc)

    await database.execute(
        """UPDATE subscriptions SET
               plan_id = :plan, status = :status,
               current_period_start = :ps, current_period_end = :pe,
               cancel_at_period_end = :cap, updated_at = NOW()
           WHERE user_id = :uid""",
        {"plan": plan, "status": status, "ps": period_start, "pe": period_end,
         "cap": sub.cancel_at_period_end, "uid": user_id},
    )

    # Update usage quota limit if plan changed
    await _ensure_usage_quota(user_id, plan, period_start, period_end)


async def _handle_subscription_deleted(event):
    """customer.subscription.deleted — subscription cancelled."""
    sub = event.data.object
    row = await database.fetch_one(
        "SELECT user_id FROM subscriptions WHERE stripe_subscription_id = :sid",
        {"sid": sub.id},
    )
    if not row:
        return

    await database.execute(
        """UPDATE subscriptions SET
               status = 'canceled', plan_id = 'free',
               stripe_subscription_id = NULL,
               canceled_at = NOW(), updated_at = NOW()
           WHERE user_id = :uid""",
        {"uid": row["user_id"]},
    )


async def _handle_invoice_payment_succeeded(event):
    """invoice.payment_succeeded — new billing period starts."""
    invoice = event.data.object
    subscription_id = invoice.subscription
    if not subscription_id:
        return

    row = await database.fetch_one(
        "SELECT user_id, plan_id FROM subscriptions WHERE stripe_subscription_id = :sid",
        {"sid": subscription_id},
    )
    if not row:
        return

    # Retrieve fresh subscription to get new period
    sub = stripe.Subscription.retrieve(subscription_id)
    period_start = datetime.fromtimestamp(sub.current_period_start, tz=timezone.utc)
    period_end = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc)

    # Reset usage for new period
    await _ensure_usage_quota(row["user_id"], row["plan_id"], period_start, period_end)


async def _handle_invoice_payment_failed(event):
    """invoice.payment_failed — mark subscription as past_due."""
    invoice = event.data.object
    subscription_id = invoice.subscription
    if not subscription_id:
        return

    await database.execute(
        "UPDATE subscriptions SET status = 'past_due', updated_at = NOW() WHERE stripe_subscription_id = :sid",
        {"sid": subscription_id},
    )


async def _handle_charge_refunded(event):
    """charge.refunded — log refund, optionally downgrade."""
    charge = event.data.object
    logger.info(f"Charge refunded: {charge.id}, amount={charge.amount_refunded}")
    # For now just log — manual review for downgrades


_WEBHOOK_HANDLERS = {
    "checkout.session.completed": _handle_checkout_completed,
    "customer.subscription.created": _handle_subscription_updated,
    "customer.subscription.updated": _handle_subscription_updated,
    "customer.subscription.deleted": _handle_subscription_deleted,
    "invoice.payment_succeeded": _handle_invoice_payment_succeeded,
    "invoice.payment_failed": _handle_invoice_payment_failed,
    "charge.refunded": _handle_charge_refunded,
}
