"""Single source of truth for a user's active quota window.

Stripe-managed subs (stripe_subscription_id IS NOT NULL): trust the
    period verbatim; Stripe webhooks update it on renewal.
Everything else (free plan, admin-granted paid plans without a Stripe
    sub): anchor + advance month-by-month when expired.
"""
from datetime import datetime, timezone
from uuid import UUID

from dateutil.relativedelta import relativedelta

from database import database


async def ensure_active_period(user_id: UUID) -> tuple[datetime, datetime, str]:
    """Return (period_start, period_end, plan_id) for the user's active window.

    For Stripe-managed subscriptions (``stripe_subscription_id IS NOT NULL``)
    the period is taken verbatim from the subscriptions row — Stripe is the
    source of truth and its webhooks update the period on renewal. For
    everything else (free plan, admin-granted paid plans without a Stripe
    sub) the period is anchored on ``users.created_at`` and rolled forward
    monthly until it contains "now", persisting the advanced window back to
    the subscriptions row.
    """
    # Filter by status so canceled/incomplete rows are treated as "no active
    # subscription" — they cannot increment usage anyway (V14's
    # increment_usage_if_allowed requires status IN ('active','trialing',
    # 'past_due')), so seed a fresh free window instead of advancing a row
    # the database will silently refuse to charge against.
    sub = await database.fetch_one(
        """SELECT plan_id, current_period_start, current_period_end,
                  stripe_subscription_id
           FROM subscriptions
           WHERE user_id = :uid
             AND status IN ('active', 'trialing', 'past_due')""",
        {"uid": user_id},
    )

    if sub is None:
        return await _seed_free_subscription(user_id)

    plan_id = sub["plan_id"]
    ps = sub["current_period_start"]
    pe = sub["current_period_end"]
    stripe_sub_id = sub["stripe_subscription_id"]

    # Stripe-managed subscriptions: webhooks own the period. Trust verbatim.
    # Everything else (free, admin-granted paid plans without a Stripe sub):
    # we manage the monthly cycle ourselves.
    if plan_id != "free" and stripe_sub_id is not None:
        return ps, pe, plan_id

    if ps is None or pe is None:
        return await _seed_free_subscription(user_id)

    now = datetime.now(timezone.utc)
    if pe > now:
        return ps, pe, plan_id

    while pe <= now:
        ps = pe
        pe = ps + relativedelta(months=1)

    await database.execute(
        """UPDATE subscriptions
           SET current_period_start = :ps, current_period_end = :pe, updated_at = NOW()
           WHERE user_id = :uid""",
        {"ps": ps, "pe": pe, "uid": user_id},
    )
    return ps, pe, plan_id


async def _seed_free_subscription(user_id: UUID) -> tuple[datetime, datetime, str]:
    user = await database.fetch_one(
        "SELECT created_at FROM users WHERE id = :uid", {"uid": user_id}
    )
    if user is None:
        raise ValueError(f"user {user_id} not found")

    anchor = user["created_at"]
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    ps, pe = anchor, anchor + relativedelta(months=1)
    while pe <= now:
        ps = pe
        pe = ps + relativedelta(months=1)

    # DO UPDATE handles two cases: (a) concurrent first-call from the same
    # user (TOCTOU race after fetch_one returned None), and (b) re-seeding
    # a canceled→free row to status='active' so V14's increment function
    # (which filters status IN ('active','trialing','past_due')) finds it.
    # canceled_at is intentionally left untouched to preserve the audit
    # timestamp.
    await database.execute(
        """INSERT INTO subscriptions (user_id, plan_id, status,
               current_period_start, current_period_end)
           VALUES (:uid, 'free', 'active', :ps, :pe)
           ON CONFLICT (user_id) DO UPDATE SET
               plan_id              = 'free',
               status               = 'active',
               current_period_start = EXCLUDED.current_period_start,
               current_period_end   = EXCLUDED.current_period_end,
               updated_at = NOW()""",
        {"uid": user_id, "ps": ps, "pe": pe},
    )
    return ps, pe, "free"
