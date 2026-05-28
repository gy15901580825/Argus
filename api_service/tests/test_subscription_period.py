"""Tests for subscription_period.ensure_active_period.

The conftest in this repo replaces ``database.database`` with AsyncMocks rather
than a real DB; we drive those mocks here. Time is frozen so the assertions are
deterministic regardless of the actual system clock.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from freezegun import freeze_time


USER_ID = UUID("11111111-1111-1111-1111-111111111111")


# ---------------------------------------------------------------------------
# Test 1: Stripe-managed paid plan — period is returned unchanged, no UPDATE.
# ---------------------------------------------------------------------------
@freeze_time("2026-04-26 12:00:00")
async def test_stripe_managed_paid_user_returns_period_unchanged(mock_db):
    """Paid plans with a Stripe subscription must be trusted verbatim — Stripe
    webhooks own the period and the helper must not mutate it."""
    from subscription_period import ensure_active_period

    ps = datetime(2026, 4, 15, tzinfo=timezone.utc)
    pe = datetime(2026, 5, 15, tzinfo=timezone.utc)
    mock_db.fetch_one.return_value = {
        "plan_id": "pro",
        "current_period_start": ps,
        "current_period_end": pe,
        "stripe_subscription_id": "sub_test123",
    }

    got_ps, got_pe, got_plan = await ensure_active_period(USER_ID)

    assert (got_ps, got_pe, got_plan) == (ps, pe, "pro")
    # No mutation: helper must not write to the subscriptions row for
    # Stripe-managed paid plans.
    mock_db.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2: free user with no subscription row — seeded from users.created_at.
# ---------------------------------------------------------------------------
@freeze_time("2026-04-26 12:00:00")
async def test_free_user_with_no_subscription_row_gets_seeded(mock_db):
    from subscription_period import ensure_active_period

    created_at = datetime(2026, 1, 10, tzinfo=timezone.utc)

    # 1st fetch_one: subscriptions lookup -> None.
    # 2nd fetch_one: users.created_at lookup -> {"created_at": ...}.
    mock_db.fetch_one.side_effect = [None, {"created_at": created_at}]

    ps, pe, plan = await ensure_active_period(USER_ID)

    # Anniversary advance: Jan 10 -> Feb 10 -> Mar 10 -> Apr 10. The window
    # containing 2026-04-26 is (Apr 10, May 10).
    assert ps == datetime(2026, 4, 10, tzinfo=timezone.utc)
    assert pe == datetime(2026, 5, 10, tzinfo=timezone.utc)
    assert plan == "free"

    # The seed must persist via INSERT ... ON CONFLICT.
    assert mock_db.execute.await_count == 1
    sql, params = mock_db.execute.await_args.args
    assert "INSERT INTO subscriptions" in sql
    assert params["uid"] == USER_ID
    assert params["ps"] == ps
    assert params["pe"] == pe


# ---------------------------------------------------------------------------
# Test 3: free user with an expired period — advanced one window forward.
# ---------------------------------------------------------------------------
@freeze_time("2026-04-26 12:00:00")
async def test_free_user_with_expired_period_is_advanced(mock_db):
    from subscription_period import ensure_active_period

    expired_ps = datetime(2026, 3, 25, tzinfo=timezone.utc)
    expired_pe = datetime(2026, 4, 25, tzinfo=timezone.utc)  # expired yesterday
    mock_db.fetch_one.return_value = {
        "plan_id": "free",
        "current_period_start": expired_ps,
        "current_period_end": expired_pe,
        "stripe_subscription_id": None,
    }

    ps, pe, plan = await ensure_active_period(USER_ID)

    assert ps == datetime(2026, 4, 25, tzinfo=timezone.utc)
    assert pe == datetime(2026, 5, 25, tzinfo=timezone.utc)
    assert plan == "free"

    # Should UPDATE the existing row with the advanced window.
    assert mock_db.execute.await_count == 1
    sql, params = mock_db.execute.await_args.args
    assert "UPDATE subscriptions" in sql
    assert params["uid"] == USER_ID
    assert params["ps"] == ps
    assert params["pe"] == pe


# ---------------------------------------------------------------------------
# Test 4: free user lapsed for several windows — advanced repeatedly.
# ---------------------------------------------------------------------------
@freeze_time("2026-04-26 12:00:00")
async def test_free_user_skips_multiple_expired_periods(mock_db):
    from subscription_period import ensure_active_period

    stale_ps = datetime(2025, 12, 25, tzinfo=timezone.utc)
    stale_pe = datetime(2026, 1, 25, tzinfo=timezone.utc)
    mock_db.fetch_one.return_value = {
        "plan_id": "free",
        "current_period_start": stale_ps,
        "current_period_end": stale_pe,
        "stripe_subscription_id": None,
    }

    ps, pe, plan = await ensure_active_period(USER_ID)

    # Loop condition is ``pe <= now``: starting at pe=Jan 25 with today=Apr 26
    # we advance through Feb 25, Mar 25, Apr 25 (still <= Apr 26), and stop at
    # May 25. Result: window (Apr 25, May 25). Note the plan body said
    # "(Mar 25, Apr 25) after 3 advances" but that window is itself expired
    # given today=Apr 26, so the helper must advance once more.
    assert ps == datetime(2026, 4, 25, tzinfo=timezone.utc)
    assert pe == datetime(2026, 5, 25, tzinfo=timezone.utc)
    assert plan == "free"


# ---------------------------------------------------------------------------
# Test 5: canceled subscription — re-seeded as active free, status reset.
# ---------------------------------------------------------------------------
@freeze_time("2026-04-26 12:00:00")
async def test_canceled_subscription_is_re_seeded_as_active_free(mock_db, user_row):
    """Canceled→free users (status='canceled', plan_id='free') must be
    re-seeded so V14's increment_usage_if_allowed (which filters by status)
    can find an active row. Preserves canceled_at as an audit signal.
    """
    from subscription_period import ensure_active_period

    # First fetch_one: status filter excludes canceled rows -> returns None.
    # Second fetch_one: _seed_free_subscription's users.created_at lookup.
    mock_db.fetch_one = AsyncMock(side_effect=[
        None,
        {"created_at": datetime(2026, 1, 10, tzinfo=timezone.utc)},
    ])
    mock_db.execute = AsyncMock()

    ps, pe, plan = await ensure_active_period(user_row["id"])

    assert plan == "free"
    assert ps == datetime(2026, 4, 10, tzinfo=timezone.utc)
    assert pe == datetime(2026, 5, 10, tzinfo=timezone.utc)

    # The seed must persist via INSERT ... ON CONFLICT, with the DO UPDATE
    # branch resetting plan_id='free' and status='active' so V14's increment
    # (filtering status IN ('active','trialing','past_due')) finds the row.
    assert mock_db.execute.await_count == 1
    sql, params = mock_db.execute.await_args.args
    assert "INSERT INTO subscriptions" in sql
    assert "ON CONFLICT (user_id) DO UPDATE" in sql
    assert "plan_id              = 'free'" in sql
    assert "status               = 'active'" in sql
    assert params["uid"] == user_row["id"]
    assert params["ps"] == ps
    assert params["pe"] == pe


# ---------------------------------------------------------------------------
# Test 6: /subscription/status anchors usage on subscription period.
# Pro user mid-period (Apr 26) — calendar month flipped from Mar to Apr but
# the subscription anniversary (May 15) is still ahead, so used=66 must NOT
# reset. Uses TestClient so route registration happens before freeze_time
# is activated (avoids freezegun/pydantic.v1 metaclass clash on import).
# ---------------------------------------------------------------------------
def test_status_anchors_usage_on_subscription_period(client, mock_db, user_row):
    """GET /subscription/status must read usage keyed on the subscription's
    current_period_start, not on calendar-month boundaries. A pro user whose
    subscription started Apr 15 is still mid-period on Apr 26 and the
    test_cases_used must reflect the running count for that window.
    """
    from auth import get_current_user
    from models import UserResponse
    import server

    user = UserResponse(**user_row)
    server.app.dependency_overrides[get_current_user] = lambda: user
    try:
        sub_period_start = datetime(2026, 4, 15, tzinfo=timezone.utc)
        sub_period_end = datetime(2026, 5, 15, tzinfo=timezone.utc)

        # _ensure_subscription_row calls dict(row._mapping); fake the
        # SQLAlchemy Row interface with a tiny shim.
        class _Row(dict):
            @property
            def _mapping(self):
                return self

        # Sequence of fetch_one calls in get_status:
        #   1. _ensure_subscription_row -> SELECT * FROM subscriptions
        #   2. ensure_active_period     -> SELECT plan_id, period_start/end
        #      (paid plan: returns Stripe-driven window unchanged, no UPDATE)
        #   3. SELECT test_cases_used, test_cases_limit FROM usage_quotas
        mock_db.fetch_one = AsyncMock(side_effect=[
            _Row({
                "plan_id": "pro",
                "status": "active",
                "current_period_end": sub_period_end,
                "cancel_at_period_end": False,
            }),
            {
                "plan_id": "pro",
                "current_period_start": sub_period_start,
                "current_period_end": sub_period_end,
                "stripe_subscription_id": "sub_test123",
            },
            {"test_cases_used": 66, "test_cases_limit": 200},
        ])
        mock_db.execute = AsyncMock()

        with freeze_time("2026-04-26 12:00:00"):
            resp = client.get("/api/v1/subscription/status")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["plan"] == "pro"
        assert body["status"] == "active"
        assert body["test_cases_used"] == 66
        assert body["test_cases_limit"] == 200
        # FastAPI/pydantic v2 serializes UTC datetimes with trailing 'Z'.
        assert body["current_period_end"] == "2026-05-15T00:00:00Z"
        assert body["cancel_at_period_end"] is False

        # The usage_quotas SELECT must key on the subscription period_start,
        # not NOW() — that's the whole point of Task 4.
        usage_call = mock_db.fetch_one.await_args_list[2]
        sql, params = usage_call.args
        assert "period_start = :ps" in sql
        assert params["ps"] == sub_period_start
        assert params["uid"] == user_row["id"]

        # Paid plan: ensure_active_period must NOT mutate the subscriptions row.
        mock_db.execute.assert_not_called()
    finally:
        server.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Test 7: admin-granted paid plan with no Stripe sub — auto-advances when
# expired, the same way free plans do. Without this the admin handler's
# "now + 10 years" period would freeze the user's quota window for the
# lifetime of the grant (200 messages over 10 years instead of /month).
# ---------------------------------------------------------------------------
@freeze_time("2026-04-26 12:00:00")
async def test_admin_granted_paid_plan_auto_advances_when_expired(mock_db, user_row):
    """Admin-granted paid plans (plan_id='pro', stripe_subscription_id=None)
    must auto-advance like free plans, not be trusted like Stripe-managed
    paid plans. Otherwise users get one quota window for the lifetime of
    the grant."""
    from subscription_period import ensure_active_period

    # Subscription row: Pro plan, no Stripe sub, period expired yesterday.
    old_ps = datetime(2026, 3, 25, tzinfo=timezone.utc)
    old_pe = datetime(2026, 4, 25, tzinfo=timezone.utc)
    mock_db.fetch_one = AsyncMock(return_value={
        "plan_id": "pro",
        "current_period_start": old_ps,
        "current_period_end": old_pe,
        "stripe_subscription_id": None,
    })
    mock_db.execute = AsyncMock()

    ps, pe, plan = await ensure_active_period(user_row["id"])

    assert plan == "pro"
    assert ps == datetime(2026, 4, 25, tzinfo=timezone.utc)
    assert pe == datetime(2026, 5, 25, tzinfo=timezone.utc)

    # Helper should UPDATE the subscriptions row with new period.
    assert mock_db.execute.await_count == 1
    sql, params = mock_db.execute.await_args.args
    assert "UPDATE subscriptions" in sql
    assert "current_period_start" in sql
    assert params["uid"] == user_row["id"]
    assert params["ps"] == ps
    assert params["pe"] == pe
