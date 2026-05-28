-- V16: Normalize legacy admin-granted subscription periods.
--
-- Pre-fix, routers/admin.py:update_user_plan set
-- current_period_end = now + 10 years for admin grants
-- ("Admin-assigned plans don't expire"). Combined with V14's collapse,
-- those users got a usage_quotas row spanning 10 years — counter never
-- resets. The plan-level fix in subscription_period.py (auto-advance
-- gate keyed on stripe_subscription_id IS NULL) only helps when the
-- period is *expired*. A 10-year-future period_end is "valid" by that
-- gate, so the bad row sticks.
--
-- This migration finds those legacy rows by signal (paid plan + no
-- Stripe sub + period_end more than 2 years from now — well beyond any
-- legitimate Stripe billing cycle) and resets them to a 1-month window
-- so subsequent ensure_active_period calls treat them like normal
-- non-Stripe subscriptions.
--
-- Safe to re-run: rows are identified into a TEMP TABLE; steps 2–4
-- only operate on that set. After first run, no rows match the filter,
-- so re-runs are no-ops.

BEGIN;

LOCK TABLE subscriptions, usage_quotas IN EXCLUSIVE MODE;

-- 1. Snapshot the affected user set.
CREATE TEMP TABLE to_fix ON COMMIT DROP AS
SELECT user_id
FROM subscriptions
WHERE plan_id != 'free'
  AND stripe_subscription_id IS NULL
  AND current_period_end > NOW() + INTERVAL '2 years';

-- 2. Normalize their subscription period to a monthly cycle anchored on now.
UPDATE subscriptions s
SET current_period_start = date_trunc('second', NOW()),
    current_period_end   = date_trunc('second', NOW()) + INTERVAL '1 month',
    updated_at = NOW()
FROM to_fix f
WHERE s.user_id = f.user_id;

-- 3. Build the canonical usage_quotas state for these users using the
--    new (post-step-2) subscription period and MAX-collapsing any
--    existing rows so we don't reduce recorded usage.
CREATE TEMP TABLE collapsed_used ON COMMIT DROP AS
SELECT s.user_id,
       s.current_period_start AS period_start,
       s.current_period_end   AS period_end,
       p.test_cases_limit,
       LEAST(COALESCE(MAX(q.test_cases_used), 0), p.test_cases_limit) AS test_cases_used
FROM to_fix f
JOIN subscriptions s        ON s.user_id = f.user_id
JOIN subscription_plans p   ON p.id      = s.plan_id
LEFT JOIN usage_quotas q    ON q.user_id = s.user_id
GROUP BY s.user_id, s.current_period_start, s.current_period_end, p.test_cases_limit;

-- 4. Replace the usage_quotas rows for the affected users.
DELETE FROM usage_quotas q
USING to_fix f
WHERE q.user_id = f.user_id;

INSERT INTO usage_quotas (user_id, period_start, period_end,
                          test_cases_used, test_cases_limit)
SELECT user_id, period_start, period_end, test_cases_used, test_cases_limit
FROM collapsed_used;

COMMIT;
