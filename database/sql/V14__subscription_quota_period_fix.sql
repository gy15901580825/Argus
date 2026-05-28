-- V14: Anchor quota period to subscriptions.current_period_start/end.
-- Fixes drift caused by dual calendar-month vs anniversary logic (see plan
-- 2026-04-26-subscription-quota-period-fix.md).
-- Safe to re-run: step 1 is a no-op once backfill is complete; steps
-- 2–5 collapse to the same canonical state and preserve test_cases_used.
-- Flyway will refuse to re-run by checksum in normal operation.

BEGIN;

-- Hold table-level exclusive locks to prevent concurrent INSERTs into
-- usage_quotas (e.g., from a webhook firing mid-migration) from racing
-- with steps 4–5 and creating duplicate rows post-migration. Migration
-- runs in seconds, so the lock window is small.
LOCK TABLE subscriptions, usage_quotas IN EXCLUSIVE MODE;

-- 1. Backfill subscriptions.current_period_start/end for rows that lack them.
--    Anchor on users.created_at, then advance one calendar month at a time
--    (using PG's INTERVAL '1 month' calendar arithmetic) until the period
--    contains NOW(). Recursive CTE keeps this exact for any month length.
WITH RECURSIVE periods AS (
    SELECT s.user_id,
           u.created_at AS ps,
           u.created_at + INTERVAL '1 month' AS pe
    FROM subscriptions s
    JOIN users u ON u.id = s.user_id
    WHERE (s.current_period_start IS NULL OR s.current_period_end IS NULL)
      AND u.created_at IS NOT NULL
      AND u.created_at < NOW()

    UNION ALL

    SELECT user_id, pe, pe + INTERVAL '1 month'
    FROM periods
    WHERE pe <= NOW()
),
active_period AS (
    SELECT DISTINCT ON (user_id) user_id, ps, pe
    FROM periods
    WHERE pe > NOW()
    ORDER BY user_id, ps
)
UPDATE subscriptions s
SET current_period_start = a.ps,
    current_period_end   = a.pe,
    updated_at = NOW()
FROM active_period a
WHERE s.user_id = a.user_id;

-- 2. Build the canonical (user_id, period_start, period_end, limit) set.
CREATE TEMP TABLE canonical_quota ON COMMIT DROP AS
SELECT s.user_id,
       s.current_period_start AS period_start,
       s.current_period_end   AS period_end,
       p.test_cases_limit
FROM subscriptions s
JOIN subscription_plans p ON p.id = s.plan_id;

-- 3. Compute used = LEAST(MAX(existing rows that overlap canonical period), limit).
--    "Overlap" = any existing row whose [period_start, period_end) intersects
--    the canonical window. MAX (not SUM) avoids double-counting when the same
--    request was recorded against two parallel duplicate rows.
CREATE TEMP TABLE collapsed_used ON COMMIT DROP AS
SELECT c.user_id,
       c.period_start,
       c.period_end,
       c.test_cases_limit,
       LEAST(
           COALESCE(MAX(q.test_cases_used), 0),
           c.test_cases_limit
       ) AS test_cases_used
FROM canonical_quota c
LEFT JOIN usage_quotas q
       ON q.user_id = c.user_id
      AND q.period_start <  c.period_end
      AND q.period_end   >  c.period_start
GROUP BY c.user_id, c.period_start, c.period_end, c.test_cases_limit;

-- 4. Delete every existing usage_quotas row for users we're about to fix.
DELETE FROM usage_quotas q
USING canonical_quota c
WHERE q.user_id = c.user_id;

-- 5. Insert the single canonical row per user.
INSERT INTO usage_quotas (user_id, period_start, period_end,
                          test_cases_used, test_cases_limit)
SELECT user_id, period_start, period_end, test_cases_used, test_cases_limit
FROM collapsed_used;

-- 6. Rewrite increment_usage_if_allowed to key on subscriptions, not NOW().
--    This makes the function immune to clock skew between the application's
--    notion of "current period" and the DB's, and removes the time-range scan.
-- Caller MUST ensure a usage_quotas row exists for the user's
-- current subscriptions.current_period_start before invoking. The
-- function returns FALSE if (a) no active subscription, (b) the
-- usage_quotas row for the period is missing, or (c) the row is
-- already at limit. Returns TRUE only if the increment actually
-- landed. Task 3's check_and_increment_quota seeds the row via
-- _ensure_quota_row before each call.
CREATE OR REPLACE FUNCTION increment_usage_if_allowed(p_user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_period_start TIMESTAMPTZ;
    v_updated INTEGER;
BEGIN
    SELECT current_period_start INTO v_period_start
    FROM subscriptions
    WHERE user_id = p_user_id
      AND status IN ('active', 'trialing', 'past_due')
    LIMIT 1;

    IF v_period_start IS NULL THEN
        RETURN FALSE;  -- caller must seed subscription row first
    END IF;

    UPDATE usage_quotas
    SET test_cases_used = test_cases_used + 1, updated_at = NOW()
    WHERE user_id = p_user_id
      AND period_start = v_period_start
      AND (test_cases_limit = 0 OR test_cases_used < test_cases_limit)
    RETURNING 1 INTO v_updated;

    RETURN v_updated IS NOT NULL;
END;
$$ LANGUAGE plpgsql;

COMMIT;
