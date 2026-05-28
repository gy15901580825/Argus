-- V21: extend redteam_findings.verdict CHECK constraint to include the new
-- verdict values introduced in Plan 4 T7 + Plan 5 T1 (D2).
--
-- V17 shipped CHECK (verdict IN ('pass', 'warn', 'fail')). Plan 4 added
-- verdict constants 'error' / 'blocked_by_target' / 'skipped' / 'aborted_cost'
-- but never updated the constraint, so:
-- - Plan 4 verdict=error path inserts FAILED (silently — the SSE error path
--   masked it; runs went status=failed with 0 findings, blamed on target 4xx)
-- - Plan 5 D2 attempts to insert verdict=skipped/blocked_by_target/aborted_cost
--   FAIL the constraint → run status=failed → 0 findings persisted
--
-- This migration drops the old constraint and adds a new one with all 7 values.
--
-- No data migration needed — pre-V21 rows can only have pass/warn/fail (the
-- only values the old constraint allowed), all of which remain in the new set.

ALTER TABLE redteam_findings
    DROP CONSTRAINT IF EXISTS redteam_findings_verdict_check;

ALTER TABLE redteam_findings
    ADD CONSTRAINT redteam_findings_verdict_check
    CHECK (verdict IN ('pass', 'warn', 'fail', 'error', 'blocked_by_target', 'skipped', 'aborted_cost'));
