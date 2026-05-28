-- V20: extend redteam_findings with full Finding-shape columns.
--
-- V17 shipped a minimal schema (verdict + severity + framework mappings).
-- T7 plan persisted only those, but the orchestrator emits full Findings
-- (attack_prompt, target_response, judge reasoning, etc.). This migration
-- adds the remaining columns so reports can render the actual probe content
-- + target output + judge rationale, not just the verdict label.
--
-- All new columns are nullable so existing rows (test data from dev validation)
-- survive without backfill.

ALTER TABLE redteam_findings
    ADD COLUMN attack_prompt TEXT,
    ADD COLUMN target_response TEXT,
    ADD COLUMN target_latency_ms DOUBLE PRECISION,
    ADD COLUMN probed_at TIMESTAMPTZ,
    ADD COLUMN confidence DOUBLE PRECISION,
    ADD COLUMN reasoning TEXT,
    ADD COLUMN judge_model TEXT,
    ADD COLUMN escalated_model TEXT;
