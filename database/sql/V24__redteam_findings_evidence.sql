-- V24: evidence-driven verdicts.
--
-- A payment probe's verdict rests on what the agent actually did — the
-- authorizations it signed, their amounts and payees — not on a judge's reading
-- of the reply text. The orchestrator now returns that record on every finding
-- that has one; this column is where it lands so the report and the dashboard
-- can show the facts behind a `fail`.
--
-- Nullable and additive: every existing finding, and every finding from the
-- five text-only target adapters, keeps NULL here.
--
-- NOTE ON NUMBERING: V23 is deliberately left unused in Argus. It is claimed
-- upstream by the embedding-SDK work; keeping the number free here means that
-- port can land as V23 without a renumber and the two repos stay aligned.
--
-- redteam_findings.evidence_blob_url (V17) is deliberately left alone: it has
-- never been written by any code and stays reserved for large artifacts that do
-- not belong inline.

ALTER TABLE redteam_findings ADD COLUMN evidence JSONB;

COMMENT ON COLUMN redteam_findings.evidence IS
    'What the target was observed doing (payment authorizations, testbed request log). NULL for text-only targets.';
