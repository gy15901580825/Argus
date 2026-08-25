-- V25: the negative-space table for a run.
--
-- A findings list says what broke. It cannot say what was never looked at: a
-- control category served by a single probe, or one skipped wholesale because
-- the target class did not match. The orchestrator computes that manifest at
-- the end of every run; this column is where it lands so the report and the
-- dashboard can show it long after the run finished.
--
-- Nullable and additive: every run that predates this column keeps NULL, and
-- the report renders the findings half exactly as before.

ALTER TABLE redteam_runs ADD COLUMN coverage JSONB;

COMMENT ON COLUMN redteam_runs.coverage IS
    'Per-standard coverage manifest: which control cells the library holds probes for, and what happened to them in this run. NULL for runs predating the feature.';
