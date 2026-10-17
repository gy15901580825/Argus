-- Which code a run tested, so a run can be compared with the latest run on a
-- base branch. Nullable: older clients do not send it.
ALTER TABLE redteam_runs ADD COLUMN repo TEXT;
ALTER TABLE redteam_runs ADD COLUMN branch TEXT;
ALTER TABLE redteam_runs ADD COLUMN commit_sha TEXT;
-- Hash of the target spec with secrets removed; a baseline only matches runs with the same key.
ALTER TABLE redteam_runs ADD COLUMN baseline_key TEXT;

CREATE INDEX idx_redteam_runs_baseline
    ON redteam_runs (user_id, repo, branch, baseline_key, finished_at DESC)
    WHERE status = 'completed';
