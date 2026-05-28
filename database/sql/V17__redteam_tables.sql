-- V17: AI-agent red-team product tables
-- Adds:
--   redteam_runs           — one row per probe-suite execution
--   redteam_findings       — one row per probe verdict within a run
--   redteam_design_partners — design-partner accounting (M1–M4 program)

CREATE TABLE redteam_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_spec JSONB NOT NULL,
    probe_suite TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    summary JSONB
);

CREATE INDEX idx_redteam_runs_user_id ON redteam_runs(user_id);
CREATE INDEX idx_redteam_runs_started_at ON redteam_runs(started_at DESC);
CREATE INDEX idx_redteam_runs_status ON redteam_runs(status) WHERE status IN ('queued', 'running');

CREATE TABLE redteam_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL REFERENCES redteam_runs(id) ON DELETE CASCADE,
    probe_id TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('pass', 'warn', 'fail')),
    severity TEXT CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    evidence_blob_url TEXT,
    atlas_id TEXT[] DEFAULT ARRAY[]::TEXT[],
    owasp_id TEXT[] DEFAULT ARRAY[]::TEXT[],
    nist_id TEXT[] DEFAULT ARRAY[]::TEXT[],
    eu_ai_act_id TEXT[] DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_redteam_findings_run_id ON redteam_findings(run_id);
CREATE INDEX idx_redteam_findings_severity ON redteam_findings(severity)
    WHERE severity IN ('high', 'critical');

CREATE TABLE redteam_design_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    plan_credit NUMERIC(10, 2) DEFAULT 0,
    contact JSONB,
    UNIQUE (user_id)
);

CREATE INDEX idx_redteam_design_partners_signed_at ON redteam_design_partners(signed_at DESC);
