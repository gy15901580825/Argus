-- ============================================================================
-- V7 Migration: Web UI Testing Tasks
-- ============================================================================

CREATE TABLE web_ui_tasks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id        VARCHAR(255) NOT NULL,
    target_url      TEXT NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending|running|completed|failed
    user_persona    VARCHAR(50),
    max_steps       INTEGER DEFAULT 100,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    steps_done      INTEGER DEFAULT 0,
    -- Result artifacts (R2 presigned URLs)
    tests_url       TEXT,
    bug_report_url  TEXT,
    features_url    TEXT,
    -- Structured result data
    bug_counts      JSONB,   -- {"critical":n,"high":n,"medium":n,"low":n}
    test_summary    JSONB,   -- {"total":n,"passed":n,"failed":n}
    -- Error info
    error_message   TEXT
);

CREATE INDEX idx_web_ui_tasks_owner ON web_ui_tasks(owner_id, created_at DESC);
CREATE INDEX idx_web_ui_tasks_status ON web_ui_tasks(status);
