-- V22__multi_tenant_organizations.sql
--
-- Multi-tenant foundation. Introduces organizations as the primary scope for
-- customer-facing resources (red-team runs, subscriptions, future API tokens).
--
-- Part A: schema creation (new tables, new columns, new indexes)
-- Part B: backfill — every existing user gets a "personal" organization with
--         themselves as OWNER, and existing redteam_runs / subscriptions get
--         organization_id populated.
--
-- Backward compat guaranteed:
--   - users.api_token continues to work (legacy lookup path stays in api_service)
--   - All existing query patterns (WHERE user_id = ?) keep returning correct rows
--   - The new organization_id columns are nullable; V23 (after Y2 ships) makes
--     them NOT NULL.
--
-- Both parts run inside a single Flyway transaction. Either everything applies
-- or nothing does. The backfill is idempotent (NOT EXISTS guards) so a partial
-- application followed by retry is safe.

BEGIN;

-- ─── Part A: schema ────────────────────────────────────────────────────────

CREATE TYPE org_member_role AS ENUM ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER');

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(64) UNIQUE NOT NULL,
    contact_email   VARCHAR(255),
    plan_tier       VARCHAR(32) NOT NULL DEFAULT 'free',
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_active ON organizations(is_active);

CREATE TABLE organization_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            org_member_role NOT NULL DEFAULT 'MEMBER',
    invited_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);
CREATE INDEX idx_org_members_user ON organization_members(user_id);
CREATE INDEX idx_org_members_org ON organization_members(organization_id);

-- Phase Y4 will start writing rows here. Created now to lock the schema shape.
CREATE TABLE organization_api_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash      VARCHAR(128) NOT NULL,
    token_prefix    VARCHAR(16) NOT NULL,
    name            VARCHAR(128) NOT NULL,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_org_tokens_org ON organization_api_tokens(organization_id)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_org_tokens_hash ON organization_api_tokens(token_hash)
    WHERE revoked_at IS NULL;

-- Phase Y4 will start writing rows here too.
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(64) NOT NULL,
    resource_type   VARCHAR(64),
    resource_id     UUID,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_org_created ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_logs(action);

ALTER TABLE redteam_runs ADD COLUMN organization_id UUID REFERENCES organizations(id);
CREATE INDEX idx_redteam_runs_org ON redteam_runs(organization_id);

ALTER TABLE subscriptions ADD COLUMN organization_id UUID REFERENCES organizations(id);
CREATE INDEX idx_subscriptions_org ON subscriptions(organization_id);

-- ─── Part B: backfill — idempotent ─────────────────────────────────────────

-- 1. Personal org per existing user
INSERT INTO organizations (id, name, slug, contact_email, plan_tier, metadata)
SELECT
    gen_random_uuid(),
    COALESCE(NULLIF(u.display_name, ''), u.username) || ' (personal)',
    lower(substring(u.id::text, 1, 8)) || '-personal',
    u.email,
    'free',
    jsonb_build_object('migrated_from_user_id', u.id::text, 'migrated_at', NOW())
FROM users u
WHERE NOT EXISTS (
    SELECT 1 FROM organizations o
    WHERE o.slug = lower(substring(u.id::text, 1, 8)) || '-personal'
);

-- 2. Each user is OWNER of their personal org
INSERT INTO organization_members (organization_id, user_id, role)
SELECT
    o.id,
    u.id,
    'OWNER'::org_member_role
FROM users u
JOIN organizations o
  ON o.slug = lower(substring(u.id::text, 1, 8)) || '-personal'
WHERE NOT EXISTS (
    SELECT 1 FROM organization_members m
    WHERE m.organization_id = o.id AND m.user_id = u.id
);

-- 3. Backfill redteam_runs.organization_id
UPDATE redteam_runs r
SET organization_id = om.organization_id
FROM organization_members om
WHERE r.user_id = om.user_id
  AND r.organization_id IS NULL
  AND om.role = 'OWNER'::org_member_role;

-- 4. Backfill subscriptions.organization_id
UPDATE subscriptions s
SET organization_id = om.organization_id
FROM organization_members om
WHERE s.user_id = om.user_id
  AND s.organization_id IS NULL
  AND om.role = 'OWNER'::org_member_role;

COMMIT;
