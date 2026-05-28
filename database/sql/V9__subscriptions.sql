-- ============================================================================
-- V9 Migration: Subscription System (Stripe Integration)
-- ============================================================================

-- 1. Subscription Plans (configuration table)
CREATE TABLE subscription_plans (
    id VARCHAR(50) PRIMARY KEY,             -- 'free', 'starter', 'pro'
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL DEFAULT 0, -- Monthly price in USD cents
    test_cases_limit INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited
    stripe_price_id VARCHAR(255),           -- Stripe Price ID (NULL for free)
    features JSONB DEFAULT '{}',            -- Feature flags & limits
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO subscription_plans (id, name, description, price_cents, test_cases_limit, stripe_price_id, features) VALUES
('free', 'Free', 'Limited trial access', 0, 5, NULL,
 '{"models": ["gpt-5-mini"], "smart_routing": false}'::jsonb),
('starter', 'Starter', 'Browser exploration + test script generation. 500 test cases/month.', 4900, 500,
 'price_1TGVPM2WSicPxKeNfpnpTkEV',
 '{"models": ["gpt-5-mini", "gpt-5.1-codex"], "smart_routing": false}'::jsonb),
('pro', 'Pro', 'Smart model routing with the most capable AI models. Unlimited test cases.', 12900, 0,
 'price_1TFTz92WSicPxKeNjsszZVWS',
 '{"models": ["gpt-5-mini", "gpt-5.1-codex", "gemini-3.1-pro", "claude-opus-4.6"], "smart_routing": true}'::jsonb);

CREATE TRIGGER update_subscription_plans_updated_at
    BEFORE UPDATE ON subscription_plans
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

-- 2. Add stripe_customer_id to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255) UNIQUE;
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

-- 3. Subscriptions table
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan_id VARCHAR(50) NOT NULL DEFAULT 'free' REFERENCES subscription_plans(id),
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255) UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'active',  -- active, past_due, canceled, trialing, incomplete
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    canceled_at TIMESTAMPTZ,
    trial_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe_customer ON subscriptions(stripe_customer_id);
CREATE INDEX idx_subscriptions_stripe_sub ON subscriptions(stripe_subscription_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

CREATE TRIGGER update_subscriptions_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

-- 4. Usage quotas (monthly rolling window)
CREATE TABLE usage_quotas (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    test_cases_used INTEGER NOT NULL DEFAULT 0,
    test_cases_limit INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_user_period UNIQUE(user_id, period_start)
);

CREATE INDEX idx_usage_quotas_user_period ON usage_quotas(user_id, period_start DESC);

CREATE TRIGGER update_usage_quotas_updated_at
    BEFORE UPDATE ON usage_quotas
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

-- 5. Stripe events (idempotency)
CREATE TABLE stripe_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB
);

CREATE INDEX idx_stripe_events_event_id ON stripe_events(event_id);

-- 6. Extend ai_token_usage with subscription context
ALTER TABLE ai_token_usage ADD COLUMN IF NOT EXISTS task_id UUID;
ALTER TABLE ai_token_usage ADD COLUMN IF NOT EXISTS subscription_plan VARCHAR(50);
ALTER TABLE ai_token_usage ADD COLUMN IF NOT EXISTS routing_reason VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_ai_token_usage_task_id ON ai_token_usage(task_id) WHERE task_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_token_usage_plan ON ai_token_usage(subscription_plan) WHERE subscription_plan IS NOT NULL;

-- 7. Helper: get user's current plan
CREATE OR REPLACE FUNCTION get_user_plan(p_user_id UUID)
RETURNS VARCHAR(50) AS $$
BEGIN
    RETURN COALESCE(
        (SELECT plan_id FROM subscriptions
         WHERE user_id = p_user_id AND status IN ('active', 'trialing', 'past_due')
         LIMIT 1),
        'free'
    );
END;
$$ LANGUAGE plpgsql;

-- 8. Helper: atomic quota check-and-increment (returns TRUE if allowed)
CREATE OR REPLACE FUNCTION increment_usage_if_allowed(p_user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE usage_quotas
    SET test_cases_used = test_cases_used + 1, updated_at = NOW()
    WHERE user_id = p_user_id
      AND period_start <= NOW() AND period_end > NOW()
      AND (test_cases_limit = 0 OR test_cases_used < test_cases_limit)
    RETURNING 1 INTO v_updated;

    RETURN v_updated IS NOT NULL;
END;
$$ LANGUAGE plpgsql;
