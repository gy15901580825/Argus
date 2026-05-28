-- ============================================================================
-- V12 Migration: Fix subscription plan test_case limits + descriptions
-- Prod & dev databases were patched manually; this makes fresh installs match.
-- Authoritative values: free=10, starter=50, pro=200
-- ============================================================================

UPDATE subscription_plans SET
    test_cases_limit = 10,
    description = 'Get started free with 10 test cases per month.',
    features = '{"models": ["gpt-5.4-mini"], "smart_routing": false}'::jsonb
WHERE id = 'free';

UPDATE subscription_plans SET
    test_cases_limit = 50,
    price_cents = 2900,
    description = 'For individual developers. 50 test cases/month.',
    features = '{"models": ["gpt-5.4-mini", "gpt-5.3-codex"], "smart_routing": false}'::jsonb
WHERE id = 'starter';

UPDATE subscription_plans SET
    test_cases_limit = 200,
    price_cents = 9900,
    description = 'For teams. Smart routing with the best AI models. 200 test cases/month.',
    features = '{"models": ["gpt-5.4-mini", "gpt-5.3-codex", "gemini-3.1-pro", "claude-opus-4.6"], "smart_routing": true}'::jsonb
WHERE id = 'pro';
