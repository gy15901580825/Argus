-- ============================================================================
-- V6 Migration: Add Trial Tokens for One-Time API Testing Links
-- ============================================================================

-- Trial tokens table for one-time anonymous API test links
-- Each token allows a single unauthenticated API test run
CREATE TABLE trial_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    is_consumed BOOLEAN DEFAULT FALSE,
    consumed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Fast lookup by token (primary validation path)
CREATE INDEX idx_trial_tokens_token ON trial_tokens(token);

-- Rate-limit queries: count unconsumed tokens per email
CREATE INDEX idx_trial_tokens_email ON trial_tokens(email);

-- Cleanup queries for expired tokens
CREATE INDEX idx_trial_tokens_expires_at ON trial_tokens(expires_at);
