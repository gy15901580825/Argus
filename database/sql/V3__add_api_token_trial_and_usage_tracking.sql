-- ============================================================================
-- V3 Migration: Add API Token, Free Trial, and AI Token Usage Tracking
-- ============================================================================

-- 1. Add api_token field to users table
-- API token for programmatic access, unique and indexed for fast lookups
ALTER TABLE users 
ADD COLUMN api_token VARCHAR(255) UNIQUE;

-- Create index on api_token for fast authentication lookups
CREATE INDEX idx_users_api_token ON users(api_token) WHERE api_token IS NOT NULL;

-- 2. User Free Trial Table
-- Tracks free trial periods for users (e.g., 1 month free trial)
CREATE TABLE user_trials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    trial_started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    trial_ends_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Calculated as trial_started_at + 1 month
    is_used BOOLEAN DEFAULT FALSE, -- Whether the user has used their free trial
    is_active BOOLEAN DEFAULT TRUE, -- Whether the trial is currently active
    trial_type VARCHAR(50) DEFAULT 'MONTHLY', -- e.g., 'MONTHLY', 'WEEKLY', 'CUSTOM'
    notes TEXT, -- Additional notes about the trial
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_trial UNIQUE (user_id) -- One active trial per user
);

-- Create index on user_id for fast lookups
CREATE INDEX idx_user_trials_user_id ON user_trials(user_id);

-- Create index on trial_ends_at for querying active/expired trials
CREATE INDEX idx_user_trials_ends_at ON user_trials(trial_ends_at);

-- Create index on is_active for filtering active trials
CREATE INDEX idx_user_trials_is_active ON user_trials(is_active) WHERE is_active = TRUE;

-- Add trigger for automatic updated_at timestamp
CREATE TRIGGER update_user_trials_updated_at 
    BEFORE UPDATE ON user_trials 
    FOR EACH ROW 
    EXECUTE PROCEDURE update_updated_at_column();

-- 3. AI Token Usage Table
-- Records detailed AI token usage for each user request
CREATE TABLE ai_token_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    model_name VARCHAR(100) NOT NULL, -- e.g., 'gpt-4', 'gpt-3.5-turbo', 'gemini-pro'
    model_provider VARCHAR(50), -- e.g., 'openai', 'google', 'anthropic'
    input_tokens INTEGER NOT NULL DEFAULT 0, -- Number of input tokens used
    output_tokens INTEGER NOT NULL DEFAULT 0, -- Number of output tokens generated
    total_tokens INTEGER NOT NULL DEFAULT 0, -- Total tokens (input + output)
    request_type VARCHAR(100), -- e.g., 'chat', 'completion', 'embedding', 'agent_execution'
    request_id VARCHAR(255), -- Optional: link to specific request/session
    agent_id UUID REFERENCES client_agent(id), -- Optional: link to agent if applicable
    cost_usd DECIMAL(10, 6), -- Optional: cost in USD if available
    metadata JSONB, -- Additional metadata (request details, parameters, etc.)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on user_id for user-specific queries
CREATE INDEX idx_ai_token_usage_user_id ON ai_token_usage(user_id);

-- Create index on created_at for time-based queries and aggregations
CREATE INDEX idx_ai_token_usage_created_at ON ai_token_usage(created_at);

-- Create index on model_name for model-specific analytics
CREATE INDEX idx_ai_token_usage_model_name ON ai_token_usage(model_name);

-- Create index on request_type for usage analytics by type
CREATE INDEX idx_ai_token_usage_request_type ON ai_token_usage(request_type);

-- Composite index for common queries (user + date range)
CREATE INDEX idx_ai_token_usage_user_date ON ai_token_usage(user_id, created_at);

-- 4. AI Token Usage Summary Table (Optional but recommended for performance)
-- Pre-aggregated daily/monthly summaries for faster reporting
CREATE TABLE ai_token_usage_summary (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    summary_date DATE NOT NULL, -- The date this summary represents
    summary_period VARCHAR(20) NOT NULL DEFAULT 'DAILY', -- 'DAILY', 'MONTHLY', 'YEARLY'
    model_name VARCHAR(100), -- NULL means aggregated across all models
    total_input_tokens BIGINT NOT NULL DEFAULT 0,
    total_output_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0, -- Number of requests
    total_cost_usd DECIMAL(10, 6), -- Total cost for the period
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_summary UNIQUE (user_id, summary_date, summary_period, model_name)
);

-- Create index on user_id and summary_date for fast lookups
CREATE INDEX idx_ai_token_usage_summary_user_date ON ai_token_usage_summary(user_id, summary_date);

-- Create index on summary_period for filtering by period type
CREATE INDEX idx_ai_token_usage_summary_period ON ai_token_usage_summary(summary_period);

-- Add trigger for automatic updated_at timestamp
CREATE TRIGGER update_ai_token_usage_summary_updated_at 
    BEFORE UPDATE ON ai_token_usage_summary 
    FOR EACH ROW 
    EXECUTE PROCEDURE update_updated_at_column();

-- 5. Helper Function: Check if user has active trial
-- Returns TRUE if user has an active trial that hasn't expired
CREATE OR REPLACE FUNCTION has_active_trial(p_user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 
        FROM user_trials 
        WHERE user_id = p_user_id 
        AND is_active = TRUE 
        AND trial_ends_at > CURRENT_TIMESTAMP
    );
END;
$$ LANGUAGE plpgsql;

-- 6. Helper Function: Get user's total token usage for a date range
-- Returns total tokens used by a user in the specified date range
CREATE OR REPLACE FUNCTION get_user_token_usage(
    p_user_id UUID,
    p_start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    p_end_date TIMESTAMP WITH TIME ZONE DEFAULT NULL
)
RETURNS TABLE (
    total_input_tokens BIGINT,
    total_output_tokens BIGINT,
    total_tokens BIGINT,
    request_count BIGINT,
    total_cost_usd DECIMAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COALESCE(SUM(input_tokens), 0)::BIGINT as total_input_tokens,
        COALESCE(SUM(output_tokens), 0)::BIGINT as total_output_tokens,
        COALESCE(SUM(total_tokens), 0)::BIGINT as total_tokens,
        COUNT(*)::BIGINT as request_count,
        COALESCE(SUM(cost_usd), 0) as total_cost_usd
    FROM ai_token_usage
    WHERE user_id = p_user_id
    AND (p_start_date IS NULL OR created_at >= p_start_date)
    AND (p_end_date IS NULL OR created_at <= p_end_date);
END;
$$ LANGUAGE plpgsql;
