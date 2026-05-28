-- 6. Client Agent Table
-- This table stores agent information for each user, including the current task ID
CREATE TABLE client_agent (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_name VARCHAR(255) NOT NULL,
    agent_type VARCHAR(100), -- e.g., 'sequential', 'parallel', 'loop', 'custom'
    agent_config TEXT, -- JSON configuration or other config data
    current_task_id VARCHAR(255), -- Current task ID (can be UUID or string)
    status VARCHAR(50) DEFAULT 'active', -- e.g., 'active', 'inactive', 'running', 'idle'
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_agent_name UNIQUE (user_id, agent_name) -- One agent name per user
);

-- Create index on user_id for faster lookups
CREATE INDEX idx_client_agent_user_id ON client_agent(user_id);

-- Create index on current_task_id for task-related queries
CREATE INDEX idx_client_agent_current_task_id ON client_agent(current_task_id) WHERE current_task_id IS NOT NULL;

-- Create index on status for filtering active agents
CREATE INDEX idx_client_agent_status ON client_agent(status);

-- Add trigger for automatic updated_at timestamp
CREATE TRIGGER update_client_agent_updated_at 
    BEFORE UPDATE ON client_agent 
    FOR EACH ROW 
    EXECUTE PROCEDURE update_updated_at_column();
