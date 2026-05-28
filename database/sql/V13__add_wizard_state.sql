-- V13__add_wizard_state.sql
-- Adds nullable JSONB column for planner option-picker wizard state.
-- Wizard initializes only on the first user turn of a session; existing
-- sessions keep wizard_state = NULL and follow the free-text planner path.

ALTER TABLE chat_sessions
    ADD COLUMN wizard_state JSONB;

-- Partial index: only rows with an active wizard are queried by round_n lookups.
CREATE INDEX idx_chat_sessions_wizard_active
    ON chat_sessions ((wizard_state->>'active'))
    WHERE wizard_state->>'active' = 'true';
