-- V8: Add artifact columns to web_ui_tasks for R2 persistence
ALTER TABLE web_ui_tasks
    ADD COLUMN IF NOT EXISTS screenshot_urls JSONB,
    ADD COLUMN IF NOT EXISTS final_output    TEXT;
