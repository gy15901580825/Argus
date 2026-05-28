-- ============================================================================
-- V4 Migration: Add publishing status to documents table
-- ============================================================================

-- Add is_published column (default false)
ALTER TABLE documents
ADD COLUMN is_published BOOLEAN DEFAULT FALSE;

-- Add published_at column (timestamp)
ALTER TABLE documents
ADD COLUMN published_at TIMESTAMP WITH TIME ZONE;

-- Create index on is_published for filtering published documents
CREATE INDEX idx_documents_is_published ON documents(is_published);
