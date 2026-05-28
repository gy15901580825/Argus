-- V15__add_chunks_to_chat_messages.sql
-- Adds nullable JSONB column on chat_messages so the frontend can persist the
-- structured StreamChunk[] array (typed log/result/web_ui_bug/web_ui_artifact/
-- ssh_result entries) alongside the flat content text.
--
-- Without this column, on session reload the chat page loses the chunk taxonomy
-- (it lived only in localStorage) and renders one giant flat blob — including
-- the entire generated pytest script body that arrived as a web_ui_artifact
-- event but got concatenated into the running text. With it, hydration uses
-- chunks[] when present and renders proper BugReportArtifact + TestScriptArtifact
-- cards; the existing flat content is kept as a fallback for old rows.
--
-- Forward-compatible: existing rows have chunks=NULL and continue to render
-- via the flat-content path. No backfill needed.

ALTER TABLE chat_messages
    ADD COLUMN chunks JSONB;
