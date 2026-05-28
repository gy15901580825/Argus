# Service Reference

Detailed request flows, API endpoints, and frontend components.

## Request Flow: Web UI Test

```
Frontend (/chat or /web-ui-test)
  → SSE stream to Orchestrator (/api/v1/orchestrator/strategy/stream)
    → Orchestrator dispatches to ClientWebUIAgent
      → WebSocket command to Client Agent
        → browser-use + Playwright explores target URL
        → Screenshots uploaded to API Service → R2
      → Client Agent returns results via WebSocket
    → Orchestrator PATCHes API Service with final results (bug report, test script, screenshots)
  → SSE events streamed back to frontend in real-time
```

## Request Flow: API Test on Cloud

```
Frontend (/chat, remote_test_enabled=true)
  → POST /api/v1/orchestrator/strategy/stream (SSE)
    → API Service proxy: validates trial token, injects subscription_plan & user_id
      → POST /orchestrator/v1/strategy/stream (internal)
        → Orchestrator: SmartPipeline → ContentAnalyzer → ApiTestingAgent
          → POST /agent/run on testing_api_service
            → LLM (gpt-5.4-mini) generates pytest suite (conftest + functional + security)
            → Uploads test zip to R2
            → Decision: SSH or Test-Runner?
              • SSH path: if ssh_config has remote_ip + username + pem_key_base64
                → SFTP upload + docker exec pytest on remote host
              • Test-Runner path (default): POST /api/v1/run → poll /api/v1/status/{id}
                → In-cluster k8s service (test-runner.test-runner.svc.cluster.local:8000)
            → Returns ssh_result event (success, stdout, stderr, exit_code, allure_url)
          → Orchestrator yields artifact + ssh_result events
        → SSE stream ends
      → Frontend parses: log, progress, result, ssh_result, error, artifact, web_ui_bug, web_ui_artifact
        → Renders via StreamingMessage → APITestResultCard / BugReportCard / TestScriptArtifact
```

## API Endpoints

### API Service (`api_service`, port 8881)

| Method | Path | Role |
|--------|------|------|
| POST | `/api/v1/orchestrator/strategy/stream` | SSE proxy to orchestrator (validates trial tokens, injects user context) |
| POST | `/api/v1/orchestrator/run_command` | Proxy JSON-RPC command to orchestrator |
| POST | `/api/v1/orchestrator/cancel-web-ui-test` | Cancel active web UI test |
| POST | `/api/v1/orchestrator/strategy/upload-script` | Save generated script to R2 or base64 data URI |
| GET  | `/api/v1/chat/sessions/{id}/planner-history` | Service-to-service: last N*2 user/assistant messages (content capped at 500 chars) for orchestrator planner core history. Requires `x-service-secret` + `x-user-id` headers. |

**StrategyRequest model** (routers/orchestrator.py): `content`, `context`, `session_id`, `user_id`, `local_test_enabled`, `remote_test_enabled`, `ssh_config`

> **Pitfall**: If a new field is added to the orchestrator's StrategyRequest but not to api_service's StrategyRequest, Pydantic silently drops the field during proxy — causing "network error" or silent feature loss.

### Orchestrator (`orchestrator`, port 8081)

| Method | Path | Role |
|--------|------|------|
| POST | `/orchestrator/v1/strategy/stream` | Main SSE streaming endpoint |
| POST | `/orchestrator/run_command` | WebSocket command dispatch to client agents |
| POST | `/orchestrator/v1/cancel-web-ui-test` | Cancel web UI test task |

### Testing API Service (`testing_api_service`, port 8000)

| Method | Path | Role |
|--------|------|------|
| POST | `/agent/run` | Main entry: LLM generates tests, executes via SSH or test-runner, streams SSE |

## Frontend Components

Key components in `frontend/src/components/`:

| Component | File | Role |
|-----------|------|------|
| `StreamingMessage` | `StreamingMessage.tsx` | Renders typed chunks: logs, results, errors, SSH/API results, web UI bugs, artifacts |
| `BugReportCard` | `BugReportCard.tsx` | Web UI test results: severity badges (critical/high/medium/low), bug list, screenshot player, allure download |
| `TestScriptArtifact` | `TestScriptArtifact.tsx` | Generated script display with syntax highlighting, download, save |
| `WebUIConfigPanel` | `WebUIConfigPanel.tsx` | Web UI test configuration (target URL, persona, max steps) |
| `OAuthTokenDialog` | `OAuthTokenDialog.tsx` | OAuth token management |

**StreamChunk types** (`StreamingMessage.tsx`): `log`, `result`, `code`, `error`, `ssh_result`, `web_ui_bug`, `web_ui_artifact`

**Streaming data flow** (`api.ts`): `streamStrategy()` → SSE fetch → parse JSON events → classify into `TypedStreamChunk` → render via `StreamingMessage`
