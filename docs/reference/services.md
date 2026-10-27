# Service Reference

Request flows, API endpoints, and frontend components.

## Request Flow: Browser-agent probe

```
Orchestrator red-team run (target kind browser_use)
  → RedteamBridge (connection_manager.py) picks the first connected client agent
    → JSON-RPC `redteam_browser_probe` over the /agent/connect WebSocket
      → Client Agent (redteam_runner.BrowserProbe) serves a scenario page on localhost
      → TargetAgentDriver POSTs the scenario URL + prompt to the customer's browser agent
    → Client Agent replies on the same WebSocket with the probe result
  → Orchestrator judges the result and records the finding
```

## API Endpoints

### API Service (`api_service`, port 8881)

| Method | Path | Role |
|--------|------|------|
| POST | `/api/v1/redteam/runs` | Start a red-team run (proxied to the orchestrator) |
| GET  | `/api/v1/redteam/runs/{run_id}` | Run status and findings |
| GET  | `/api/v1/redteam/runs/{run_id}/diff?base=` | Diff against a base run |
| GET  | `/api/v1/redteam/runs/{run_id}/report` | Rendered report |
| GET  | `/api/v1/redteam/probes` | Probe library |
| GET  | `/api/v1/redteam/coverage` | Standards coverage |
| GET  | `/api/v1/chat/sessions/{id}/planner-history` | Service-to-service: last N*2 user/assistant messages (content capped at 500 chars). Requires `x-service-secret` + `x-user-id` headers. |

`routers/orchestrator.py` still mounts `/api/v1/orchestrator/strategy/stream`, `/run_command` and `/cancel-web-ui-test`. The orchestrator endpoints behind them have been removed, so these proxies no longer work.

### Orchestrator (`orchestrator`, port 8081)

| Method | Path | Role |
|--------|------|------|
| POST | `/redteam/run/preflight` | Cost-cap check without running probes (402 when over the cap) |
| POST | `/redteam/run` | Execute a red-team run |
| GET  | `/redteam/probes` | Probe library |
| GET  | `/redteam/suites` | Probe suites |
| GET  | `/redteam/coverage` | Standards coverage |
| WS   | `/agent/connect` | Client-agent WebSocket hub (requires the `x-agent-id` header) |

## Frontend Components

Key components in `frontend/src/components/`:

| Component | File | Role |
|-----------|------|------|
| `StreamingMessage` | `StreamingMessage.tsx` | Renders typed chunks: logs, results, errors, SSH/API results, web UI bugs, artifacts |
| `BugReportCard` | `BugReportCard.tsx` | Web UI test results: severity badges (critical/high/medium/low), bug list, screenshot player, allure download |
| `TestScriptArtifact` | `TestScriptArtifact.tsx` | Generated script display with syntax highlighting, download, save |
| `WebUIConfigPanel` | `WebUIConfigPanel.tsx` | Web UI test configuration (target URL, persona, max steps) |
| `OAuthTokenDialog` | `OAuthTokenDialog.tsx` | OAuth token management |

The chat and web-UI components above still call `streamStrategy()` in `api.ts`, which targets the removed strategy stream.
