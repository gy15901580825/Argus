# Service Reference

Request flows and orchestrator API endpoints.

## Request Flow: Browser-agent probe

```
Orchestrator red-team run (target kind browser_use)
  → RedteamBridge (argus/connection_manager.py) picks the first connected client agent
    → JSON-RPC `redteam_browser_probe` over the /agent/connect WebSocket
      → Client Agent (redteam_runner.BrowserProbe) serves a scenario page on localhost
      → TargetAgentDriver POSTs the scenario URL + prompt to the customer's browser agent
    → Client Agent replies on the same WebSocket with the probe result
  → Orchestrator judges the result and records the finding
```

## API Endpoints

### Orchestrator (`python -m argus.server`, port 8080)

Install with `pip install "argus-probe[server]"`; the `server` extra adds the WebSocket library uvicorn needs for `/agent/connect`.

| Method | Path | Role |
|--------|------|------|
| POST | `/redteam/run/preflight` | Cost-cap check without running probes (402 when over the cap) |
| POST | `/redteam/run` | Execute a red-team run |
| GET  | `/redteam/probes` | Probe library |
| GET  | `/redteam/suites` | Probe suites |
| GET  | `/redteam/coverage` | Standards coverage |
| WS   | `/agent/connect` | Client-agent WebSocket hub (requires the `x-agent-id` header, plus `x-agent-secret` when `AGENT_CONNECT_SECRET` is set; a second connection with a live agent id is refused) |

The `/api/v1/redteam` API the CLI uses in server mode (runs, reports, diffs, stored history) is not part of this repo. It was served by `api_service`, which lives at tag `v0.3-full`.
