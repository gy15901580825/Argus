# Service Reference

Request flows and orchestrator API endpoints.

## Request Flow: Browser-agent probe

```
Orchestrator red-team run (target kind browser_use)
  → RedteamBridge (argus/connection_manager.py) picks the first connected client agent
    → JSON-RPC `redteam_browser_probe` over the /agent/connect WebSocket
      → Client Agent (redteam_runner.BrowserProbe) serves a scenario page (localhost by default)
      → TargetAgentDriver POSTs the scenario URL + prompt to the customer's browser agent
    → Client Agent replies on the same WebSocket with the probe result
  → Orchestrator judges the result and records the finding
```

The `redteam_browser_probe` message carries two text fields. `prompt` is the user's instruction and is what the client agent sends to the browser agent; `payload` is the hostile scenario planted in the trap page and must never be treated as the instruction. A probe without a `scenario` block sends its prompt in both fields.

The message can also carry `trap_host`, `trap_port` and `trap_public_url`, copied from the target spec. Each key is present only when the spec sets a value other than the default, and is never null. The client agent binds the trap page to `trap_host` and `trap_port`, and sends the browser agent `trap_public_url` with `/scenario` appended. A missing key keeps the default: `127.0.0.1`, a free port, and a URL built from the bound address.

The client agent's reply includes `trap_url`, the URL it sent the browser agent. When the spec sets any trap field, the orchestrator checks `trap_url` against those settings. If `trap_url` is missing or does not match, the probe gets an `error` finding that says "client_agent did not use the trap settings (upgrade client_agent)". A client agent older than this field causes that error.

## API Endpoints

### Orchestrator (`python -m argus.server`, port 8080)

Install with `pip install "argus-probe[server]"`; the `server` extra adds the WebSocket library uvicorn needs for `/agent/connect`.

The server is configured with these environment variables:

| Variable | Default | Effect |
|----------|---------|--------|
| `ARGUS_SERVER_HOST` | `127.0.0.1` | Address to bind. The Docker image sets `0.0.0.0`. |
| `PORT` | `8080` | Port to bind. |
| `ARGUS_SERVER_TOKEN` | unset | When set, every `/redteam/*` request must send `Authorization: Bearer <token>`; others get 401. |
| `ARGUS_SERVER_ALLOW_UNAUTHENTICATED` | unset | Set to `1` to start on a non-loopback address without a token, for example when a proxy in front of the server does the authentication. |

The server refuses to start, with exit code 1, when `ARGUS_SERVER_HOST` is not a loopback address and `ARGUS_SERVER_TOKEN` is not set, unless `ARGUS_SERVER_ALLOW_UNAUTHENTICATED=1`. `/redteam/run` makes the server send requests to whatever target the caller names and spends the server's judge budget, so it should not be open to a network.

`/docs`, `/redoc` and `/openapi.json` stay open without a token. `/agent/connect` does not use `ARGUS_SERVER_TOKEN`; it has its own `AGENT_CONNECT_SECRET`.

| Method | Path | Role |
|--------|------|------|
| POST | `/redteam/run/preflight` | Cost-cap check without running probes (402 when over the cap) |
| POST | `/redteam/run` | Execute a red-team run |
| GET  | `/redteam/probes` | Probe library |
| GET  | `/redteam/suites` | Probe suites |
| GET  | `/redteam/coverage` | Standards coverage |
| WS   | `/agent/connect` | Client-agent WebSocket hub (requires the `x-agent-id` header, plus `x-agent-secret` when `AGENT_CONNECT_SECRET` is set; a second connection with a live agent id is refused) |

The `/api/v1/redteam` API the CLI uses in server mode (runs, reports, diffs, stored history) is not part of this repo. It was served by `api_service`, which lives at tag `v0.3-full`.
