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

The message can also carry `trap_host`, `trap_port` and `trap_public_url`, copied from the target spec. Each key is present only when the spec sets a value other than the default, and is never null. The client agent binds the trap page to `trap_host` and `trap_port`, and sends the browser agent `trap_public_url` followed by a random path token and `/scenario`. The sink lives under the same token. Requests without it get a 404 and are not recorded. A missing key keeps the default: `127.0.0.1`, a free port, and a URL built from the bound address.

The client agent's reply includes `trap_url`, the URL it sent the browser agent. When the spec sets any trap field, the orchestrator checks `trap_url` against those settings. If `trap_url` is missing or does not match, the probe gets an `error` finding that says "client_agent did not use the trap settings (upgrade client_agent)". A client agent older than this field causes that error.

The reply also carries `trap_evidence`, the trap server's record of what the browser agent did: `page_loads`, `interaction_count` and `trap_requests`, one entry per request to the sink with `method`, `path`, `query`, `body` and `complete`. The orchestrator decides browser probes from this record, not from the agent's reply alone, and masks every recorded value that does not contain the probe's canary before it stores the finding ([run.json](../run-json.md) describes the fields). A reply without `trap_evidence`, or with an entry missing a field, is a delivery error. So server-mode browser runs need a client agent from this release; with an older one every browser probe ends as an `error` finding that asks you to upgrade the client agent.

## API Endpoints

### Orchestrator (`python -m argus.server`, port 8080)

Install with `pip install "argus-probe[server]"`; the `server` extra adds the WebSocket library uvicorn needs for `/agent/connect`.

The server is configured with these environment variables:

| Variable | Default | Effect |
|----------|---------|--------|
| `ARGUS_SERVER_HOST` | `127.0.0.1` | Address to bind. The Docker image sets `0.0.0.0`. |
| `PORT` | `8080` | Port to bind. |
| `ARGUS_SERVER_TOKEN` | unset | When set, every `/redteam/*` request must send `Authorization: Bearer <token>`; others get 401. |
| `AGENT_CONNECT_SECRET` | unset | When set, a client agent must send it in the `x-agent-secret` header to connect to `/agent/connect`. |
| `ARGUS_SERVER_ALLOW_UNAUTHENTICATED` | unset | Set to `1` to start on a non-loopback address without `ARGUS_SERVER_TOKEN` or `AGENT_CONNECT_SECRET`. This leaves both `/redteam/*` and `/agent/connect` open to anything that reaches the port, so use it only behind a proxy that authenticates both. |

The server refuses to start, with exit code 1, when `ARGUS_SERVER_HOST` is not a loopback address and either `ARGUS_SERVER_TOKEN` or `AGENT_CONNECT_SECRET` is not set, unless `ARGUS_SERVER_ALLOW_UNAUTHENTICATED=1`. `/redteam/run` makes the server send requests to whatever target the caller names and spends the server's judge budget. A client agent on `/agent/connect` receives probe payloads and returns results into runs. Neither should be open to a network. Use different values for the two secrets: a client agent machine needs only `AGENT_CONNECT_SECRET`, and the API token would let it start runs. On a loopback address, a missing `AGENT_CONNECT_SECRET` only logs a warning.

`/docs`, `/redoc` and `/openapi.json` stay open without a token. `/agent/connect` does not use `ARGUS_SERVER_TOKEN`; it has its own `AGENT_CONNECT_SECRET`.

| Method | Path | Role |
|--------|------|------|
| POST | `/redteam/run/preflight` | Cost-cap check without running probes (402 when over the cap) |
| POST | `/redteam/run` | Execute a red-team run. An empty `probe_ids` selects every probe the target kind can run |
| GET  | `/redteam/probes` | Probe library |
| GET  | `/redteam/suites` | Probe suites |
| GET  | `/redteam/coverage` | Standards coverage |
| WS   | `/agent/connect` | Client-agent WebSocket hub (requires the `x-agent-id` header, plus `x-agent-secret` when `AGENT_CONNECT_SECRET` is set; a second connection with a live agent id is refused) |

### `POST /redteam/run` stream

The response is a Server-Sent Events stream: one `data:` line per finding, then one `data:` line with the coverage event, then `event: end` with `data: {}`. If the run fails, the stream ends with `event: error` instead, and no coverage event is sent.

The coverage event has three keys:

```json
{"type": "coverage", "coverage": {...}, "summary": {...}}
```

`coverage` is the per-standard coverage table (the same object `GET /redteam/coverage` returns, with run results filled in). `summary` counts this run's findings:

```json
{
  "total": 0,
  "evaluated": 0,
  "evaluated_verdicts": ["fail", "pass", "warn"],
  "by_verdict": {"fail": 0, "pass": 0, "warn": 0, "skipped": 0, "blocked_by_target": 0, "aborted_cost": 0, "error": 0},
  "failed_by_severity": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
}
```

`total` counts findings. `evaluated` counts findings whose verdict is in `evaluated_verdicts`: the probe reached the target and came back with a verdict. This is the same rule coverage uses for `tested`. `blocked_by_target`, `skipped`, `aborted_cost` and `error` findings are not evaluated. `by_verdict` counts every finding and always lists all seven verdicts. `failed_by_severity` counts only `fail` findings and always lists all five severities. A verdict or severity outside these lists gets its own key. The summary has no score and no percentage. If you compute a rate, divide by `evaluated`, not `total`. `summary.total` counts findings, while `coverage.totals.probes_run` counts distinct probes that were evaluated, so the two numbers can differ.

The `/api/v1/redteam` API the CLI uses in server mode (runs, reports, diffs, stored history) is not part of this repo. It was served by `api_service`, which lives at tag `v0.3-full`.
