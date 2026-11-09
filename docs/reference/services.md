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

`/healthz`, `/docs`, `/redoc` and `/openapi.json` stay open without a token. `/agent/connect` does not use `ARGUS_SERVER_TOKEN`; it has its own `AGENT_CONNECT_SECRET`.

| Method | Path | Role |
|--------|------|------|
| GET  | `/healthz` | Health, version, judge model names and cost caps. No token, no model call, no network |
| POST | `/redteam/run/preflight` | Cost-cap check without running probes (402 when over the cap) |
| POST | `/redteam/run` | Execute a red-team run. An empty `probe_ids` selects every probe the target kind can run |
| GET  | `/redteam/probes` | Probe library |
| GET  | `/redteam/suites` | Probe suites |
| GET  | `/redteam/coverage` | Standards coverage |
| WS   | `/agent/connect` | Client-agent WebSocket hub (requires the `x-agent-id` header, plus `x-agent-secret` when `AGENT_CONNECT_SECRET` is set; a second connection with a live agent id is refused) |

### Finding events

Each finding in the `POST /redteam/run` stream includes `events`. The `POST /redteam/scenario/run` stream also includes the array inside the finding object sent with `event: finding`. See [finding events in run.json](../run-json.md#finding-events) for the fields, operations, object kinds, and parent links. Findings without supported event evidence contain `[]`.

The scenario finding passes through `ctx.redact` when serialized and when emitted in the SSE stream. That redaction masks credentials, email addresses, and values under keys with sensitive names. Trusted finding event structure fields survive both passes, including `event_id`, `parent_event_ids`, `ts`, `operation`, `basis`, `source`, `atlas_technique`, and `seq`. Event field names stay intact. `actor`, `tool_name`, `tool_call_id`, `object_ref`, and `summary` undergo normal text redaction. An object reference whose kind becomes unknown is null, and a summary remains at most 200 characters after redaction.

### `GET /healthz`

`/healthz` is the one health path. It sits outside `/redteam` because everything under `/redteam` needs the bearer token when `ARGUS_SERVER_TOKEN` is set, and a load balancer probe does not carry one. It makes no model call and opens no network connection. It always returns 200 with this body:

```json
{
  "status": "ok",
  "version": "1.7.0",
  "judge": {"provider": "anthropic", "fast_model": "claude-haiku-4-5-20251001", "strong_model": "claude-sonnet-4-6"},
  "per_run_cap_usd": {"static": 0.5, "deep": 5.0},
  "daily_cap_usd": 13.5
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `status` | string | Always `"ok"` when the process answers. |
| `version` | string | The installed `argus-probe` version, or `"unknown"` when the package metadata is missing. |
| `judge` | object | The judge a run started now would use, resolved from the environment on each request the same way `POST /redteam/run` resolves it. `provider`, `fast_model` and `strong_model` are strings. |
| `judge.error` | string | Present instead of the three judge fields when the judge settings do not resolve, for example an unknown `REDTEAM_MODEL_PROVIDER`. It is the exception type name only. `POST /redteam/run` answers 500 on the same settings. |
| `per_run_cap_usd.static` | number | Default per-run cap for static runs, in US dollars. A request's `per_run_cap_usd` overrides it. |
| `per_run_cap_usd.deep` | number | Default per-run cap for deep runs, in US dollars. |
| `daily_cap_usd` | number | The process-wide daily cap (`REDTEAM_DAILY_CAP_USD`, default 13.50). |

The body never contains an API key, a token or a base URL. The model names and caps are the only settings it shows. `/healthz` does not check the judge credentials, so a 200 does not mean they are valid.

When the app starts, the server logs the same body once on the `OrchestratorAPI` logger at INFO level, as `argus server config {...}` with the body as JSON.

### Read-only routes

| Route | 200 body |
|-------|----------|
| `GET /redteam/probes` | `{"probe_ids": [string, ...]}`. Every probe id in the loaded library. |
| `GET /redteam/suites` | `{"suites": {suite_id: [probe_id, ...]}}`. Only suites with at least one probe. |
| `GET /redteam/coverage` | `{"coverage": {"standards": {...}, "totals": {...}, "thin_threshold": number}}`. The library-level coverage table, with no run results. |
| `POST /redteam/run/preflight` | `{}` when the run fits the caps. Over a cap it answers 402 with `{"detail": string}`. |

Request errors on `/redteam/run` and `/redteam/run/preflight` use FastAPI's `{"detail": ...}` body: 422 for a bad target, probe id, suite or mode, 402 for a cost cap, 500 for missing judge settings. These come before any stream starts.

### Stream contract: `POST /redteam/run`

A 200 response is a Server-Sent Events stream (`Content-Type: text/event-stream`). Each frame ends with a blank line. A frame is either one `data:` line, or an `event:` line followed by one `data:` line. Every `data:` line holds one JSON object. Every stream payload masks registered target-spec secret values with the same function and `***` token as run.json. This includes findings, deep transcripts, `deep_run` metadata, coverage, error details, and cleanup reports. Payloads are normalized to JSON values, as run.json does, then masked at the stream boundary before the frame is encoded. This also masks tuples that JSON converts to arrays.

Deep mode first emits a bare `data:` frame with `type: "deep_run"` and `deep`
selection metadata. It then emits one finding per persona/strategy thread,
instead of one finding per round; `evidence.transcript` holds all rounds.
Static finding frames remain unchanged. Consumers must distinguish metadata
from findings before computing counts.

After the optional deep metadata frame, the remaining frames come in this order:

1. Zero or more finding frames, one per finding, as bare `data:` lines. The object has exactly the keys of a run.json finding, listed in [the run.json format](../run-json.md#run-summary), and no others.
2. One coverage frame, a bare `data:` line whose `type` is `"coverage"`.
3. `event: end` with `data: {}`.

If the run fails after the stream starts, the coverage frame and `event: end` are not sent. The stream ends with `event: error` instead. Findings sent before the failure stay valid.

A finding object never has a `type` key, so `type == "coverage"` tells the coverage frame apart from a finding.

#### Coverage frame

```json
{"type": "coverage", "coverage": {...}, "summary": {...}, "cost": {"spent_usd": 0.0412, "per_run_cap_usd": 0.5}}
```

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | Always `"coverage"`. |
| `coverage` | object | The per-standard coverage table, the same object `GET /redteam/coverage` returns, with this run's results filled in. |
| `summary` | object | Counts of this run's findings, described below. |
| `cost` | object | `spent_usd` and `per_run_cap_usd`, both numbers, described below. |
| `target_cleanup` | object | Optional target cleanup report, described below. Omitted when the target returns no report. |

`summary` counts this run's findings:

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

`cost.spent_usd` is the cost of this run's model calls in US dollars, rounded to six decimals. It is the engine's own estimate from model token usage and its price table, not an invoice. `cost.per_run_cap_usd` is the per-run cap the run was held to. It is the request's `per_run_cap_usd` when set, otherwise the server's default for the mode (static or deep). It is always a number. A run stopped at the cap can show `spent_usd` above `per_run_cap_usd` by the one call that crossed it.

#### `event: end`

`data: {}`. The run finished and every finding was sent.

#### `event: error`

```json
{"detail": "per_run cap $0.05 exceeded: this run has spent $0.0600", "type": "CostExceededError", "cost": {"spent_usd": 0.06, "per_run_cap_usd": 0.05}}
```

| Field | Type | Meaning |
|-------|------|---------|
| `detail` | string | The error message. |
| `type` | string | The exception class name. `CostExceededError` means the run stopped at a cost cap. Probes that did not start are sent first as `aborted_cost` findings. `CleanupStateUnknown` means the cleanup report could not be read or validated; its detail is "cleanup state unknown". |
| `cost` | object | The same shape as the coverage frame's `cost`. |
| `target_cleanup` | object | Optional target cleanup report, described below. Omitted when the target returns no report or its report is invalid. |
| `judge_blocked` | object | Only when `type` is `JudgeBlockedError`: a provider content filter refused a judge or attacker prompt. It holds `provider` (string), `model` (string, the model or deployment), `categories` (array of strings, empty when the provider names none) and `fallback` (`"off"` when a fallback provider exists but a block does not use it, `"<provider>/<model>: <error type>"` when the other attempt failed too, or null). |

#### `target_cleanup`

The existing coverage payload on success and error payload on failure can include this object. It adds no frame. Targets with no cleanup report omit the key; it is never null.

| Field | Type | Meaning |
|-------|------|---------|
| `complete` | boolean | True only when `open` is empty and every abort is `done` or `not_needed`. |
| `done` | integer | Completed undo intents and delivery aborts. |
| `open` | array of objects | Unfinished records with `scope`, `step`, `status`, `method`, `url` (string or null), and `http_status` (integer or null). Abort records also have `attempt` (integer) and optional `failure_reason` (string). |
| `stop_reason` | string or null | The transport stop reason, if any. |
| `leftover` | array of strings | Required list of resources for manual review, including resources with no undo. |
| `aborts` | array of objects | Optional delivery abort records with the same fields as an open abort record. |

See [target cleanup in run.json](../run-json.md#target-cleanup) for statuses and completion rules. An invalid report omits `target_cleanup` and produces the "cleanup state unknown" diagnostic introduced with the public cleanup contract. When another exception already stopped the run, its type and original detail remain, and the diagnostic is appended to `detail`.

#### Stability policy

Within a major version of `argus-probe`, the stream frames, the `/healthz` body and the route bodies above change only by addition: a new key, a new frame type or a new `event:` name. A client must ignore keys and event names it does not know. Renaming or removing a key, changing a key's type, or changing the frame order needs a new major version, and the release notes announce it. Tests in `tests/test_contract_freeze.py`, `tests/test_server_routes.py`, `tests/test_redteam_coverage_api.py`, `tests/test_server_run_cost_cap.py` and `tests/test_judge_blocked.py` pin these shapes, so a rename fails CI.

The `/api/v1/redteam` API the CLI uses in server mode (runs, reports, diffs, stored history) is not part of this repo. It was served by `api_service`, which lives at tag `v0.3-full`.
