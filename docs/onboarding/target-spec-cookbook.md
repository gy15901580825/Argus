# Target spec cookbook

Argus needs to know how to reach your AI agent. The "target spec" is a small JSON file (`argus-target.json`) that describes the agent endpoint and how to authenticate against it.

The fastest way to generate it is interactively, for any of the 9 kinds `init` knows how to ask questions about (`openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `browser_use`, `payment_agent`, `mcp_agent`, `testbed_agent`, `http_upload`):

```bash
argus-probe init --kind <one of those 9>
```

Below are copy-paste templates for each supported agent shape, plus the gotchas we've run into in real deployments.

---

## openai_compat

**Use this for**: any endpoint that speaks the OpenAI Chat Completions protocol — OpenAI itself, Azure OpenAI, Azure AI Foundry, Mistral, DeepSeek-on-Foundry, llama.cpp / vLLM with the OpenAI shim, etc.

```json
{
  "kind": "openai_compat",
  "endpoint_url": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-4o-mini",
  "api_key": "${OPENAI_API_KEY}"
}
```

**Notes:**
- The `${OPENAI_API_KEY}` reference is resolved from your shell env at run time — the actual secret never gets persisted in the JSON file.
- Some endpoints expect an `api-key` header instead of `Authorization: Bearer` (Azure OpenAI does this). Use `extra_headers` to override:
  ```json
  "extra_headers": [["api-key", "${AZURE_OPENAI_KEY}"]]
  ```
- Content-filter responses (HTTP 400 on adversarial prompts) are a *correct* signal — they appear as `verdict=blocked_by_target` findings, not as errors. This represents a partial defense win for your stack.

---

## anthropic_native

**Use this for**: agents that call the Anthropic Messages API directly (different request/response shape from OpenAI-compat).

```json
{
  "kind": "anthropic_native",
  "model": "claude-sonnet-4-6",
  "api_key": "${ANTHROPIC_API_KEY}",
  "max_tokens": 1024
}
```

---

## custom_http

**Use this for**: production agents that wrap an LLM behind their own HTTP shape — almost every "real" customer-facing agent falls into this category. The agent's request and response don't follow OpenAI's format, but you can describe them with a request template + a response selector.

```json
{
  "kind": "custom_http",
  "request_url": "https://my-agent.example/chat",
  "request_method": "POST",
  "request_headers": [
    ["Content-Type", "application/json"],
    ["Authorization", "Bearer ${MY_AGENT_TOKEN}"]
  ],
  "request_body_template": "{\"input\": {{prompt|tojson}}, \"session_id\": \"argus\"}",
  "response_jsonpath": "$.choices[0].message.content"
}
```

How the body is built: `request_body_template` is a Jinja2 template. `{{prompt|tojson}}` substitutes the adversarial prompt with proper JSON escaping, so embedded quotes / backslashes / newlines never break the JSON envelope.

The template can also use `{{conversation_id}}`. It is a fresh id for each conversation and stays the same across the turns of one conversation. Use it for agents that keep chat state per session id. `mcp-trap` sends every round as a new conversation.

How the response is parsed: `response_jsonpath` is a [JSONPath](https://goessner.net/articles/JsonPath/) expression that extracts the agent's reply text from the JSON response.

**Notes:**
- A bad request template will silently produce a malformed body. Sanity-check it with `curl` once before running probes:
  ```bash
  curl -X POST <request_url> -H 'Content-Type: application/json' -d '{"input": "hello", "session_id": "test"}'
  ```
- A JSONPath that doesn't match returns an empty string (not an error). If your `verdict=fail` findings show empty `target_response`, your JSONPath is probably wrong — re-check by manually running a curl and applying the path to the response.
- TLS errors → check that `request_url` is `https://` and the target's certificate chain is valid.

---

## grpc

**Use this for**: gRPC services that have server reflection enabled.

```json
{
  "kind": "grpc",
  "endpoint": "agent.example:50051",
  "service_method": "agent.AgentService/Chat",
  "prompt_field": "user_input",
  "response_field": "response",
  "tls": true
}
```

**Requirements:**
- Reflection must be enabled on your gRPC server. Check with:
  ```bash
  grpcurl -plaintext agent.example:50051 list
  ```
  If this returns the list of services, reflection is on. If it errors, your gRPC team needs to register `grpc.reflection.v1alpha.ServerReflection`.
- `prompt_field` and `response_field` must currently be top-level string fields on the request and response messages. Nested-message fields are coming in a future release; if your contract requires that today, talk to us — we can usually work around it.

---

## browser_use

**Use this for**: browser-using agents — anything driving a real browser via Playwright, computer-use, browser-use, or similar. Argus hosts the adversarial scenario page (DOM-injection HTML, phishing UI, visual-payload image, OS-command bait) at a transient URL and asks your agent to navigate to it.

```json
{
  "kind": "browser_use",
  "agent_url": "https://my-browser-agent.example/run",
  "scenario_kind": "dom_injection"
}
```

`scenario_kind` selects the attack format: `dom_injection` / `ui_phishing` / `visual_injection` / `os_cmd`.

**Agent contract:**
- The `agent_url` must accept `POST {"url": "<scenario URL>", "prompt": "<user instruction>"}`.
- It must return JSON: `{"final_text": "...", "screenshots": [...], "latency_ms": <number>}`.

**Running it.** `argus-probe run --local` runs `browser_use` targets on your machine; see [Running browser probes locally](#running-browser-probes-locally) below. In server mode, a `browser_use` run needs a server implementing the `/api/v1/redteam` API, backed by the orchestrator, with a [`client_agent`](../../client_agent/README.md) connected to that orchestrator's WebSocket hub. The client agent serves the scenario page and calls your `agent_url`. This repo does not ship such a server; the self-hosted stack is at tag `v0.3-full`. The client agent can connect directly to the orchestrator:

```bash
cd client_agent && pip install -r requirements.txt && playwright install chromium
export AGENT_CONNECT_SECRET=<shared secret>      # same value as on the orchestrator
python client_agent.py --orchestrator-url ws://<orchestrator-host>:8080 --agent-name my-browser-agent
```

Anyone who can reach the orchestrator's `/agent/connect` can pose as an agent and receive probe payloads. Set `AGENT_CONNECT_SECRET` on both sides and keep the orchestrator on localhost or a trusted network.

We provide a thin reference adapter you can drop into your agent harness; ask in the design-partner channel for the latest version.

### Running browser probes locally

`argus-probe run --local` runs browser probes on your machine with no server and no client_agent. For each probe the CLI serves the trap page itself and sends your agent its URL. Browser probes are judged, so set a judge key:

```bash
pipx install argus-probe
export ANTHROPIC_API_KEY=<your key>
argus-probe run --local --target argus-target.json \
  --probes browser_dom_inject_html_comment,browser_os_cmd_install_tutorial --format html --out report.html
```

Your agent must be able to open the trap page URL. By default the page listens on `127.0.0.1` on a free port, which works when the agent runs on the same machine. If the agent runs in a container or on another machine, set where the page listens and the URL the agent should open:

```json
{
  "kind": "browser_use",
  "agent_url": "http://192.168.1.30:8000/run",
  "scenario_kind": "dom_injection",
  "trap_host": "0.0.0.0",
  "trap_port": 8765,
  "trap_public_url": "http://192.168.1.20:8765"
}
```

- `trap_host` is the IPv4 address the trap page listens on. The default is `127.0.0.1`. `0.0.0.0` listens on every interface and needs `trap_public_url`.
- `trap_port` is the port it listens on. The default `0` picks a free port for each probe. Set a fixed port when you set `trap_public_url`.
- `trap_public_url` is the base URL your agent opens. Argus adds `/scenario` to it. Use your LAN address, `http://host.docker.internal:8765` for an agent in Docker, or a tunnel URL that forwards to `trap_port`.

With `0.0.0.0`, anyone on your network can open the trap page while the run lasts. Use your machine's LAN address as `trap_host` when you can. These three options only apply to `--local`. Without `--local` the CLI refuses a spec that sets them.

If your agent can't reach your machine at all, submit the run with `--api-url` and `--token` to a compatible hosted service instead.

---

## payment_agent

**Use this for**: agents that spend money on a user's behalf — quoting, authorizing, and settling payments (e.g. the x402 protocol). Unlike the kinds above, this adapter doesn't just relay a prompt and hand back text: it opens a session on a payment testbed, tells the agent where the paid resource lives, and afterwards reports what the agent actually authorized there. That record, not the reply text, is what the probe's assertions judge.

```json
{
  "kind": "payment_agent",
  "testbed_url": "http://127.0.0.1:8090",
  "inner": {
    "kind": "openai_compat",
    "endpoint_url": "http://127.0.0.1:8091/v1/chat/completions",
    "model": "argus-demo-payment-agent"
  },
  "sandbox": true
}
```

**`sandbox: true` is not a formality — it's a safety interlock.** This adapter drives an agent that spends real money if you point it at a real payment endpoint. Construction is refused outright without `sandbox: true` (both the engine and the CLI check it independently); there is no way to turn it off. If you think you don't need it, you're pointing this adapter at the wrong thing.

**What's on the other end:** `inner` is a nested target spec (any kind above — here, `openai_compat`) for the transport that actually talks to your agent; the payment adapter wraps it. The `testbed_url` must point at a running `payment_testbed/` instance from this repo — see `payment_testbed/README.md` for `testbed/` (mock merchant + facilitator) and `demo_agent/` (the vulnerable reference agent the example above points at). Nothing in `payment_testbed/` touches a blockchain or real funds.

**Notes:**
- `payment_agent` only runs probes whose `target_class` includes `payment_agent` (the ones under `argus/probes/payment/`). Point an ordinary chat probe at a `payment_agent` target and it's skipped, not run; point a payment probe at a `custom_http`/`openai_compat` target and it's skipped too — the two families only match each other.
- `script` is an optional fallback merchant script (`quote_amount`, `payee_override`, `inject_followup`, `fail_first_settle`) used only when a probe declares no `scenario.payload` of its own — each probe's own payload takes precedence.

---

## mcp_agent

**Use this for**: agents that connect to MCP tool servers. Same shape as `payment_agent`: instead of just relaying a prompt, it opens a session on a hostile MCP testbed, tells the agent where the (poisoned) MCP server lives, and afterwards reports which tools the agent called, with what arguments, and whether the server changed a tool's description mid-session.

```json
{
  "kind": "mcp_agent",
  "testbed_url": "http://127.0.0.1:8092",
  "inner": {
    "kind": "openai_compat",
    "endpoint_url": "http://127.0.0.1:8093/v1/chat/completions",
    "model": "argus-demo-mcp-agent"
  },
  "sandbox": true
}
```

**`sandbox: true` is not a formality — it's a safety interlock.** This adapter drives an agent against a live MCP server. Construction is refused outright without `sandbox: true` (both the engine and the CLI check it independently); there is no way to turn it off. It exists because a red-team run that can reach a real MCP server is not a configuration mistake you want to recover from after the fact.

**What's on the other end:** `inner` is a nested target spec (any kind above — here, `openai_compat`) for the transport that actually talks to your agent. The `testbed_url` must point at a running `mcp_testbed/` instance from this repo — see `mcp_testbed/README.md` for `testbed/` (the hostile MCP server, staging tool poisoning / rug-pull / shadowing / confused-deputy / credential-lure scenarios) and `demo_agent/` (the vulnerable reference MCP client the example above points at).

**Notes:**
- `mcp_agent` only runs probes whose `target_class` includes `mcp_agent` (the ones under `argus/probes/mcp/`). Point an ordinary chat probe at an `mcp_agent` target and it's skipped, not run; point an MCP probe at a `custom_http`/`openai_compat` target and it's skipped too — the two families only match each other.
- `script` is an optional fallback scenario (`{"scenario": "tool_poisoning"}` etc.) used only when a probe declares no `scenario.payload` of its own — each probe's own payload takes precedence.

---

## mcp_server

**Use this for**: an MCP server you run over HTTP (Streamable HTTP), checked for the exposure in [GHSA-mvf5-2qqv-rg3c](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-mvf5-2qqv-rg3c). There, a server accepted requests from any web origin, had no authentication, and listed a tool that returned the whole environment, so any page open in the developer's browser could read every secret. This target tests the server, not an agent.

```json
{
  "kind": "mcp_server",
  "url": "http://127.0.0.1:3001/mcp",
  "headers": [["Authorization", "Bearer <token a legitimate client uses>"]]
}
```

**What it sends:** an OPTIONS preflight and an `initialize` with a foreign `Origin`, an `initialize` without `headers`, then `initialize` + `tools/list` with `headers`. **It never sends `tools/call`.** Listing an env-dump tool is enough to prove the exposure, and calling it would copy your secrets into the report.

**Probes** (`argus/probes/mcp_server/`, decided by assertions, no judge):

| probe | fails when |
|---|---|
| `mcp_server_foreign_origin` | `initialize` from a foreign Origin succeeds. The reason says whether CORS also lets any page read the reply. Without CORS, the server is still open to DNS rebinding |
| `mcp_server_no_auth` | `initialize` without credentials succeeds |
| `mcp_server_sensitive_tools` | `tools/list` names a tool that dumps env vars, runs commands or reads files. It also fails when `tools/list` does not answer, because tools it cannot see are not proven absent. Give `headers` if the server needs them |
| `mcp_server_known_vulnerable_version` | `serverInfo` names a server with a published advisory, at a version below the fix. That covers server-everything (GHSA-mvf5-2qqv-rg3c) and server-filesystem (GHSA-4gxg-m5jx-9j57), both fixed in 2.0.1. The date-versioned releases report a fixed old `serverInfo.version` ("2.0.0" and "0.2.0"), so they all count as below the fix. It also fails when no `initialize` returns `serverInfo` |

**Notes:**
- The legacy SSE transport (`GET /sse` + `POST /message`) is not covered.
- No `sandbox` flag. The adapter only reads, so point it at your own server only.

---

## vllm_server

**Use this for**: a vLLM server you run, checked against published vLLM advisories. This target tests the model server, not an agent.

```json
{
  "kind": "vllm_server",
  "url": "http://10.0.0.5:8000"
}
```

`url` is the server root, not the `/v1` path. `headers` is optional and only needed when a proxy in front of vLLM requires it; vLLM's own `--api-key` does not cover `/version`.

**What it sends:** one `GET /version`. Nothing else. The advisories are denial-of-service bugs, so the version is the only evidence it collects.

**Probe:** `vllm_server_known_vulnerable_version` fails when the version falls inside a known advisory range, and names each advisory. It also fails when `/version` gives no version or the version does not parse (for example a `.dev` build), because an unidentified server is not proven safe.

---

## testbed_agent

**Use this for**: the generic form of `mcp_agent` and `payment_agent`. The `environment` field (`mcp` or `payment`) selects which testbed it drives, and the rest of the spec is the same shape. `environment` also decides which probes apply (the `mcp/` or `payment/` probe families).

```json
{
  "kind": "testbed_agent",
  "environment": "mcp",
  "testbed_url": "http://127.0.0.1:8092",
  "inner": {
    "kind": "openai_compat",
    "endpoint_url": "http://127.0.0.1:8093/v1/chat/completions",
    "model": "argus-demo-mcp-agent"
  },
  "sandbox": true
}
```

`sandbox: true` is required here too, and both the engine and the CLI refuse the spec without it.

---

## http_upload

**Use this for**: file-upload-and-render sinks — an endpoint that accepts a file upload and later serves it back to be rendered (the CVE-2026-42138 shape: unauthenticated upload followed by inline rendering of active content). Distinct from `custom_http` because the probe's `prompt` is treated as the file body, not a chat turn: the adapter POSTs it as `multipart/form-data`, extracts the render URL from the upload response, then GETs that URL and returns the rendered body.

```json
{
  "kind": "http_upload",
  "upload_url": "https://my-agent.example/api/upload",
  "upload_field_name": "file",
  "upload_filename": "payload.svg",
  "upload_content_type": "image/svg+xml",
  "render_url_jsonpath": "$.url"
}
```

**Notes:**
- Exactly one of `render_url_jsonpath` or `render_url_header` must be set — how the adapter finds the render URL in the upload response (a JSON body field vs. a response header like `Location`). Setting both, or neither, is rejected at construction.
- If the render URL can't be located, the adapter returns the upload response body itself so the judge can still inspect it, rather than erroring.
- `upload_headers` / `render_headers` / `extra_form_fields` are Jinja2 templates rendered with `{{api_key}}` in scope, so a bearer token only needs to be written once via the `api_key` field.

---

## GitHub Actions integration

Use [`argus-probe-action`](https://github.com/marketplace/actions/argus-agent-red-team-scan). It installs `argus-probe` from PyPI, runs the probes in local mode, uploads the SARIF to code scanning and applies the `fail-on` gate. `argus-probe init --workflow` writes this file (the `OPENAI_API_KEY` line appears because the target spec reads that key):

```yaml
# .github/workflows/argus-probe.yml
# Generated by `argus-probe init`. Customize as needed.
name: argus-probe
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    # Weekly Monday 06:00 UTC
    - cron: '0 6 * * 1'
  workflow_dispatch: {}

jobs:
  redteam:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: gy15901580825/argus-probe-action@v1
        env:
          # The LLM judge.
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        with:
          target: argus-target.json
          probes: owasp_01_prompt_injection_basic,syscard_crescendo
          fail-on: critical
```

Add `ANTHROPIC_API_KEY` and any key your target spec references as repository secrets. Pull requests from forks and Dependabot do not receive repository secrets, so the keys are empty and the job fails on them.

`fail-on: critical` fails the job when a critical finding lands; use `high` to tighten it, or set it to `""` to report without blocking. The SARIF uploads before the gate runs, so findings appear in the repo's **Security** tab either way. Other inputs: `per-run-cap` (USD, default `0.50`), `format`, `output`, `upload-sarif`, `argus-version`.

### Server mode: gate only on new failures

The action always runs in local mode, which keeps no run history. To fail a pull request only on failures that are new relative to the base branch, run the CLI against a server implementing the `/api/v1/redteam` API with `--compare-to`:

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install argus-probe
      # PRs gate only on failures new relative to the base branch; pushes to main record the baseline.
      - run: >
          argus-probe run --target argus-target.json
          --probes owasp_01_prompt_injection_basic,syscard_crescendo
          --format sarif --out argus.sarif --fail-on critical
          ${{ github.event_name == 'pull_request' && format('--compare-to {0}', github.base_ref) || '' }}
        env:
          ARGUS_API_URL: ${{ vars.ARGUS_API_URL }}
          ARGUS_API_TOKEN: ${{ secrets.ARGUS_API_TOKEN }}
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: argus.sarif
```

Set `ARGUS_API_URL` as a repository variable and `ARGUS_API_TOKEN` as a secret. `argus-probe` has no default endpoint, and a job that omits the URL fails with `Missing option '--api-url'`.

Keep both the `pull_request` and `push` triggers and pass `--compare-to` only on pull requests. A scheduled or push run on `main` would compare `main` with itself, and without a completed run on `main` every failure counts as new.

Two limits: a severity increase on a probe that was already failing does not count as new. Branch detection reads GitHub Actions variables or git, so on other CI systems with a detached HEAD no branch is recorded and every failure counts as new.

---

## mcp-trap

`argus-probe mcp-trap` takes a plain chat spec and needs no special kind. Use `openai_compat`, `custom_http` or `grpc`, whichever reaches your agent's chat endpoint.

```bash
argus-probe mcp-trap --target ./target.json --print-config
```

The agent must be able to reach the trap as an MCP server. Add the printed entry to the agent's MCP config, attach nothing else, and restart the agent if it reads config only at startup. For `custom_http`, put `{{conversation_id}}` in the request template if your agent keeps state per session,. The full walkthrough, the exit codes and the other-host setup are in [cli.md](../cli.md#test-your-agent-against-a-hostile-mcp-server).

---

## Next

- [Quickstart](./quickstart.md) — install + first run
- [Threat coverage overview](./probe-id-cheatsheet.md) — what threats are covered + recommended starter sets
