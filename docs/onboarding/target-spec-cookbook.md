# Target spec cookbook

Argus needs to know how to reach your AI agent. The "target spec" is a small JSON file (`argus-target.json`) that describes the agent endpoint and how to authenticate against it.

The fastest way to generate it is interactively, for any of the 8 kinds `init` knows how to ask questions about (`openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `browser_use`, `payment_agent`, `mcp_agent`, `http_upload`):

```bash
argus-probe init --kind <one of those 8>
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

We provide a thin reference adapter you can drop into your agent harness; ask in the design-partner channel for the latest version.

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

**`sandbox: true` is not a formality — it's a safety interlock.** This adapter drives an agent that spends real money if you point it at a real payment endpoint. Construction is refused outright without `sandbox: true` (both the API and the CLI check it independently); there is no way to turn it off. If you think you don't need it, you're pointing this adapter at the wrong thing.

**What's on the other end:** `inner` is a nested target spec (any kind above — here, `openai_compat`) for the transport that actually talks to your agent; the payment adapter wraps it. The `testbed_url` must point at a running `payment_testbed/` instance from this repo — see `payment_testbed/README.md` for `testbed/` (mock merchant + facilitator) and `demo_agent/` (the vulnerable reference agent the example above points at). Nothing in `payment_testbed/` touches a blockchain or real funds.

**Notes:**
- `payment_agent` only runs probes whose `target_class` includes `payment_agent` (the ones under `orchestrator/orchestrator/redteam/probes/payment/`). Point an ordinary chat probe at a `payment_agent` target and it's skipped, not run; point a payment probe at a `custom_http`/`openai_compat` target and it's skipped too — the two families only match each other.
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

**`sandbox: true` is not a formality — it's a safety interlock.** This adapter drives an agent against a live MCP server. Construction is refused outright without `sandbox: true` (both the API and the CLI check it independently); there is no way to turn it off. It exists because a red-team run that can reach a real MCP server is not a configuration mistake you want to recover from after the fact.

**What's on the other end:** `inner` is a nested target spec (any kind above — here, `openai_compat`) for the transport that actually talks to your agent. The `testbed_url` must point at a running `mcp_testbed/` instance from this repo — see `mcp_testbed/README.md` for `testbed/` (the hostile MCP server, staging tool poisoning / rug-pull / shadowing / confused-deputy / credential-lure scenarios) and `demo_agent/` (the vulnerable reference MCP client the example above points at).

**Notes:**
- `mcp_agent` only runs probes whose `target_class` includes `mcp_agent` (the ones under `orchestrator/orchestrator/redteam/probes/mcp/`). Point an ordinary chat probe at an `mcp_agent` target and it's skipped, not run; point an MCP probe at a `custom_http`/`openai_compat` target and it's skipped too — the two families only match each other.
- `script` is an optional fallback scenario (`{"scenario": "tool_poisoning"}` etc.) used only when a probe declares no `scenario.payload` of its own — each probe's own payload takes precedence.

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

Once your `argus-target.json` is committed (or generated on the fly in CI), wire Argus into the same CI that runs your tests:

```yaml
# .github/workflows/argus-probe.yml
name: argus-probe
on:
  schedule:
    - cron: '0 6 * * 1'   # weekly Monday 06:00 UTC
  workflow_dispatch: {}
jobs:
  redteam:
    uses: <your-gh-user>/argus-probe-action/.github/workflows/argus-probe-reusable.yml@v1
    with:
      target-config: argus-target.json
      threshold: warn               # warn | block-on-critical | block-on-high
      per-run-cap: '0.50'           # USD ceiling per run
    secrets:
      api-token: ${{ secrets.ARGUS_API_TOKEN }}
```

The action must also see `ARGUS_API_URL` (repository variable or job `env:`) — `argus-probe` has no default endpoint, and a job that omits it fails with `Missing option '--api-url'`.

`threshold: warn` (default) reports findings without failing the build. Switch to `block-on-critical` once you trust the signal — the action then exits non-zero when a critical-severity finding lands, breaking the PR check until your team fixes or accepts.

The SARIF output is automatically uploaded to GitHub's code-scanning, so findings appear in your repo's **Security** tab alongside CodeQL / Dependabot / Snyk.

---

## Next

- [Quickstart](./quickstart.md) — install + first run
- [Threat coverage overview](./probe-id-cheatsheet.md) — what threats are covered + recommended starter sets
