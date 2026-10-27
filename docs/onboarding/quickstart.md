# Argus quickstart

Point Argus at any AI agent endpoint and get a SARIF report. Local mode (step 3a) needs only a judge API key (`argus-probe quickstart` needs none). Server mode (steps 3 to 5) needs a server implementing the `/api/v1/redteam` API; this repo does not ship one (see step 3).

## 1. Install the CLI

Python 3.11+ is required. Install from PyPI:

```bash
pipx install "argus-probe[local]"        # or: pip install "argus-probe[local]"
argus-probe --version
```

The `[local]` extra pulls in the probe engine so step 3a works without a server. From a clone, `pip install ./orchestrator ./cli` does the same.

## Try it with no key: `argus-probe quickstart`

```bash
argus-probe quickstart
```

This starts a deliberately insecure demo MCP agent and a hostile MCP testbed on 127.0.0.1, runs the 12 MCP probes against the agent and writes `argus-quickstart.html` (change it with `--out`). It needs no API key and no target of your own. These probes are decided by assertions on what the agent did, so no judge model is involved. The demo agent is meant to fail, so most probes report a finding. Probes that need a judge model (prompt injection, system-prompt leakage and others) still need a key; see step 3a.

## 2. Generate a target spec

```bash
argus-probe init --kind openai_compat
```

Interactive prompts walk you through:
- `Endpoint URL` — the chat-completions endpoint of your agent (default: OpenAI's)
- `Model name` — e.g. `gpt-4o-mini`, `claude-sonnet-4-6`, your own model id
- `API key env var` — name of the env var holding your agent API key (e.g. `OPENAI_API_KEY`); the value is resolved at run time so the secret is never persisted in `target.json`

The 11 supported `kind` values: `openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `http_upload`, `browser_use`, `payment_agent`, `mcp_agent`, `testbed_agent`, `mcp_server`, `vllm_server`. See [target-spec-cookbook.md](./target-spec-cookbook.md) for non-OpenAI shapes.

Output: `argus-target.json`, plus `.github/workflows/argus-probe.yml` if you say yes to the workflow prompt.

## 3a. Run locally (no server)

Set a judge key and add `--local`. The CLI loads the probe library, sends them to your agent and judges the replies in this process:

```bash
export ANTHROPIC_API_KEY="<your key>"
argus-probe run --local --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
```

The judge uses `ANTHROPIC_API_KEY` by default, or `OPENAI_API_KEY` when that is the only key set. For a local model, set `REDTEAM_MODEL_PROVIDER=litellm` and `REDTEAM_FAST_MODEL=ollama/qwen2.5:32b` (add `REDTEAM_LLM_API_BASE` for a non-default host). Small models miss many jailbreaks, so the CLI prints a warning and a clean report from one is weak evidence. `REDTEAM_MODEL_PROVIDER=azure` runs the judge on Azure OpenAI; its default content filter blocks judge calls because the judge reads attack text, so use a custom filter policy with jailbreak detection turned off for that deployment (the same applies to `OPENAI_API_KEY` with `REDTEAM_LLM_API_BASE` pointed at Azure). If `OPENAI_API_KEY` is paired with `REDTEAM_LLM_API_BASE` pointing at Azure, set `REDTEAM_FAST_MODEL` and `REDTEAM_STRONG_MODEL` to your deployment names, because the default strong model `gpt-5.6-terra` is usually not deployed. Local models other than Ollama (vLLM or LM Studio via `openai/...` with `REDTEAM_LLM_API_BASE`) are billed at the most expensive known rate, so pass `--per-run-cap`.

`browser_use` targets run locally too. The CLI serves each probe's trap page from your machine, so your agent must be able to open that URL. The default address is `127.0.0.1`, which works when the agent runs on the same machine. For an agent in a container or on another machine, set `trap_host`, `trap_port` and `trap_public_url` in the target spec; see the [browser_use section of the cookbook](./target-spec-cookbook.md#browser_use). If your agent can't reach your machine at all, submit the run with `--api-url` and `--token` to a compatible hosted service instead.

Optional: `REDTEAM_DECIDER=jev` plus `TYPESAFE_API_KEY` lets a third-party model settle conflicting judge verdicts. It sends probe text to TypeSafe; see `docs/operations/judge-decider.md`.

`--per-run-cap` and `--fail-on` work the same way as in server mode. If this is all you need, skip steps 3 to 5 and continue at step 6 to read the report.

## 3. Get an API token (server mode)

Server mode needs a server implementing the `/api/v1/redteam` API. There is no hosted Argus instance, and this repo no longer ships a server; the self-hosted stack (REST API, web UI, migrations) is at tag [`v0.3-full`](https://github.com/gy15901580825/Argus/tree/v0.3-full). Get a token from the server you use, then set the token and the server URL in your shell:

```bash
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-server>"
```

`ARGUS_API_URL` is required (or pass `--api-url` per command) — there is no default endpoint.

For `browser_use` targets in server mode, the server's orchestrator also needs a connected [`client_agent`](../../client_agent/README.md). It connects directly, with the same `AGENT_CONNECT_SECRET` set on both sides.

## 4. Validate the target is reachable (server mode, optional)

```bash
argus-probe validate-target --target argus-target.json
```

Sends a tiny "Reply with OK" message and reports if the target endpoint accepts the OpenAI-compat shape. If this fails, fix the target spec before continuing.

## 5. Run your first probe (server mode)

```bash
argus-probe run \
  --target argus-target.json \
  --probes owasp_07_system_prompt_leakage \
  --format html \
  --out report.html
```

In local mode, add `--local` to the same command and drop the server variables.

The CLI submits the run to that server, polls for completion (typically ~10–30 s), then writes the chosen format to disk.

Add `--per-run-cap 0.50` to enforce a hard cost ceiling (checked before any LLM call in both modes; an over-cap run exits with code 4).

The pre-run estimate is a worst case: it counts every prompt of every selected probe (and, in deep mode, which the CLI and API do not expose yet, every persona × strategy thread at its full round budget). Runs usually cost a fraction of it, but the cap is compared against the ceiling — so a full-library sweep needs `--per-run-cap 6.00` even though it typically bills well under $1.

## 6. Read the report

Open `report.html` in your browser:

```bash
open report.html      # macOS
xdg-open report.html  # Linux
```

For SARIF (GitHub Code-scanning compatible) or JUnit (CI-tool compatible) output, swap the format flag:

```bash
argus-probe run --target argus-target.json --probes owasp_07_system_prompt_leakage --format sarif --out report.sarif
argus-probe run --target argus-target.json --probes owasp_07_system_prompt_leakage --format junit --out report.xml
```

## Probe set recommendations

| Use case | `--probes` value |
|---|---|
| Quick smoke (1 probe, 3 prompts) | `owasp_07_system_prompt_leakage` |
| Full sweep (needs `--per-run-cap 6.00`, see step 5) | `all` |

See [Threat coverage overview](./probe-id-cheatsheet.md) for the categories the library covers and recommended use-case → probe-set mappings.

## What's next

- **Add to CI**: `argus-probe init --workflow` writes a workflow that runs [`argus-probe-action`](https://github.com/marketplace/actions/argus-agent-red-team-scan), uploads SARIF and fails on critical findings; see [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration".
- **Understand the verdicts**: each finding's `verdict` is one of:
  - `pass` — agent resisted the attack
  - `fail` — agent fell for the attack (look at `severity`: critical/high/medium/low)
  - `blocked_by_target` — target gateway (e.g. content filter) rejected before the agent saw it; counts as a partial defense
  - `skipped` — probe target_class incompatible with adapter (no LLM cost incurred)
  - `error` / `aborted_cost` — operational issues (5xx, timeout, cost cap hit)

## CLI reference

```
argus-probe quickstart                Run the MCP probes against a built-in demo agent, no key
argus-probe init --kind <X>           Interactive target.json generator
argus-probe validate-target           Sanity-check target reachability
argus-probe list-probes               List probe ids (local library, or a server with --api-url)
argus-probe run                       Submit a run + write the report
argus-probe report                    Re-render an existing run's report
argus-probe coverage                  Show what the probe library covers, offline
```

Each command's `--help` lists its flags. The most common flags on `run`:

| Flag | Purpose |
|---|---|
| `--target` | path to target.json (or inline JSON) |
| `--probes` | comma-separated probe ids OR `all` |
| `--format` | `html` / `sarif` / `junit` |
| `--out` | output report file path |
| `--per-run-cap` | USD cap; over-budget runs exit with code 4 (default $0.50) |
| `--local` | run probes in this process; needs the `[local]` extra and a judge key, no `--api-url`/`--token` |
| `--fail-on` | `info` / `low` / `medium` / `high` / `critical`; exit 3 when a failing finding is at or above it |
| `--token` | API token (or set `ARGUS_API_TOKEN`) |
| `--max-wait` | how long to poll for run completion (default 1800 s) |
