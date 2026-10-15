# Argus quickstart

Point Argus at any AI agent endpoint and get a SARIF report. Local mode (step 3a) needs only a judge API key. Server mode (step 3) needs a running Argus API server.

## 1. Install the CLI

Python 3.11+ is required. There are no prebuilt binaries and no PyPI package; install from this repo:

```bash
pip install "argus-probe[local] @ git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"
argus-probe --version
```

The `[local]` extra pulls in the probe engine so step 3a works without a server. From a clone, `pip install ./orchestrator ./cli` does the same.

## 2. Generate a target spec

```bash
argus-probe init --kind openai_compat
```

Interactive prompts walk you through:
- `Endpoint URL` — the chat-completions endpoint of your agent (default: OpenAI's)
- `Model name` — e.g. `gpt-4o-mini`, `claude-sonnet-4-6`, your own model id
- `API key env var` — name of the env var holding your agent API key (e.g. `OPENAI_API_KEY`); the value is resolved at run time so the secret is never persisted in `target.json`

The 8 supported `kind` values: `openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `http_upload`, `browser_use`, `payment_agent`, `mcp_agent`. See [target-spec-cookbook.md](./target-spec-cookbook.md) for non-OpenAI shapes.

Output: `argus-target.json`, plus `.github/workflows/argus-probe.yml` if you say yes to the workflow prompt.

## 3a. Run locally (no server)

Set a judge key and add `--local`. The CLI loads the 205 probes, sends them to your agent and judges the replies in this process:

```bash
export ANTHROPIC_API_KEY="<your key>"        # or REDTEAM_MODEL_PROVIDER=azure plus the Azure variables
argus-probe run --local --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
```

`--local` does not support `browser_use` targets; submit those to a server.

`--per-run-cap` and `--fail-on` work the same way as in server mode. If this is all you need, skip steps 3 to 5 and continue at step 6 to read the report.

## 3. Get an Argus API token (server mode)

There is no hosted Argus instance. Run your own `api_service` (see [local-dev.md](../runbooks/local-dev.md)); the token is the `api_token` column of a row in its `users` table. An admin mints one with `POST /api/v1/admin/users` and `"api_token_only": true`. There is no bootstrap step for the first admin, so insert that first row directly in the database with role `SUPER_ADMIN`. Then set the token and the server URL in your shell:

```bash
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-argus-host>"
```

`ARGUS_API_URL` is required (or pass `--api-url` per command) — there is no default endpoint.

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

The CLI submits the run to the Argus API, polls for completion (typically ~10–30 s), then writes the chosen format to disk.

Add `--per-run-cap 0.50` to enforce a hard cost ceiling (server-side; over-cap predicted runs return HTTP 402 before any LLM call).

The pre-run estimate is a worst case: it counts every prompt of every selected probe (and, in deep mode, every persona × strategy thread at its full round budget). Runs usually cost a fraction of it, but the cap is compared against the ceiling — so a full-library sweep needs `--per-run-cap 6.00` even though it typically bills well under $1.

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

- **Add to CI**: `argus-probe init --workflow` writes a starter workflow that uploads SARIF and fails on critical findings (`--fail-on critical`); see [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration". There is no published GitHub Action
- **Understand the verdicts**: each finding's `verdict` is one of:
  - `pass` — agent resisted the attack
  - `fail` — agent fell for the attack (look at `severity`: critical/high/medium/low)
  - `blocked_by_target` — target gateway (e.g. content filter) rejected before the agent saw it; counts as a partial defense
  - `skipped` — probe target_class incompatible with adapter (no LLM cost incurred)
  - `error` / `aborted_cost` — operational issues (5xx, timeout, cost cap hit)

## CLI reference

```
argus-probe init --kind <X>           Interactive target.json generator
argus-probe validate-target           Sanity-check target reachability
argus-probe list-probes               List probe ids the server has loaded
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
| `--per-run-cap` | USD cap; over-budget runs reject with HTTP 402 (default $0.50) |
| `--local` | run probes in this process; needs the `[local]` extra and a judge key, no `--api-url`/`--token` |
| `--fail-on` | `info` / `low` / `medium` / `high` / `critical`; exit 3 when a failing finding is at or above it |
| `--token` | API token (or set `ARGUS_API_TOKEN`) |
| `--max-wait` | how long to poll for run completion (default 1800 s) |
