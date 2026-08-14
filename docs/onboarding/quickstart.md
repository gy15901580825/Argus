# Argus 5-minute quickstart

Point Argus at any AI agent endpoint and get a SARIF report in 5 minutes.

## 1. Install the binary

Linux x86_64:

```bash
curl -sSL https://github.com/<your-gh-user>/cli/releases/download/v0.1.1/argus-probe-linux-x86_64 \
  -o /usr/local/bin/argus-probe
chmod +x /usr/local/bin/argus-probe
argus-probe --version
```

macOS arm64:

```bash
curl -sSL https://github.com/<your-gh-user>/cli/releases/download/v0.1.1/argus-probe-darwin-arm64 \
  -o /usr/local/bin/argus-probe
chmod +x /usr/local/bin/argus-probe
```

Or via pip (if you have Python 3.11+):

```bash
pip install git+https://github.com/<your-gh-user>/cli.git@v0.1.1
```

## 2. Generate a target spec

```bash
argus-probe init --kind openai_compat
```

Interactive prompts walk you through:
- `Endpoint URL` — the chat-completions endpoint of your agent (default: OpenAI's)
- `Model name` — e.g. `gpt-4o-mini`, `claude-sonnet-4-6`, your own model id
- `API key env var` — name of the env var holding your agent API key (e.g. `OPENAI_API_KEY`); the value is resolved at run time so the secret is never persisted in `target.json`

The 5 supported `kind` values: `openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `browser_use`. See [target-spec-cookbook.md](./target-spec-cookbook.md) for non-OpenAI shapes.

Output: `argus-target.json` + optionally `.github/workflows/argus-probe.yml`.

## 3. Get an Argus API token

Email `<contact@example.com>` with your company name. Design partners get tokens within 24h. Set in your shell, along with the Argus instance the CLI should talk to:

```bash
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-argus-host>"
```

`ARGUS_API_URL` is required (or pass `--api-url` per command) — there is no default endpoint.

## 4. Validate the target is reachable (optional)

```bash
argus-probe validate-target --target argus-target.json
```

Sends a tiny "Reply with OK" message and reports if the target endpoint accepts the OpenAI-compat shape. If this fails, fix the target spec before continuing.

## 5. Run your first probe

```bash
argus-probe run \
  --target argus-target.json \
  --probes owasp_07_system_prompt_leakage \
  --format html \
  --out report.html
```

The CLI submits the run to the Argus API, polls for completion (typically ~10–30 s), then writes the chosen format to disk.

Add `--per-run-cap 0.50` to enforce a hard cost ceiling (server-side; over-cap predicted runs return HTTP 402 before any LLM call).

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
| Curated starter set | (probe-id list ships in your design-partner welcome email) |
| Full sweep (~$0.50, ~3 min) | `all` |

See [Threat coverage overview](./probe-id-cheatsheet.md) for the categories the library covers and recommended use-case → probe-set mappings.

## What's next

- **Add to GitHub Actions**: see [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration"
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
```

Each command's `--help` lists its flags. The most common flags on `run`:

| Flag | Purpose |
|---|---|
| `--target` | path to target.json (or inline JSON) |
| `--probes` | comma-separated probe ids OR `all` |
| `--format` | `html` / `sarif` / `junit` |
| `--out` | output report file path |
| `--per-run-cap` | USD cap; over-budget runs reject with HTTP 402 (default $0.50) |
| `--token` | API token (or set `ARGUS_API_TOKEN`) |
| `--max-wait` | how long to poll for run completion (default 600 s) |
