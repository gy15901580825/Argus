# argus-probe

Open-source CLI for [Argus](https://github.com/gy15901580825/Argus), black-box red-team testing for AI agents.

Point `argus-probe` at any AI agent endpoint — chat APIs, custom HTTP services, gRPC, or browser-using agents — and get a report mapped to MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, and the EU AI Act.

```
$ argus-probe run --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
Submitting run to https://<your-argus-host>/api/v1/redteam/runs ...
  run_id: abc123
Polling until completion...
  status: completed, findings: 1
Fetching html report...
Wrote report to report.html
```

## Install

Python 3.11+ is required.

```bash
pipx install "argus-probe[local]"
# or
pip install "argus-probe[local]"
```

The `[local]` extra installs the probe engine (`argus-orchestrator`) for `--local`. A plain `pip install argus-probe` gives server mode only: the CLI can then only talk to an Argus API server.

From a clone of the repo: `pip install ./orchestrator ./cli`.

## Quickstart

```bash
# 1. Generate a target spec interactively
argus-probe init --kind openai_compat

# 2a. Run locally: set a judge key, no server needed
export ANTHROPIC_API_KEY="<your key>"
argus-probe run --local --target argus-target.json \
  --probes owasp_07_system_prompt_leakage --format html --out report.html

# 2b. Or submit to your own Argus API server
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-argus-host>"
argus-probe validate-target --target argus-target.json
argus-probe run --target argus-target.json \
  --probes owasp_07_system_prompt_leakage --format html --out report.html
```

`--local` does not support `browser_use` targets; submit those to a server.

There is no hosted Argus instance. `ARGUS_API_URL` is your own `api_service` deployment, and the token is the `api_token` of a user on that server. An admin mints one with `POST /api/v1/admin/users` and `"api_token_only": true`; see the [quickstart](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/quickstart.md) for the first-admin step.

## Supported agent shapes

`argus-probe init --kind <X>` generates a target spec for one of:

| `--kind` | For |
|---|---|
| `openai_compat` | OpenAI Chat Completions protocol — OpenAI, Azure OpenAI, Foundry, Mistral, vLLM/llama.cpp with the OpenAI shim |
| `anthropic_native` | Anthropic Messages API |
| `custom_http` | Production agents wrapping an LLM behind their own HTTP shape (Jinja2 request templates + JSONPath response selectors) |
| `grpc` | gRPC services with server reflection enabled |
| `browser_use` | Browser-using agents driving Playwright / computer-use / browser-use |
| `payment_agent` | Agents that spend money on a user's behalf (e.g. x402), run against a payment testbed |
| `mcp_agent` | Agents that connect to MCP tool servers, run against a hostile MCP testbed |
| `testbed_agent` | Generic form of `mcp_agent` / `payment_agent`; `environment` picks the testbed |
| `http_upload` | File-upload-and-render sinks (upload then inline-render an active payload) |

Full configuration reference: [target spec cookbook](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/target-spec-cookbook.md).

## What it does

Without `--local`, `argus-probe` is a thin client: it submits the target spec and probe selection to an Argus service over HTTPS; the service runs the probes against your agent and returns the report. With `--local` the same engine runs in this process and calls the judge model directly with your key.

Secret references in your target spec (`${OPENAI_API_KEY}`, etc.) are resolved from the local shell environment at run time and sent only as outbound headers to your agent — they never enter the target.json file or the Argus service.

## Output formats

- `html` — human-readable report
- `sarif` — SARIF 2.1.0, uploads cleanly to GitHub code-scanning (Security tab)
- `junit` — JUnit XML for any CI tool that parses test results

## CI integration

Use [`argus-probe-action`](https://github.com/marketplace/actions/argus-agent-red-team-scan). It installs `argus-probe[local]` from PyPI, runs the probes in local mode, uploads the SARIF to code scanning and fails the job at `fail-on`:

```yaml
- uses: actions/checkout@v4
- uses: gy15901580825/argus-probe-action@v1
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  with:
    target: argus-target.json
    probes: owasp_01_prompt_injection_basic,syscard_crescendo
    fail-on: critical
```

The job needs `permissions: security-events: write` for the SARIF upload. `argus-probe init --workflow` writes a complete workflow file with that set. Pull requests from forks and Dependabot do not receive repository secrets, so `ANTHROPIC_API_KEY` is empty and the job fails on them.

`--fail-on <severity>` exits 3 when a failing finding is at or above that level; the SARIF is written first. `--compare-to <base branch>` makes `--fail-on` count only failures that are new relative to the latest run on that branch. It is server mode only, because it needs run history, so the action does not offer it; see the target-spec cookbook for a server-mode workflow. Exit codes: 0 success, 1 run or configuration error, 2 usage error or `--local` without the engine installed, 3 threshold hit, 4 cost cap.

## Cost controls

```bash
argus-probe run --target ... --per-run-cap 0.50
```

Runs that would exceed the cap are rejected before any LLM cost is incurred, in both server and local mode (exit code 4).

## Subcommands

```
argus-probe init                Interactive target.json generator
argus-probe validate-target     Sanity-check target reachability
argus-probe list-probes         List probe ids available to your account
argus-probe run                 Submit a run + write the report
argus-probe report              Re-render an existing run's report
argus-probe coverage            Show what the probe library covers; asks the server, runs no probes
```

Each command's `--help` lists its flags.

## License

Apache-2.0 — see [LICENSE](https://github.com/gy15901580825/Argus/blob/main/cli/LICENSE). Copyright © 2026 Veyon Solutions.

## Security

To report a vulnerability: see [SECURITY.md](https://github.com/gy15901580825/Argus/blob/main/cli/SECURITY.md).

## Links

- Documentation: [docs/onboarding](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/)
- Argus repo: https://github.com/gy15901580825/Argus
