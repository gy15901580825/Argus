# argus-probe

Open-source CLI for [Argus](https://github.com/gy15901580825/Argus), black-box red-team testing for AI agents.

Point `argus-probe` at any AI agent endpoint — chat APIs, custom HTTP services, gRPC, or browser-using agents — and get a report mapped to MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, and the EU AI Act.

```
$ argus-probe run --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
[..] submitted run abc123
[..] polling for completion (typically 10–30s)
[..] report written to report.html
```

## Install

Python 3.11+ is required. There are no prebuilt binaries and no PyPI package; install from the Argus repo:

```bash
pip install "git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"
```

From a clone of the repo, `pip install ./cli` does the same.

## Quickstart

```bash
# 1. Generate a target spec interactively
argus-probe init --kind openai_compat

# 2. Set your Argus API token and instance URL
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-argus-host>"

# 3. Sanity-check the target is reachable
argus-probe validate-target --target argus-target.json

# 4. Run a probe
argus-probe run \
  --target argus-target.json \
  --probes owasp_07_system_prompt_leakage \
  --format html --out report.html
```

There is no hosted Argus instance. `ARGUS_API_URL` is your own `api_service` deployment, and the token is the `api_token` of a user on that server. An admin mints one with `POST /api/v1/admin/users` and `"api_token_only": true`; see the [quickstart](../docs/onboarding/quickstart.md) for the first-admin step.

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
| `http_upload` | File-upload-and-render sinks (upload then inline-render an active payload) |

Full configuration reference: [target spec cookbook](../docs/onboarding/target-spec-cookbook.md).

## What it does

`argus-probe` is a thin client. It submits the target spec and probe selection to the Argus service over HTTPS; the service runs the probes against your agent and returns the report. The CLI itself does not call LLMs or store secrets.

Secret references in your target spec (`${OPENAI_API_KEY}`, etc.) are resolved from the local shell environment at run time and sent only as outbound headers to your agent — they never enter the target.json file or the Argus service.

## Output formats

- `html` — human-readable report
- `sarif` — SARIF 2.1.0, uploads cleanly to GitHub code-scanning (Security tab)
- `junit` — JUnit XML for any CI tool that parses test results

## CI integration

There is no published GitHub Action. Run the CLI in a workflow step and upload the SARIF:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
- run: pip install "git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"
- run: >
    argus-probe run --target argus-target.json
    --probes owasp_01_prompt_injection_basic,syscard_crescendo
    --format sarif --out argus.sarif
  env:
    ARGUS_API_URL: ${{ vars.ARGUS_API_URL }}      # the CLI has no default endpoint
    ARGUS_API_TOKEN: ${{ secrets.ARGUS_API_TOKEN }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus.sarif
```

The job needs `permissions: security-events: write` for the SARIF upload. `argus-probe init --workflow` writes a complete workflow file with that set.

`argus-probe run` does not exit non-zero on findings. To fail the build on severity, read `argus.sarif` in a later step.

## Cost controls

```bash
argus-probe run --target ... --per-run-cap 0.50
```

Runs that would exceed the cap are rejected by the service before any LLM cost is incurred (HTTP 402).

## Subcommands

```
argus-probe init                Interactive target.json generator
argus-probe validate-target     Sanity-check target reachability
argus-probe list-probes         List probe ids available to your account
argus-probe run                 Submit a run + write the report
argus-probe report              Re-render an existing run's report
argus-probe coverage            Show what the probe library covers, offline
```

Each command's `--help` lists its flags.

## License

Apache-2.0 — see [LICENSE](./LICENSE). Copyright © 2026 Veyon Solutions.

## Security

To report a vulnerability: see [SECURITY.md](./SECURITY.md).

## Links

- Documentation: [docs/onboarding](../docs/onboarding/)
- Argus repo: https://github.com/gy15901580825/Argus
