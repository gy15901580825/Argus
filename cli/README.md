# argus-probe

Open-source CLI for [Argus](https://www.example.com), the red-team testing service for AI agents.

Point `argus-probe` at any AI agent endpoint — chat APIs, custom HTTP services, gRPC, or browser-using agents — and get a report mapped to MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, and the EU AI Act.

```
$ argus-probe run --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
[..] submitted run abc123
[..] polling for completion (typically 10–30s)
[..] report written to report.html
```

## Install

**Linux x86_64**

```bash
curl -sSL https://github.com/<your-gh-user>/cli/releases/download/v0.1.1/argus-probe-linux-x86_64 \
  -o /usr/local/bin/argus-probe
chmod +x /usr/local/bin/argus-probe
```

**macOS arm64**

```bash
curl -sSL https://github.com/<your-gh-user>/cli/releases/download/v0.1.1/argus-probe-darwin-arm64 \
  -o /usr/local/bin/argus-probe
chmod +x /usr/local/bin/argus-probe
```

**From source (Python 3.11+)**

```bash
pip install git+https://github.com/<your-gh-user>/cli.git@v0.1.1
```

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

Get an API token by emailing `<contact@example.com>`.

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

Full configuration reference: [target spec cookbook](https://www.example.com/docs).

## What it does

`argus-probe` is a thin client. It submits the target spec and probe selection to the Argus service over HTTPS; the service runs the probes against your agent and returns the report. The CLI itself does not call LLMs or store secrets.

Secret references in your target spec (`${OPENAI_API_KEY}`, etc.) are resolved from the local shell environment at run time and sent only as outbound headers to your agent — they never enter the target.json file or the Argus service.

## Output formats

- `html` — human-readable report
- `sarif` — SARIF 2.1.0, uploads cleanly to GitHub code-scanning (Security tab)
- `junit` — JUnit XML for any CI tool that parses test results

## CI integration

Wire into GitHub Actions with the official action:

```yaml
- uses: <your-gh-user>/argus-probe-action@v1
  env:
    ARGUS_API_URL: ${{ vars.ARGUS_API_URL }}   # required — the CLI has no default endpoint
  with:
    api-token: ${{ secrets.ARGUS_API_TOKEN }}
    target-config: argus-target.json
    threshold: block-on-critical
```

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
```

Each command's `--help` lists its flags.

## License

Apache-2.0 — see [LICENSE](./LICENSE). Copyright © 2026 Veyon Solutions.

## Security

To report a vulnerability: see [SECURITY.md](./SECURITY.md).

## Links

- Documentation: https://www.example.com/docs
- Become a design partner: https://www.example.com/design-partners
- Pricing: https://www.example.com/pricing
