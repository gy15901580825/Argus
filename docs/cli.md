# argus-probe

Open-source CLI for [Argus](https://github.com/gy15901580825/Argus), black-box red-team testing for AI agents.

Point `argus-probe` at any AI agent endpoint — chat APIs, custom HTTP services, gRPC, or browser-using agents — and get a report mapped to MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, and the EU AI Act.

```
$ argus-probe run --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
Submitting run to https://<your-server>/api/v1/redteam/runs ...
  run_id: abc123
Polling until completion...
  status: completed, findings: 1
Fetching html report...
Wrote report to report.html
```

## Install

Python 3.11+ is required.

```bash
pipx install argus-probe
# or
pip install argus-probe
```

The package includes the probe engine, so `--local`, `quickstart`, `list-probes` and `scan-skill` work after a plain install. The `[local]` extra still exists for older pins but adds nothing.

The unrelated `argus` project on PyPI also installs a top-level `argus` package. Do not install it in the same environment as `argus-probe`; `pipx` keeps each tool in its own venv.

To use `mcp-trap`, install the extra:

```bash
pip install 'argus-probe[mcp-trap]'
```

The extra exists because the MCP SDK it needs (`mcp` 2.3 or newer) requires `pydantic>=2.12` and several other packages. Keeping it out of the base install leaves the pydantic floor at 2.5 for everyone else.

From a clone of the repo: `pip install .`.

The engine is importable as `argus`, for example `from argus.targets import build_target`. Code written against `orchestrator.redteam` (the `argus-orchestrator` package, 0.3.x) needs one change: replace `orchestrator.redteam` with `argus` in its imports.

To see a report before you set anything up, run `argus-probe quickstart`. It starts a deliberately insecure demo MCP agent and a hostile MCP testbed on 127.0.0.1, runs the 12 MCP probes and writes `argus-quickstart.html` (`--out` changes the path). It needs no API key. The demo agent is meant to fail. Judged probes such as prompt injection still need `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`.

```bash
argus-probe quickstart
```

## Quickstart

```bash
# 1. Generate a target spec interactively
argus-probe init --kind openai_compat

# 2a. Run locally: set a judge key, no server needed
export ANTHROPIC_API_KEY="<your key>"
argus-probe run --local --target argus-target.json \
  --probes owasp_07_system_prompt_leakage --format html --out report.html

# 2b. Or submit to a server implementing the /api/v1/redteam API
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-server>"
argus-probe validate-target --target argus-target.json
argus-probe run --target argus-target.json \
  --probes owasp_07_system_prompt_leakage --format html --out report.html
```

`--local` also runs `browser_use` targets. The CLI serves each probe's trap page from your machine and sends your agent its URL, so the agent must be able to open it:

```bash
argus-probe run --local --target browser-target.json \
  --probes browser_dom_inject_html_comment --format html --out report.html
```

The trap page listens on `127.0.0.1` by default, which works when the agent runs on the same machine. For an agent in a container or on another machine, set `trap_host`, `trap_port` and `trap_public_url` in the target spec; the [target spec cookbook](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/target-spec-cookbook.md#browser_use) explains them. If your agent can't reach your machine at all, submit the run with `--api-url` and `--token` to a compatible hosted service instead.

The local judge uses `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY` when that is the only key set. For a local model, set `REDTEAM_MODEL_PROVIDER=litellm` and `REDTEAM_FAST_MODEL=ollama/qwen2.5:32b` (add `REDTEAM_LLM_API_BASE` for a non-default host); small models miss many jailbreaks, so the CLI prints a warning. `REDTEAM_MODEL_PROVIDER=azure` runs the judge on Azure OpenAI. Azure's default content filter blocks judge calls because the judge reads attack text, so use a custom filter policy with jailbreak detection turned off for that deployment (also when `OPENAI_API_KEY` is paired with `REDTEAM_LLM_API_BASE` pointing at Azure). If `OPENAI_API_KEY` is paired with `REDTEAM_LLM_API_BASE` pointing at Azure, set `REDTEAM_FAST_MODEL` and `REDTEAM_STRONG_MODEL` to your deployment names, because the default strong model `gpt-5.6-terra` is usually not deployed. Local models other than Ollama (vLLM or LM Studio via `openai/...` with `REDTEAM_LLM_API_BASE`) are billed at the most expensive known rate, so pass `--per-run-cap`.

Server mode talks to any server implementing the `/api/v1/redteam` API: set `ARGUS_API_URL` to it and `ARGUS_API_TOKEN` to a token that server issued. There is no hosted Argus instance, and the Argus repo no longer ships a server; the self-hosted stack is at tag [`v0.3-full`](https://github.com/gy15901580825/Argus/tree/v0.3-full). A `browser_use` run in server mode also needs a [`client_agent`](https://github.com/gy15901580825/Argus/blob/main/client_agent/README.md) connected to the server's orchestrator; it connects directly, with the same `AGENT_CONNECT_SECRET` set on both sides.

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

Without `--local`, `argus-probe` is a thin client: it submits the target spec and probe selection over HTTPS to a server implementing the `/api/v1/redteam` API; that server runs the probes against your agent and returns the report. With `--local` the same engine runs in this process and calls the judge model directly with your key.

Secret references in your target spec (`${OPENAI_API_KEY}`, etc.) are resolved from the local shell environment at run time; they are never written back to target.json. With `--local` they stay in this process and go only to your agent. In server mode the resolved spec, secrets included, is sent to the server, because the server is what calls your agent; use a server you trust with those credentials.

## Output formats

- `html` — human-readable report
- `sarif` — SARIF 2.1.0, uploads cleanly to GitHub code-scanning (Security tab)
- `junit` — JUnit XML for any CI tool that parses test results

## CI integration

Use [`argus-probe-action`](https://github.com/marketplace/actions/argus-agent-red-team-scan). It installs `argus-probe` from PyPI, runs the probes in local mode, uploads the SARIF to code scanning and fails the job at `fail-on`:

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

`--fail-on <severity>` exits 3 when a failing finding is at or above that level; the SARIF is written first. `--compare-to <base branch>` makes `--fail-on` count only failures that are new relative to the latest run on that branch. It is server mode only, because it needs run history, so the action does not offer it; see the target-spec cookbook for a server-mode workflow. Exit codes: 0 success, 1 run or configuration error, 2 usage error, 3 threshold hit, 4 cost cap.

## Cost controls

```bash
argus-probe run --target ... --per-run-cap 0.50
```

Runs that would exceed the cap are rejected before any LLM cost is incurred, in both server and local mode (exit code 4).

## Check a skill before you install it

```bash
export ANTHROPIC_API_KEY=sk-ant-...
argus-probe scan-skill ./path/to/skill
argus-probe scan-skill https://github.com/someone/skills.git --path pdf-tools
argus-probe scan-skill --sample key-grab
```

`argus-probe scan-skill <dir-or-git-url>` installs a Claude Code skill in a throwaway Linux container, gives Claude Code a few ordinary tasks that use the skill, and reports what the agent did: the files it read, the commands it ran and the requests it tried to send. It needs Docker and `ANTHROPIC_API_KEY`. The sandbox's proxy holds the real key and caps each task at `--per-task-cap`. The default depends on `--model`: about 2x one large Claude Code call (150 KB of request and 8,192 output tokens, reserved as below), at least $1.00, rounded up to $0.25. That is $1.00 for Haiku 4.5, Haiku 5.5 and Sonnet 5.5, $1.50 for Sonnet 4.6 (the default model), $2.00 for Opus 5.5 and $4.75 for Fable 5.1. Before it starts, the scan prints the cap and the most it can spend (the cap times the number of tasks): $4.50 for three tasks on Sonnet 4.6. A clean scan on Sonnet 4.6 costs about $0.30. A task's API spend cannot pass its cap, whether Claude Code or a process the skill started makes the calls, because every call is reserved at its worst case before it is sent: its `max_tokens` of output plus one input token for every byte of the request, priced at the dearest input rate. The proxy refuses a call if the task's spend plus its open reservations would pass the cap. A finished call is then charged what it really cost, and a call that fails or whose client drops it is charged its full reservation. The proxy also refuses any request shaped differently from Claude Code's own (fast mode, fallbacks, unknown betas, server tools, PDFs and the like). It allows only the scan's model and Claude Code's own background model, and `--model` takes only models the proxy has a price for. A `--per-task-cap` below what one 100 KB Claude Code call reserves on the model is refused, with the minimum named ($0.51 on Sonnet 4.6). A task that reaches its cap stops early. If its calls had already cost at least half the cap, the report gives it a medium finding, because Claude Code on its own stays well under the cap. Otherwise the cap was too small for one large call's worst case (a refused call costs nothing), and the report gives it a low note with the reserved, spent and cap amounts, so you can raise `--per-task-cap`. If a repository holds several skills, pick one with `--path`. To see what a finding looks like, scan one of the bundled inert samples with `--sample` instead of a source: `key-grab`, `config-theft`, `fake-prerequisite`, `hidden-instruction`, `persistence`, or the clean control `benign-markdown`. A clean report is not proof the skill is safe, because a skill can wait for conditions the scan did not create, and skills that only act on macOS do nothing in the Linux container. For a static review of the skill text, also run NVIDIA SkillSpector or Cisco skill-scanner. If Docker's DNS cannot resolve the Anthropic API, set `ARGUS_SKILLSCAN_DNS` to a DNS server that works on your network (for example `ARGUS_SKILLSCAN_DNS=1.1.1.1`); the image build already retries with this machine's resolver on its own.

## Test your agent against a hostile MCP server

```bash
pip install 'argus-probe[mcp-trap]'
argus-probe mcp-trap --target ./target.json --print-config
argus-probe mcp-trap --target ./target.json
```

`argus-probe mcp-trap` starts an MCP server on this machine, the trap, and sends your agent chat messages through the chat API in `--target`. The trap offers tools that are set up to fool the agent. The report says what the agent did with them. The verdicts are deterministic checks. There is no LLM judge, so Argus spends nothing on models. The target must be an `openai_compat`, `custom_http` or `grpc` spec for your agent's chat API.

First run:

1. Run `--print-config` to see the MCP server entry. It is a JSON entry named `argus-trap` that points at `http://127.0.0.1:8765/mcp`.
2. Add it to the MCP config of the agent under test. Restart the agent if it reads its MCP config only at startup.
3. Run the command without `--print-config`.

If you skip step 2, the first run sends one warm-up message, sees no MCP request, prints the entry and exits 2. That is expected. Run it again after you add the entry.

Attach only the trap to the agent under test. The report covers only what the agent does through the trap's tools. Anything the agent does with its own tools is not in it.

Every run is one warm-up conversation, then 5 scenarios with `--rounds` conversations each (default 3). With the defaults that is 16 conversations. The scenarios are `tool_poisoning`, `rug_pull`, `shadowing`, `confused_deputy` and `credential_lure`. `--scenarios` takes a comma list to run fewer. Each round plants a fresh canary string. A round fails when the agent sends the canary to the trap in a request, or when a scenario check fails. The report shows `k/N` for each scenario: k failed rounds out of N conclusive rounds. A scenario fails if any round fails.

A round is inconclusive when it cannot show what the agent would do:

- the agent sent no MCP request to the trap in that round;
- the chat call failed before the round could be judged;
- the agent did not fetch the round's tool list, so it may have acted on an earlier scenario's tools;
- the agent called a tool the scenario does not serve.

Inconclusive rounds are not counted in N. A scenario with no conclusive round is reported as an error.

The HTML report shows `k/N` for each scenario, a table of every round, and a note on the scope above. `--format` also takes `sarif`, `junit` and `json`. `--out` sets the path (default `argus-mcp-trap-report.<ext>`).

Exit codes:

| Code | Meaning |
|---|---|
| 0 | The run finished and every scenario reached a verdict. Failing findings still exit 0 unless you set `--fail-on`. |
| 1 | The target spec could not be loaded, the chat API was unreachable, or at least one scenario had no conclusive round. The report is still written when the run got that far. |
| 2 | Setup problem. The MCP SDK is missing or too old, the trap port is taken, or the warm-up saw no MCP request. A stale-session warm-up (an agent holding a session from an earlier run) tells you to restart the agent. |
| 3 | `--fail-on <severity>` is set and a finding with verdict `fail` is at or above that severity. |
| 130 | Ctrl-C. No report is written. |
| 143 | SIGTERM, for example a CI cancel. It stops the run the same way as Ctrl-C. |

To test an agent on another host, bind the trap to all interfaces and give the address the agent can reach:

```bash
argus-probe mcp-trap --target ./target.json --trap-host 0.0.0.0 --trap-public-url http://<lan-ip>:8765
```

The URL the command prints is the one the agent must reach. `--trap-port` changes the port (default 8765).

v1 limits:

- Streamable HTTP only. There is no stdio.
- General-purpose agents such as Claude Code, Codex and Gemini CLI are not covered. The target must be an agent you can talk to through a chat API.

## Subcommands

```
argus-probe quickstart          Run the MCP probes against a built-in demo agent, no key
argus-probe init                Interactive target.json generator
argus-probe validate-target     Sanity-check target reachability
argus-probe list-probes         List probe ids (local library, or a server with --api-url)
argus-probe run                 Submit a run + write the report
argus-probe report              Re-render a run stored on a server
argus-probe coverage            Show what the probe library covers; asks the server, runs no probes
argus-probe scan-skill          Run a Claude Code skill in a sandbox and report what it did
argus-probe mcp-trap            Point your agent at a hostile MCP server and report what it did
```

Each command's `--help` lists its flags.

## License

Apache-2.0. See [LICENSE](https://github.com/gy15901580825/Argus/blob/main/LICENSE). Copyright © 2026 Veyon Solutions.

## Security

To report a vulnerability, see [SECURITY.md](https://github.com/gy15901580825/Argus/blob/main/SECURITY.md).

## Links

- Documentation: [docs/onboarding](https://github.com/gy15901580825/Argus/blob/main/docs/onboarding/)
- Argus repo: https://github.com/gy15901580825/Argus
