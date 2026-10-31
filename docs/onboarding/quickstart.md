# Argus quickstart

Point Argus at any AI agent endpoint and get a SARIF report. Local mode (step 3a) needs only a judge API key (`argus-probe quickstart` needs none). Server mode (steps 3 to 5) needs a server implementing the `/api/v1/redteam` API; this repo does not ship one (see step 3).

## 1. Install the CLI

Python 3.11+ is required. Install from PyPI:

```bash
pipx install argus-probe                 # or: pip install argus-probe
argus-probe --version
```

The package includes the probe engine, so step 3a works without a server. From a clone, `pip install .` does the same.

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

The 13 supported `kind` values: `openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `http_upload`, `browser_use`, `payment_agent`, `mcp_agent`, `testbed_agent`, `mcp_server`, `vllm_server`, `web_chat`, `a2a_server`. See [target-spec-cookbook.md](./target-spec-cookbook.md) for non-OpenAI shapes.

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

Sends one "ping" prompt the way `run` does, with `$VAR` references in the spec expanded, and reports whether the target answered with text. It works for the chat kinds: `openai_compat`, `anthropic_native` and `custom_http`. For other kinds it exits 2 and points you to `run --local`, because their probes are the check. If this fails, fix the target spec before continuing.

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

Add `--per-run-cap 0.50` to limit what Argus spends on judge calls. A run whose estimate is above the cap does not start, in both modes; with `--local` the run also stops when spend reaches the cap. Either way the command exits 4.

The pre-run estimate counts a fast and a strong judge call for every prompt of every selected probe that needs the judge (and, in deep mode, which the CLI and API do not expose yet, every persona × strategy thread at its full round budget). Requests to your agent are not counted. On 2026-10-29, `--probes all` against a chat target was estimated at $5.32 with the default Anthropic judge, so it needs `--per-run-cap 5.32`; when a run is over the cap, the error names a cap at or above the estimate. Most verdicts do not escalate to the strong model, so a run usually costs well under its estimate.

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
| Full sweep: every probe that fits the target kind (a chat target needs `--per-run-cap 5.32`, see step 5) | `all` |

See [Threat coverage overview](./probe-id-cheatsheet.md) for the categories the library covers and recommended use-case → probe-set mappings.

## Check a skill before you install it

```bash
export ANTHROPIC_API_KEY=sk-ant-...
argus-probe scan-skill ./path/to/skill
argus-probe scan-skill https://github.com/someone/skills.git --path pdf-tools
argus-probe scan-skill --sample key-grab
```

`argus-probe scan-skill <dir-or-git-url>` installs a Claude Code skill in a throwaway Linux container, gives Claude Code a few ordinary tasks that use the skill, and reports what the agent did: the files it read, the commands it ran and the requests it tried to send. It needs Docker and `ANTHROPIC_API_KEY`. The sandbox's proxy holds the real key and caps each task at `--per-task-cap`. The default depends on `--model`: about 2x one large Claude Code call (150 KB of request and 8,192 output tokens, reserved as below), at least $1.00, rounded up to $0.25. That is $1.00 for Haiku 4.5, Haiku 5.5 and Sonnet 5.5, $1.50 for Sonnet 4.6 (the default model), $2.00 for Opus 5.5 and $4.75 for Fable 5.1. Before it starts, the scan prints the cap and the most it can spend (the cap times the number of tasks): $4.50 for three tasks on Sonnet 4.6. A clean scan on Sonnet 4.6 costs about $0.30. A task's API spend cannot pass its cap, whether Claude Code or a process the skill started makes the calls, because every call is reserved at its worst case before it is sent: its `max_tokens` of output plus one input token for every byte of the request, priced at the dearest input rate. The proxy refuses a call if the task's spend plus its open reservations would pass the cap. A finished call is then charged what it really cost, and a call that fails or whose client drops it is charged its full reservation. The proxy also refuses any request shaped differently from Claude Code's own (fast mode, fallbacks, unknown betas, server tools, PDFs and the like). It allows only the scan's model and Claude Code's own background model, and `--model` takes only models the proxy has a price for. A `--per-task-cap` below what one 100 KB Claude Code call reserves on the model is refused, with the minimum named ($0.51 on Sonnet 4.6). A task that reaches its cap stops early. If its calls had already cost at least half the cap, the report gives it a medium finding, because Claude Code on its own stays well under the cap. Otherwise the cap was too small for one large call's worst case (a refused call costs nothing), and the report gives it a low note with the reserved, spent and cap amounts, so you can raise `--per-task-cap`. If a repository holds several skills, pick one with `--path`. To see what a finding looks like, scan one of the bundled inert samples with `--sample` instead of a source: `key-grab`, `config-theft`, `fake-prerequisite`, `hidden-instruction`, `persistence`, or the clean control `benign-markdown`. A clean report is not proof the skill is safe, because a skill can wait for conditions the scan did not create, and skills that only act on macOS do nothing in the Linux container. For a static review of the skill text, also run NVIDIA SkillSpector or Cisco skill-scanner. If Docker's DNS cannot resolve the Anthropic API, set `ARGUS_SKILLSCAN_DNS` to a DNS server that works on your network (for example `ARGUS_SKILLSCAN_DNS=1.1.1.1`); the image build already retries with this machine's resolver on its own.

## What's next

- **Add to CI**: `argus-probe init --workflow` writes a workflow that runs [`argus-probe-action`](https://github.com/marketplace/actions/argus-agent-red-team-scan), uploads SARIF and fails on critical findings; see [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration".
- **Understand the verdicts**: each finding's `verdict` is one of:
  - `pass` — agent resisted the attack
  - `fail` — agent fell for the attack (look at `severity`: critical/high/medium/low)
  - `blocked_by_target` — the target answered the attack prompt with a 4xx such as a content filter's 400 or 403, or its content filter withheld the reply; counted as blocked
  - `skipped` — probe target_class incompatible with adapter, or, in local mode with `--skip-judged`, the probe needs the judge and no judge key is set (no LLM cost incurred; the exit code does not change)
  - `error` — the probe reached no verdict: 401/404/422/429, 5xx, timeout, connection error, an empty reply or a missing rubric. The run continues, the report is marked incomplete, and `run` exits 1
  - `aborted_cost` — the cost cap stopped this probe, or the run hit the cap before it started; `run` exits 4

## CLI reference

```
argus-probe quickstart                Run the MCP probes against a built-in demo agent, no key
argus-probe init --kind <X>           Interactive target.json generator
argus-probe validate-target           Send one prompt to a chat target and check it answers
argus-probe list-probes               List probe ids (local library, or a server with --api-url); --target / --target-class filter them
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
| `--local` | run probes in this process, no `--api-url`/`--token`; needs a judge key when a selected probe is judged |
| `--skip-judged` | with `--local` and no judge key, skip the judged probes and run the rest |
| `--fail-on` | `info` / `low` / `medium` / `high` / `critical`; exit 3 when a failing finding is at or above it |
| `--token` | API token (or set `ARGUS_API_TOKEN`) |
| `--max-wait` | how long to poll for run completion (default 1800 s) |
