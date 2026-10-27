# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Monorepo Overview

Argus is a black-box red-team testing tool for AI agents. Customers point Argus at any HTTP-spoken or browser-using agent endpoint; Argus produces an attack report mapped to MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF.

## Services

| Service | Port | Stack | Role |
|---------|------|-------|------|
| `orchestrator` | 8080 | FastAPI, litellm | Red-team engine: probe dispatch + judge harness in `orchestrator/redteam/`, served at `/redteam/*`, plus the WebSocket hub for client agents |
| `client_agent` | — | websockets, browser-use, Playwright | Edge agent on client/cloud machines. Red-team probe runner in `redteam_runner/` |
| `cli` | — | Python (click) | Published `argus-probe` CLI — quickstart / run / report / list-probes / validate-target / coverage |
| `demo_target` | 8000 | FastAPI | Deliberately-vulnerable chatbot used as a public demo target for `argus-probe` |
| `payment_testbed` | 8080 | FastAPI | Mock x402 payment world + insecure demo agent for `payment_agent` probes |
| `mcp_testbed` | 8080 | FastAPI | Hostile MCP tool server + insecure demo agent for `mcp_agent` probes |

Argus is the engine and CLI only. The CLI's server mode (`run` without `--local`, `report`, `list-probes --api-url`) talks to any server implementing the `/api/v1/redteam` API; this repo does not ship one. The self-hosted stack (`api_service`, `frontend`, `database`, `kubernets`, `terraform`) was removed after tag `v0.3-full`; check out that tag to get it back.

The three legacy `testing_*` services moved to separate repositories on 2026-05-28:
- `testing_api_service` + `testing_web_fetch_service` → https://github.com/gy15901580825/argus-api-testing
- `testing_web_ui_service` (+ vendored `browser_use`) → https://github.com/gy15901580825/argus-web-ui-testing

The orchestrator no longer calls them: the planner and web-UI testing code were removed from this repo.

## Documentation

Project docs live in `docs/`. The repo root keeps only `CLAUDE.md` and `README.md` — all other text/markdown documents go under `docs/`.

- `docs/runbooks/local-dev.md` — Run each service locally
- `docs/runbooks/release.md` — Publish argus-probe and argus-orchestrator to PyPI (trusted publishing, TestPyPI rehearsal)
- `docs/reference/services.md` — Orchestrator endpoints and request flows
- `docs/onboarding/` — Quickstart, probe ID cheatsheet, target-spec cookbook
- `docs/operations/` — Operator-facing runbooks
- `docs/run-json.md` — The `run.json` format
- `docs/agent-evaluation-deep-dive.md` / `docs/llm-agent-testing-overview.md` — Background reading

## Architecture

`orchestrator` keeps an import-linter CI contract (`.importlinter`) that forbids `redteam/` from importing legacy web-UI modules.

### Communication Protocols

- **In-process**: `argus-probe run --local` and `quickstart` import the engine directly
- **REST/SSE**: `POST /redteam/run` streams one `data:` line per finding, then a `coverage` event, then `event: end` (or `event: error`)
- **WebSocket**: Orchestrator ↔ Client Agents (JSON-RPC; the orchestrator sends `redteam_browser_probe`)

Detailed request flows → `docs/reference/services.md`.

### LLM Configuration

- **Azure OpenAI**: `gpt-5.4-mini` — the orchestrator's red-team judge/attacker model when `REDTEAM_MODEL_PROVIDER=azure` (via litellm). The `testing_*` services live in the external repos listed above.
- **Temperature constraint**: `gpt-5.4-mini` does NOT support custom temperature parameter (Azure limitation) — never set `temperature` when calling this model

## Common Pitfalls & Gotchas

1. **Temperature on gpt-5.4-mini**: Azure's `gpt-5.4-mini` rejects requests with `temperature` parameter. Never pass it.
