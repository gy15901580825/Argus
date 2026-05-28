# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Monorepo Overview

Argus is a black-box red-team testing tool for AI agents. Customers point Argus at any HTTP-spoken or browser-using agent endpoint; Argus produces an attack report mapped to MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF.

## Services

| Service | Port | Stack | Role |
|---------|------|-------|------|
| `api_service` | 8881 | FastAPI, asyncpg, PostgreSQL | Central REST API: users, R2 storage, `/redteam/*`. Module isolation via `redteam/` + import-linter |
| `orchestrator` | 8081 | FastAPI, Google ADK, litellm | Agent orchestration, SSE streaming, WebSocket agent hub. Probe dispatch + judge harness in `orchestrator/redteam/` |
| `client_agent` | — | websockets, browser-use, Playwright | Edge agent on client/cloud machines. Red-team probe runner in `redteam_runner/` |
| `frontend` | 3000 | Next.js 16, React 19, Zustand | Web UI: marketing site, chat, dashboard |
| `database` | — | Flyway, PostgreSQL | Schema migrations |
| `kubernets` | — | Helm, AKS/k3s | Deployment charts, scripts, YAML manifests |
| `cli` | — | Python (click) | Published `argus-probe` CLI — run / report / list-probes / validate-target |
| `demo_target` | 8000 | FastAPI | Deliberately-vulnerable chatbot used as a public demo target for `argus-probe` |
| `terraform` | — | Terraform | Azure IaC reference (AKS, ACR, PG, Key Vault, B2C apps) |

The three legacy `testing_*` services moved to separate repositories on 2026-05-28:
- `testing_api_service` + `testing_web_fetch_service` → https://github.com/gy15901580825/argus-api-testing
- `testing_web_ui_service` (+ vendored `browser_use`) → https://github.com/gy15901580825/argus-web-ui-testing

The orchestrator still references them over HTTP via `run_api_test` and `run_web_ui_cloud` planner tools; the in-cluster services must be deployed from those repos (their Helm charts ship alongside the code).

## Domain & Environment

### Shared infrastructure

- **Cluster**: Azure AKS, context `<YOUR_AKS>`
- **Container registry**: Azure ACR — `<YOUR_ACR>.azurecr.io/argus/<service>:<tag>`
- **Database server**: Azure Database for PostgreSQL — `<YOUR_PG_SERVER>.postgres.database.azure.com` (`publicNetworkAccess=Disabled`; psql/Flyway must run from in-cluster pods)
- **Ingress**: NGINX Ingress Controller, single LoadBalancer IP `<YOUR_INGRESS_IP>` shared by all hosts
- **Azure Key Vault**: `<YOUR_KEY_VAULT>` is the runtime source-of-truth for `api_service` credentials. K8s Secret `argus-api-service-secret` is auto-synced from KV by External Secrets Operator (ESO) via `ClusterSecretStore: <YOUR_AZURE_KV_STORE>`. ESO authenticates with Workload Identity → UAMI `eso-kv-reader` (federated credential subject `system:serviceaccount:external-secrets:external-secrets`). Other services use literal Helm-rendered Secrets. Operator runbook: `kubernets/DEV_DEPLOYMENT_GUIDE.md` § Secrets management.
- **TLS**: cert-manager + Let's Encrypt (ClusterIssuer: `letsencrypt-prod`), auto-renewed
- **DNS**: Cloudflare proxy (orange cloud) in front of all hosts
- **Auth**: Microsoft Entra External ID (CIAM), SPA app ID `<YOUR_CLIENT_ID>`, in separate tenant `<YOUR_TENANT_ID>`
  - To manage app registrations: `az login --tenant <YOUR_TENANT_ID> --allow-no-subscriptions`
  - SPA `redirectUris` include both prod and dev callbacks: `https://www.example.com/{callback,auth-redirect}`, `https://dev.example.com/{callback,auth-redirect}`, `http://localhost:3000/{callback,auth-redirect}`

### Production

| Dimension | Value |
|---|---|
| URL | `https://www.example.com` |
| Namespace | `default` |
| Database | `argus` |
| Helm release | `argus-<svc>` |
| Image tag | semver (e.g. `1.0.0`) |
| Ingress | `kubernets/ingress-azure.yaml` |
| TLS secret | `argus-tls` |
| Values override | `values-azure.yaml` |
| Secret | `argus-<svc>-secret` (per-service, created by chart from `values.secrets.*`) |

### Dev

| Dimension | Value |
|---|---|
| URL | `https://dev.example.com` |
| Namespace | `dev` |
| Database | `argus_dev` (same PG server, separate logical DB) |
| Helm release | `argus-<svc>-dev` |
| Image tag | `dev-latest` or `dev-<gitsha-short>` |
| Ingress | `kubernets/ingress-azure-dev.yaml` |
| TLS secret | `argus-dev-tls` |
| Values override | `values-azure-dev.yaml` (in addition to `values.yaml` + `values-azure.yaml`) |
| Secrets | `argus-dev-secrets` (shared, covering orchestrator + testing services with all naming-convention aliases) + `argus-api-service-dev-secret` (separate; api-service chart hardcodes `{fullname}-secret` for most keys) |
| Operator manual | `kubernets/DEV_DEPLOYMENT_GUIDE.md` |

**Dev secret-naming gotcha:** Three charts use three different key conventions for the same underlying credentials. `argus-dev-secrets` stores all three sets to satisfy each chart's references:
- orchestrator: `AZURE_API_*` (litellm) + `R2_*`
- testing-{api,web-ui}-service: `AZURE_OPENAI_*` + `CLOUDFLARE_R2_*`
- api-service: `AZURE_OPENAI_*` + `R2_*` (in its own per-service secret because the chart doesn't honor `existingSecretName` for non-DATABASE keys)

## Docker Registry Rules

- **client_agent** → Docker Hub: `<your-gh-user>/client_agent:latest`
- **All other services** → Azure ACR: `<YOUR_ACR>.azurecr.io/argus/<service>:<tag>`

Build/push via `./build-and-push.sh <service> <tag>`. Full deploy procedures (AKS Helm, frontend rebuild, domain-change checklist) → `docs/runbooks/deploy.md`.

## Documentation

Project docs live in `docs/`. The repo root keeps only `CLAUDE.md` and `README.md` — all other text/markdown documents go under `docs/`.

- `docs/CI_CD.md` — CI/CD pipeline (GitHub Actions build/push + ArgoCD GitOps to AKS)
- `docs/runbooks/deploy.md` — Build images, Helm upgrade, frontend rebuild, domain-change checklist
- `docs/runbooks/local-dev.md` — Run each service locally (Python services, frontend, Flyway migrations)
- `docs/reference/services.md` — Detailed request flows, API endpoint tables, frontend component tables
- `docs/onboarding/` — Quickstart, probe ID cheatsheet, target-spec cookbook
- `docs/operations/` — Operator-facing runbooks
- `docs/agent-evaluation-deep-dive.md` / `docs/llm-agent-testing-overview.md` — Background reading

## Architecture

### Authentication

Dual-auth via **Microsoft Entra External ID (CIAM)**:
- **JWT tokens**: From CIAM OAuth flow (MSAL on frontend, ROPC for client_agent), sent as `Authorization: Bearer <token>`
- **API tokens**: Long-lived per-user secrets, sent as `x-api-token` header
- **Service-to-service**: `x-user-id` header + `ORCHESTRATOR_SECRET`
- **Screenshot proxy**: `?token=` query param (because `<img src>` can't send headers)

### Database

Azure Database for PostgreSQL (production) with async driver (asyncpg). Migrations in `database/sql/` (Flyway).

Key tables: `users`, `redteam_runs`, `redteam_findings`, `redteam_design_partners`, `client_agent`, `chat_sessions`, `chat_messages`, `blogs`, `documents`, `trial_tokens`.

All Python services have `redteam/` modules with import-linter CI rules forbidding cross-talk with legacy `web_ui_*` code.

### Storage

Cloudflare R2 (S3-compatible) for file artifacts:
- `scripts/{user_id}/...` — generated test scripts
- `web-ui/{user_id}/{task_id}/bug_report.txt` — bug reports
- `web-ui/{user_id}/{task_id}/test_script.py` — test scripts
- `web-ui/{user_id}/{task_id}/screenshots/step_000.png` — screenshot sequence

### Agent Framework

The orchestrator uses Google ADK agent types:
- **SequentialAgent**: Content analyzer, API testing, web UI testing
- **ParallelAgent**: Slide generation
- **LoopAgent**: Quality assessment
- **Custom**: SmartPipeline, RemoteAgent, ClientWebUIAgent

### Communication Protocols

- **REST/SSE**: Frontend ↔ API Service ↔ Orchestrator
- **WebSocket**: Orchestrator ↔ Client Agents (bidirectional command/response)
- **MCP**: Orchestrator ↔ testing_web_fetch_service (tool-based crawling)

Detailed request-flow diagrams → `docs/reference/services.md`.

### LLM Configuration

- **Provider**: Configurable via `LLM_PROVIDER` env (default: `azure`)
- **Azure OpenAI**: `gpt-5.4-mini` (chat/main) + `gpt-5.3-codex` (codex, Responses API only) — used by orchestrator, testing services, and client_agent
- **Gemini**: `gemini-3-pro-preview` (main), `gemini-2.0-flash` (fast) — alternative provider
- **Model Router** (`orchestrator/model_router.py`): Routes based on subscription plan (free/starter/pro) and task complexity
- **Temperature constraint**: `gpt-5.4-mini` does NOT support custom temperature parameter (Azure limitation) — never set `temperature` when calling this model

### Key SSE Event Types

| Event Type | Source | Frontend Display |
|------------|--------|-----------------|
| `log` / `discovery_progress` | Orchestrator agents | Collapsible "Thinking" block (LogMessage) |
| `progress` | Agent pipeline steps | Collapsible log lines |
| `result` | Final agent output | Markdown-rendered ResultMessage |
| `ssh_result` | testing_api_service | APITestResultCard with pytest summary |
| `web_ui_bug` | ClientWebUIAgent | BugReportCard with severity badges + screenshots |
| `web_ui_artifact` | ClientWebUIAgent | TestScriptArtifact with syntax highlighting |
| `artifact` | Script upload | Captured as scriptUrl (not displayed) |
| `error` | Any service | Red error banner, stops stream |

## Common Pitfalls & Gotchas

1. **Pydantic model sync**: Both `api_service` and `orchestrator` define `StrategyRequest`. Fields must match — api_service drops unknown fields silently when proxying to orchestrator.
2. **Temperature on gpt-5.4-mini**: Azure's `gpt-5.4-mini` rejects requests with `temperature` parameter. Never pass it.
3. **Frontend env vars baked at build time**: `NEXT_PUBLIC_*` vars are compiled into the JS bundle. Domain/URL changes require `./build-and-push.sh frontend <tag>`, not just a restart.
4. **ACR auth expires**: Run `az acr login --name <YOUR_ACR>` before any image push. Tokens expire after ~3 hours.
5. **SSH vs Test-Runner routing**: Only uses SSH when user provides **all three** fields: `remote_ip`, `username`, `pem_key_base64`. Missing any one → falls back to in-cluster test-runner service.
6. **SSE event parsing**: Frontend `streamStrategy()` handles both direct fields (`parsed.ssh_result`) and nested content (`parsed.content.parts[0].text` with inner JSON). Both paths must be maintained for backward compatibility.
