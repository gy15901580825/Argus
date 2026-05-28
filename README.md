# ARGUS

**ARGUS** is a black-box red-team testing tool for AI agents.

Point ARGUS at any HTTP-spoken or browser-using agent endpoint, and in under an hour it produces an attack report mapped to **MITRE ATLAS**, **OWASP LLM Top 10**, and **NIST AI RMF** controls — including 30+ exclusive browser-agent probes that no other tool ships.

> **Status:** in active development. v0 (CLI + report + 130-probe library) targets September 2026. The legacy web-UI-testing product is sunsetting on 2026-07-01 — see [Sunset notice](https://www.example.com/legacy-export/manifest).

## Repositories

| Service | Purpose |
|---|---|
| `api_service` | REST API (FastAPI) — auth, persistence, R2 storage |
| `orchestrator` | AI agent orchestration (FastAPI + Google ADK) — probe dispatcher (M2+) |
| `client_agent` | Edge agent — browser-use runtime, probe runner (M3+) |
| `frontend` | Web UI (Next.js 16) — marketing site, dashboard (M7+) |
| `database` | Flyway migrations |
| `kubernets` | Helm charts, AKS manifests |

The `testing_*` services are scheduled for archival after the legacy sunset window — see git history.

## Documentation

- [Architecture & infrastructure](CLAUDE.md)
- [Product spec](docs/superpowers/specs/2026-05-01-argus-pivot-agent-redteam-design.md)
- [GEO content strategy](docs/superpowers/specs/2026-04-29-geo-reliability-security-redesign.md)

## Research arm

OSS probe library and research write-ups: [github.com/argus-research](https://github.com/argus-research)

Research blog: ["Agent Reliability Notes"](https://agent-reliability-notes.substack.com)
