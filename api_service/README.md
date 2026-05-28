# api_service

Central REST API for Argus.

Surface area:
- Auth (Microsoft Entra External ID JWT + per-user API tokens)
- `/redteam/*` (M2+): probe runs, findings, design-partner accounts
- `/legacy-export/*` (during 60-day sunset, until 2026-07-01): data export for legacy web-UI-testing users
- R2 storage proxy
- User management
- Existing `/api/v1/*` endpoints (chat, blog, docs, scripts, web_ui_tasks)

Module layout: `redteam/` — strict isolation from `routers/web_ui*` and `routers/scripts` (import-linter enforced; CI gate on every push).

Port 8881. See parent [README](../README.md) and [CLAUDE.md](../CLAUDE.md).
