# orchestrator

FastAPI service that orchestrates AI-agent red-team probe execution.

- **Probe dispatch** (M2+): drives `client_agent` to run probes against target agents
- **Judge harness** (M2+): scores probe outcomes via Anthropic Haiku (default) / Sonnet (escalation on high-severity)
- **Report rendering** (M3+): HTML, SARIF, JUnit
- **SSE streaming**: per-probe progress and findings

Module layout: `orchestrator/redteam/` — strict isolation from legacy `web_ui_test/` enforced by import-linter (see `.importlinter`); CI gate runs on every push.

Port 8081. See parent [README](../README.md) and [CLAUDE.md](../CLAUDE.md).

## Run locally

```bash
pip install -r requirements.txt
./start.sh
```

API docs at `http://localhost:8081/docs`.
