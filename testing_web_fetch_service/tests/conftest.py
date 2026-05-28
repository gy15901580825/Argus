"""Pytest fixtures for testing_web_fetch_service.

Self-contained: this file makes the service runnable as a standalone repo with
no parent-monorepo dependency. It puts the service dir on sys.path and scrubs
env vars that would otherwise trigger live network / LLM / auth calls.

The service defines top-level modules `server` (FastMCP + FastAPI /result cache),
`tools_impl` (httpx + BeautifulSoup page fetcher), `ai_crawler` (Playwright +
Gemini driven API crawler), and `tunnel_client` (websockets JSON-RPC bridge).

Do NOT create tests/__init__.py — it would shadow the service-level
`server` / `tools_impl` / `ai_crawler` / `tunnel_client` modules.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import server / tools_impl /
# ai_crawler / tunnel_client` resolves to this repo.
# ---------------------------------------------------------------------------
_SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(_SERVICE_DIR) in sys.path:
    sys.path.remove(str(_SERVICE_DIR))
sys.path.insert(0, str(_SERVICE_DIR))


# ---------------------------------------------------------------------------
# Env isolation — never let tests hit real services.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    safe_defaults = {
        "ENV": "test",
        "GOOGLE_API_KEY": "test",
        "ORCHESTRATOR_URL": "ws://orchestrator.invalid",
        "ORCHESTRATOR_SECRET": "test-secret",
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    yield
