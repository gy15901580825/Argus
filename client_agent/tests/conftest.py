"""Pytest fixtures for client_agent.

Self-contained: this file makes the service runnable as a standalone repo with
no parent-monorepo dependency. It puts the service dir on sys.path and scrubs
env vars that would otherwise trigger live network/auth.

The client agent is a run-side script (not a FastAPI server). Its top-level
modules are `client_agent` (main entrypoint — same name as the service dir)
and `web_ui_runner` (browser-use wrapper).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import client_agent / web_ui_runner`
# resolves to this repo.
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
        "API_SERVICE_URL": "http://api.invalid",
        "ORCHESTRATOR_URL": "ws://orchestrator.invalid",
        "ORCHESTRATOR_SECRET": "test-secret",
        "AZURE_OPENAI_API_KEY": "test",
        "AZURE_OPENAI_ENDPOINT": "https://azure.invalid",
        "GOOGLE_API_KEY": "test",
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    yield
