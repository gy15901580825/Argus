"""Pytest fixtures for orchestrator.

Self-contained: this file makes the service runnable as a standalone repo with
no parent-monorepo dependency. It puts the service dir on sys.path and scrubs
env vars that would otherwise trigger live network/auth.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import server / connection_manager /
# orchestrator` resolves to this repo.
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
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "R2_ACCOUNT_ID": "test",
        "R2_ACCESS_KEY_ID": "test",
        "R2_SECRET_ACCESS_KEY": "test",
        "R2_BUCKET_NAME": "test-bucket",
        "R2_ENDPOINT_URL": "https://example.invalid",
        "API_SERVICE_URL": "http://api.invalid",
        "ORCHESTRATOR_URL": "http://orchestrator.invalid",
        "ORCHESTRATOR_SECRET": "test-secret",
        "STRIPE_SECRET_KEY": "sk_test_dummy",
        "CIAM_TENANT_ID": "test-tenant",
        "CIAM_CLIENT_ID": "test-client",
        "AZURE_OPENAI_API_KEY": "test",
        "AZURE_OPENAI_ENDPOINT": "https://azure.invalid",
        "GOOGLE_API_KEY": "test",
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    yield


# ---------------------------------------------------------------------------
# Orchestrator-specific fixtures.
# ---------------------------------------------------------------------------
@pytest.fixture
def fresh_manager():
    """A brand-new ConnectionManager instance (not the module global)."""
    from connection_manager import ConnectionManager
    return ConnectionManager()


@pytest.fixture
def fake_ws():
    """An AsyncMock WebSocket supporting accept/send_json/receive_json/close."""
    ws = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_json = AsyncMock()
    ws.receive_json = AsyncMock()
    ws.close = AsyncMock()
    return ws
