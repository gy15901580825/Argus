"""Pytest fixtures for the argus package.

Puts the repo root on sys.path, so `import argus` resolves to this checkout,
and scrubs env vars that would otherwise trigger live network/auth.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the repo root first so `import argus` resolves to this checkout.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) in sys.path:
    sys.path.remove(str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT))


# ---------------------------------------------------------------------------
# Env isolation — never let tests hit real services.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, request):
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
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    # Judge provider auto-detect reads these; a developer's shell must not change results.
    # The live rubric and scan-skill tiers need the real ANTHROPIC_API_KEY.
    scrub = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "REDTEAM_MODEL_PROVIDER",
             "REDTEAM_FAST_MODEL", "REDTEAM_STRONG_MODEL", "REDTEAM_LLM_API_BASE"]
    if request.node.get_closest_marker("rubric_live") or request.node.get_closest_marker("live_skillscan"):
        scrub.remove("ANTHROPIC_API_KEY")
    # Server secrets from a developer's .env would 401 /redteam/* or refuse /agent/connect tests.
    scrub += ["ARGUS_SERVER_TOKEN", "ARGUS_SERVER_HOST", "ARGUS_SERVER_ALLOW_UNAUTHENTICATED",
              "AGENT_CONNECT_SECRET"]
    for k in scrub:
        monkeypatch.delenv(k, raising=False)
    yield


# ---------------------------------------------------------------------------
# Orchestrator-specific fixtures.
# ---------------------------------------------------------------------------
@pytest.fixture
def fresh_manager():
    """A brand-new ConnectionManager instance (not the module global)."""
    from argus.connection_manager import ConnectionManager
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
