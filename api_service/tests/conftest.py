"""Pytest fixtures for api_service.

Self-contained: this file makes the service runnable as a standalone repo with
no parent-monorepo dependency. It puts the service dir on sys.path, scrubs env
vars that would otherwise trigger live network/auth, and provides DB + auth
test doubles.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import server / auth / database`
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
# Domain test doubles.
# ---------------------------------------------------------------------------
@pytest.fixture
def user_row():
    """Raw DB row shape that auth.py SELECTs."""
    return {
        "id": UUID("11111111-1111-1111-1111-111111111111"),
        "username": "alice",
        "email": "alice@example.com",
        "display_name": "Alice",
        "avatar": None,
        "role": "ORDINARY_USER",
        "is_active": True,
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
    }


@pytest.fixture
def admin_row(user_row):
    return {
        **user_row,
        "id": UUID("22222222-2222-2222-2222-222222222222"),
        "username": "admin",
        "role": "SUPER_ADMIN",
    }


@pytest.fixture
def mock_db():
    """Replace database.database.fetch_one / fetch_all / execute with AsyncMocks."""
    import database as db_module

    fake = db_module.database
    fake.fetch_one = AsyncMock(return_value=None)
    fake.fetch_all = AsyncMock(return_value=[])
    fake.execute = AsyncMock(return_value=None)
    fake.connect = AsyncMock(return_value=None)
    fake.disconnect = AsyncMock(return_value=None)
    return fake


@pytest.fixture
def client(mock_db):
    """TestClient bound to the FastAPI app, with DB calls mocked."""
    import server

    with TestClient(server.app) as c:
        yield c
