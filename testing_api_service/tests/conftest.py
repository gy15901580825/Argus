"""Pytest fixtures for testing_api_service.

Self-contained: this file makes the service runnable as a standalone repo
with no parent-monorepo dependency. It puts the service dir on sys.path and
scrubs env vars that would otherwise trigger live network/auth.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import server / utils /
# remote_executor` resolves to this repo.
# ---------------------------------------------------------------------------
_SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(_SERVICE_DIR) in sys.path:
    sys.path.remove(str(_SERVICE_DIR))
sys.path.insert(0, str(_SERVICE_DIR))


# ---------------------------------------------------------------------------
# Env isolation — never let tests hit real services. Provides R2 env defaults
# so `CloudflareR2Manager.__init__` doesn't raise at construction time; real
# networking is blocked by patching the class in individual tests.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    safe_defaults = {
        "ENV": "test",
        "CLOUDFLARE_R2_ACCOUNT_ID": "test-acct",
        "CLOUDFLARE_R2_ACCESS_KEY_ID": "test-key",
        "CLOUDFLARE_R2_SECRET_ACCESS_KEY": "test-secret",
        "CLOUDFLARE_R2_BUCKET_NAME": "test-bucket",
        "AZURE_OPENAI_API_KEY": "test",
        "AZURE_OPENAI_ENDPOINT": "https://azure.invalid",
        "GOOGLE_API_KEY": "test",
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    yield
