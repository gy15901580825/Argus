"""Client tests import the service and its repository-level shared transport.

The image test separately checks imports outside the repository working directory.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import client_agent / redteam_runner`
# resolves to this repo.
# ---------------------------------------------------------------------------
_SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(_SERVICE_DIR) in sys.path:
    sys.path.remove(str(_SERVICE_DIR))
sys.path.insert(0, str(_SERVICE_DIR.parent))
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
        "AZURE_OPENAI_ENDPOINT": "https://azure.invalid",
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    yield
