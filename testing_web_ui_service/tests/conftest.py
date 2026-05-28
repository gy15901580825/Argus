"""Pytest fixtures for testing_web_ui_service.

Self-contained: this file makes the service runnable as a standalone repo with
no parent-monorepo dependency. It puts the service dir on sys.path, scrubs env
vars that would otherwise trigger live network/auth, and installs a stub
`browser_use` module in `sys.modules` so `import server` and the lazy
`from browser_use import ...` calls inside server functions succeed without
pulling in the real package (which requires `psutil` and other heavy deps
not installed in the test venv).
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# sys.path: put the service root first so `import server` resolves to this
# repo.
# ---------------------------------------------------------------------------
_SERVICE_DIR = Path(__file__).resolve().parents[1]
if str(_SERVICE_DIR) in sys.path:
    sys.path.remove(str(_SERVICE_DIR))
sys.path.insert(0, str(_SERVICE_DIR))


# ---------------------------------------------------------------------------
# Stub `browser_use` in sys.modules.
#
# The real `browser_use` package fails to import in the test venv because it
# pulls in `psutil` (not listed as a test dep). Server functions
# (`_extract_bug_report`, `_generate_test_script`, `_run_agent`) import
# `browser_use` lazily *inside* the function body, so we only need the stub
# registered before those functions run. Installing it at conftest import
# time is the simplest, safest choice and matches the original monorepo
# conftest behavior.
# ---------------------------------------------------------------------------
class _FakeChatAzureOpenAI:
    """Placeholder — individual tests patch this on the fake `browser_use` module."""

    def __init__(self, *a, **kw):
        pass

    async def ainvoke(self, messages):  # pragma: no cover - overridden in tests
        raise NotImplementedError


def _install_fake_browser_use() -> None:
    mod = types.ModuleType("browser_use")
    mod.ChatAzureOpenAI = _FakeChatAzureOpenAI
    sub = types.ModuleType("browser_use.llm")
    msgs = types.ModuleType("browser_use.llm.messages")

    class _Msg:
        def __init__(self, content: str = ""):
            self.content = content

    msgs.SystemMessage = _Msg
    msgs.UserMessage = _Msg
    sys.modules["browser_use"] = mod
    sys.modules["browser_use.llm"] = sub
    sys.modules["browser_use.llm.messages"] = msgs


_install_fake_browser_use()


# ---------------------------------------------------------------------------
# Env isolation — never let tests hit real services.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    safe_defaults = {
        "ENV": "test",
        "OPENAI_API_KEY": "test",
        "AZURE_OPENAI_API_KEY": "test",
        "AZURE_OPENAI_ENDPOINT": "https://azure.invalid",
        "GOOGLE_API_KEY": "test",
        "R2_ACCOUNT_ID": "test",
        "R2_ACCESS_KEY_ID": "test",
        "R2_SECRET_ACCESS_KEY": "test",
        "R2_BUCKET_NAME": "test-bucket",
        "R2_ENDPOINT_URL": "https://example.invalid",
        "API_SERVICE_URL": "http://api.invalid",
        "ORCHESTRATOR_URL": "http://orchestrator.invalid",
        "ORCHESTRATOR_SECRET": "test-secret",
    }
    for k, v in safe_defaults.items():
        monkeypatch.setenv(k, v)
    yield
