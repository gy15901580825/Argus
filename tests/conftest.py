"""Pytest fixtures for the argus package.

Puts the repo root on sys.path, so `import argus` resolves to this checkout,
and scrubs env vars that would otherwise trigger live network/auth.
"""
from __future__ import annotations

import os
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
# Credentials a model provider SDK or litellm could pick up from a developer's shell or home.
_CRED_SUFFIXES = ("_API_KEY", "_API_TOKEN")
_CRED_PREFIXES = ("AWS_", "GOOGLE_", "GCLOUD_", "CLOUDSDK_", "AZURE_", "VERTEX", "TYPESAFE_")
_CRED_NAMES = ("HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN", "TOGETHER_AI_TOKEN",
               "ANTHROPIC_AUTH_TOKEN", "OPENAI_ORG_ID")


def _is_live(request) -> bool:
    return bool(request.node.get_closest_marker("rubric_live") or request.node.get_closest_marker("live_skillscan"))


@pytest.fixture(scope="session")
def _test_home(tmp_path_factory):
    return tmp_path_factory.mktemp("home")


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, request, _test_home):
    if not _is_live(request):
        # No test may reach a real provider: no keys from the shell, no ~/.aws, gcloud or ADC files.
        for k in list(os.environ):
            if k.endswith(_CRED_SUFFIXES) or k.startswith(_CRED_PREFIXES) or k in _CRED_NAMES:
                monkeypatch.delenv(k)
        for k, v in {"HOME": _test_home, "AWS_CONFIG_FILE": _test_home / ".aws" / "config",
                     "AWS_SHARED_CREDENTIALS_FILE": _test_home / ".aws" / "credentials",
                     "CLOUDSDK_CONFIG": _test_home / ".config" / "gcloud",
                     "GOOGLE_APPLICATION_CREDENTIALS": _test_home / "no-adc.json",
                     "AWS_EC2_METADATA_DISABLED": "true"}.items():
            monkeypatch.setenv(k, str(v))
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
    # Declared judge prices change every cost estimate.
    scrub += [k for k in os.environ if k.startswith("REDTEAM_PRICE_")]
    for k in scrub:
        monkeypatch.delenv(k, raising=False)
    yield


@pytest.fixture(autouse=True)
def llm_call_guard(request, monkeypatch):
    """Refuse and record any real judge/attacker call (litellm or the Anthropic client); the test then fails.

    Tests mock argus.llm._acompletion / argus.llm._anthropic_client. Request this fixture to inspect attempts.
    """
    attempts: list[dict] = []
    if _is_live(request):
        yield attempts
        return
    import litellm

    from argus import llm

    def refuse(*args, **kwargs):
        attempts.append(kwargs)
        raise RuntimeError(f"test made a real LLM call (model={kwargs.get('model')!r}); "
                           "mock argus.llm._acompletion or argus.llm._anthropic_client")

    async def refuse_async(*args, **kwargs):
        return refuse(*args, **kwargs)

    def refuse_anthropic(api_key=None):
        return refuse(model="anthropic client")

    monkeypatch.setattr(litellm, "acompletion", refuse_async)
    monkeypatch.setattr(litellm, "completion", refuse)
    monkeypatch.setattr(llm, "_anthropic_client", refuse_anthropic)
    yield attempts
    assert not attempts, f"unmocked LLM call(s) to {[a.get('model') for a in attempts]}"


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
