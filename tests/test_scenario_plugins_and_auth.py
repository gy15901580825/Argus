from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from argus.scenarios.api import router


def test_scenario_endpoints_fail_closed_without_server_token(monkeypatch):
    monkeypatch.delenv("ARGUS_SERVER_TOKEN", raising=False)
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        assert client.get("/redteam/scenarios").status_code == 503
        assert client.post("/redteam/scenario/run", json={}).status_code == 503
        assert client.post("/redteam/scenario/cleanup", json={}).status_code == 503


def test_wrong_server_token_is_rejected(monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "expected")
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        assert client.get("/redteam/scenarios", headers={"Authorization": "Bearer wrong"}).status_code == 401


async def test_scanner_status_does_not_use_public_default_when_unconfigured(monkeypatch):
    import argus.connection_manager as manager
    monkeypatch.setattr(manager, "ORCHESTRATOR_SECRET", "")
    monkeypatch.setenv("API_SERVICE_URL", "https://example.invalid")
    with patch.object(manager.httpx.AsyncClient, "post", new_callable=AsyncMock) as post:
        await manager.ConnectionManager()._post_status("agent", "online")
    post.assert_not_called()


def test_probe_pack_can_use_plugin_target_classes(monkeypatch, tmp_path):
    import argus.targets
    from argus.probe import load_probe
    class PluginTarget:
        compatible_classes = frozenset({"integration_custom"})
    monkeypatch.setattr(argus.targets, "_plugin_builders", lambda: {"custom": (object, PluginTarget)})
    file = tmp_path / "probe.yaml"
    file.write_text("id: custom\nname: custom\nseverity: high\ntarget_class: [integration_custom]\nattack_class: [indirect-injection]\nprompts: [test]\n")
    assert load_probe(file).target_class == ("integration_custom",)


def test_assertion_plugins_are_resolved_without_changing_builtin_checks(monkeypatch):
    import argus.assertions
    class Entry:
        name = "custom_integration_check"
        def load(self):
            return lambda value, evidence, response: (evidence.get("persisted") == value, "independent persisted state")
    monkeypatch.setattr(argus.assertions, "entry_points", lambda **kwargs: [Entry()])
    result = argus.assertions.evaluate_assertions(({"custom_integration_check": True},), {"persisted": True}, "")
    assert result[0].passed


def test_target_credentials_in_urls_are_rejected_before_network():
    import pytest
    from argus.scenarios.runtime import validate_target_credentials
    for url in ["https://user:secret@target.invalid/chat", "https://target.invalid/chat?api_key=secret", "https://target.invalid/chat?custom=literal-header-secret"]:
        with pytest.raises(ValueError):
            validate_target_credentials({"request_url": url, "request_headers": {"Authorization": "Bearer literal-header-secret"}})
    validate_target_credentials({"request_url": "https://target.invalid/chat?api-version=2024-01-01"})
