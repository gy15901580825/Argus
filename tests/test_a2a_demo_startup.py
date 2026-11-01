import json

import pytest
from fastapi.testclient import TestClient

from argus.demo.a2a_testbed.demo_agent import app as demo


def unset(monkeypatch):
    for name in (
        "TESTBED_ORIGIN",
        "A2A_AGENT_CREDENTIALS",
        "A2A_DRIVER_CREDENTIAL",
        "DEMO_WEAKNESSES",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(demo, "state", None)


def test_demo_startup_without_environment_stays_unconfigured(monkeypatch):
    unset(monkeypatch)
    with TestClient(demo.app) as client:
        assert (
            client.post("/v1/chat/completions", json={"messages": []}).status_code
            == 503
        )


def test_demo_startup_environment_configures_safe_by_default(monkeypatch):
    unset(monkeypatch)
    credentials = {
        role: "Bearer startup-" + role for role in ("planner", "reviewer", "executor")
    }
    monkeypatch.setenv("TESTBED_ORIGIN", "http://127.0.0.1:8080")
    monkeypatch.setenv("A2A_AGENT_CREDENTIALS", json.dumps(credentials))
    monkeypatch.setenv("A2A_DRIVER_CREDENTIAL", "Bearer startup-driver")
    with TestClient(demo.app) as client:
        assert client.get("/healthz").status_code == 200
        assert demo.state.credentials == credentials
        assert demo.state.driver_credential == "Bearer startup-driver"
        assert demo.state.weaknesses == frozenset()


@pytest.mark.parametrize(
    "field,value",
    [
        ("A2A_AGENT_CREDENTIALS", "synthetic-secret-invalid-json"),
        ("TESTBED_ORIGIN", "synthetic-secret-invalid-origin"),
        ("DEMO_WEAKNESSES", "synthetic-secret-invalid-weakness"),
    ],
)
def test_invalid_demo_environment_fails_closed_without_secret(
    monkeypatch, field, value
):
    unset(monkeypatch)
    monkeypatch.setenv("TESTBED_ORIGIN", "http://127.0.0.1:8080")
    monkeypatch.setenv(
        "A2A_AGENT_CREDENTIALS",
        json.dumps(
            {
                role: "Bearer startup-" + role
                for role in ("planner", "reviewer", "executor")
            }
        ),
    )
    monkeypatch.setenv(field, value)
    with pytest.raises(
        ValueError, match="invalid A2A demo environment configuration"
    ) as caught:
        with TestClient(demo.app):
            pass
    assert value not in str(caught.value)
    assert demo.state is None
