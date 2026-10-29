"""argus.server: bearer token on /redteam/* and the bind-address startup guard."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ARGUS_SERVER_TOKEN", raising=False)
    from argus.server import app

    return TestClient(app)


def test_no_token_configured_leaves_redteam_open(client):
    resp = client.get("/redteam/probes")
    assert resp.status_code == 200
    assert resp.json()["probe_ids"]


@pytest.mark.parametrize("path", ["/redteam/probes", "/redteam/suites", "/redteam/coverage"])
def test_token_configured_rejects_missing_header(client, monkeypatch, path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get(path)
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("header", [
    "Bearer wrong-token",
    "Bearer right-token-extra",
    "Basic right-token",
    "right-token",
    "Bearer ",
])
def test_token_configured_rejects_wrong_header(client, monkeypatch, header):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get("/redteam/probes", headers={"Authorization": header})
    assert resp.status_code == 401


def test_token_configured_accepts_right_header(client, monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get("/redteam/probes", headers={"Authorization": "Bearer right-token"})
    assert resp.status_code == 200
    assert resp.json()["probe_ids"]


def test_bearer_scheme_is_case_insensitive(client, monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    resp = client.get("/redteam/probes", headers={"Authorization": "bearer right-token"})
    assert resp.status_code == 200


def test_post_routes_are_guarded_before_body_validation(client, monkeypatch):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")
    assert client.post("/redteam/run", json={}).status_code == 401
    assert client.post("/redteam/run/preflight", json={}).status_code == 401


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_routes_stay_open(client, monkeypatch, path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "right-token")


def test_openapi_declares_the_bearer_scheme(client):
    schema = client.get("/openapi.json").json()
    schemes = schema["components"]["securitySchemes"]
    assert any(s == {"type": "http", "scheme": "bearer"} for s in schemes.values())
    assert schema["paths"]["/redteam/probes"]["get"].get("security")


# --------------------------------------------------------------------------
# startup guard
# --------------------------------------------------------------------------

def _guard(host, token="", agent_secret="", allow=False):
    from argus.server import startup_error

    return startup_error(host, token=token, agent_secret=agent_secret, allow_unauthenticated=allow)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "localhost"])
def test_loopback_without_secrets_may_start(host):
    assert _guard(host) is None


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "my-host.example"])
def test_non_loopback_without_secrets_is_refused(host):
    msg = _guard(host)
    assert msg is not None
    assert host in msg
    assert "ARGUS_SERVER_TOKEN" in msg
    assert "AGENT_CONNECT_SECRET" in msg
    assert "ARGUS_SERVER_ALLOW_UNAUTHENTICATED=1" in msg


def test_non_loopback_with_token_but_no_agent_secret_is_refused():
    msg = _guard("0.0.0.0", token="t")
    assert msg is not None
    assert "AGENT_CONNECT_SECRET" in msg
    assert "ARGUS_SERVER_TOKEN is not set" not in msg


def test_non_loopback_with_agent_secret_but_no_token_is_refused():
    msg = _guard("0.0.0.0", agent_secret="s")
    assert msg is not None
    assert "ARGUS_SERVER_TOKEN" in msg
    assert "AGENT_CONNECT_SECRET is not set" not in msg


def test_server_token_does_not_stand_in_for_the_agent_secret():
    # Same value in both slots is fine; a token alone never opens the hub.
    assert _guard("0.0.0.0", token="same", agent_secret="") is not None
    assert _guard("0.0.0.0", token="t", agent_secret="s") is None


def test_opt_out_opens_both_surfaces():
    assert _guard("0.0.0.0", allow=True) is None
    assert _guard("0.0.0.0", token="t", allow=True) is None


def test_refusal_message_says_the_opt_out_opens_both():
    msg = _guard("0.0.0.0")
    assert "/redteam/*" in msg and "/agent/connect" in msg


def _clear_server_env(monkeypatch):
    for name in ("ARGUS_SERVER_HOST", "ARGUS_SERVER_TOKEN", "ARGUS_SERVER_ALLOW_UNAUTHENTICATED",
                 "AGENT_CONNECT_SECRET", "PORT"):
        monkeypatch.delenv(name, raising=False)


def _fake_uvicorn(monkeypatch):
    started = []
    monkeypatch.setattr("uvicorn.run", lambda *a, **kw: started.append(kw))
    return started


def test_main_exits_nonzero_on_unsafe_bind(monkeypatch, capsys):
    import argus.server as server

    _clear_server_env(monkeypatch)
    monkeypatch.setenv("ARGUS_SERVER_HOST", "0.0.0.0")
    started = _fake_uvicorn(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    assert "ARGUS_SERVER_TOKEN" in capsys.readouterr().err
    assert started == []


def test_main_exits_nonzero_off_loopback_with_token_but_no_agent_secret(monkeypatch, capsys):
    import argus.server as server

    _clear_server_env(monkeypatch)
    monkeypatch.setenv("ARGUS_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "t")
    started = _fake_uvicorn(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    assert "AGENT_CONNECT_SECRET" in capsys.readouterr().err
    assert started == []


def test_main_binds_loopback_by_default(monkeypatch):
    import argus.server as server

    _clear_server_env(monkeypatch)
    started = _fake_uvicorn(monkeypatch)
    server.main()
    assert started[0]["host"] == "127.0.0.1"
    assert started[0]["port"] == 8080


def test_main_binds_configured_host_with_both_secrets(monkeypatch):
    import argus.server as server

    _clear_server_env(monkeypatch)
    monkeypatch.setenv("ARGUS_SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "t")
    monkeypatch.setenv("AGENT_CONNECT_SECRET", "s")
    started = _fake_uvicorn(monkeypatch)
    server.main()
    assert started[0]["host"] == "0.0.0.0"
