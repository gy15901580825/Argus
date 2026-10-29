"""`testbed_url: "local"`: run --local starts the bundled testbed on 127.0.0.1 for the run and stops it after."""
import json
import pathlib
import socket
import threading
import time

import httpx
import pytest
from click.testing import CliRunner

from argus.cli.cmd_run import cmd_run
from argus.demo import servers
from argus.local import LocalRunError, run_local

INNER = {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1/chat/completions", "model": "m"}
SPECS = {
    "mcp": ({"kind": "mcp_agent", "testbed_url": "local", "sandbox": True, "inner": INNER}, "mcp_url"),
    "payment": ({"kind": "payment_agent", "testbed_url": "local", "sandbox": True, "inner": INNER}, "merchant_url"),
    "generic": ({"kind": "testbed_agent", "environment": "payment", "testbed_url": "local", "sandbox": True,
                 "inner": INNER}, "merchant_url"),
}
PAYMENT_PROBES = sorted(
    p.stem for p in (pathlib.Path(servers.__file__).parents[1] / "probes/payment").glob("*.yaml")
    if "assertions:" in p.read_text()
)


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.delenv(servers.PORT_ENV, raising=False)


def _port(url: str) -> int:
    return int(url.rsplit(":", 1)[1])


def _closed(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


@pytest.fixture
def no_leftover_threads():
    # Closing the socket alone frees the port; the server thread must stop too.
    before = threading.active_count()
    yield
    assert threading.active_count() == before


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize("name", sorted(SPECS))
def test_local_starts_the_matching_testbed_and_stops_it(name, no_leftover_threads):
    spec, url_key = SPECS[name]
    with servers.local_testbed(spec) as resolved:
        assert resolved["testbed_url"].startswith("http://127.0.0.1:")
        port = _port(resolved["testbed_url"])
        session = httpx.post(f"{resolved['testbed_url']}/sessions", json={}).json()
        assert session[url_key].startswith(resolved["testbed_url"] + "/s/")
        assert {k: v for k, v in resolved.items() if k != "testbed_url"} == {
            k: v for k, v in spec.items() if k != "testbed_url"}
    assert spec["testbed_url"] == "local"  # the caller's spec is not mutated
    assert _closed(port)


def test_a_real_url_is_left_alone_and_nothing_starts(no_leftover_threads):
    spec = {**SPECS["mcp"][0], "testbed_url": "http://10.0.0.5:8092"}
    before = threading.active_count()
    with servers.local_testbed(spec) as resolved:
        assert resolved == spec
        assert threading.active_count() == before


def test_testbed_stops_when_the_run_raises(no_leftover_threads):
    with pytest.raises(RuntimeError, match="boom"):
        with servers.local_testbed(SPECS["mcp"][0]) as resolved:
            port = _port(resolved["testbed_url"])
            raise RuntimeError("boom")
    assert _closed(port)


def test_testbed_stops_on_ctrl_c(no_leftover_threads):
    with pytest.raises(KeyboardInterrupt):
        with servers.local_testbed(SPECS["payment"][0]) as resolved:
            port = _port(resolved["testbed_url"])
            raise KeyboardInterrupt
    assert _closed(port)


def test_port_env_pins_the_port(monkeypatch):
    port = _free_port()
    monkeypatch.setenv(servers.PORT_ENV, str(port))
    with servers.local_testbed(SPECS["mcp"][0]) as resolved:
        assert resolved["testbed_url"] == f"http://127.0.0.1:{port}"
    assert _closed(port)


def test_port_in_use_is_a_clear_error(monkeypatch):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        monkeypatch.setenv(servers.PORT_ENV, str(port))
        with pytest.raises(LocalRunError, match=f"127.0.0.1:{port}") as exc:
            with servers.local_testbed(SPECS["mcp"][0]):
                pass
    assert servers.PORT_ENV in str(exc.value)


@pytest.mark.parametrize("bad", ["abc", "0", "70000"])
def test_bad_port_env_is_a_clear_error(monkeypatch, bad):
    monkeypatch.setenv(servers.PORT_ENV, bad)
    with pytest.raises(LocalRunError, match=servers.PORT_ENV):
        with servers.local_testbed(SPECS["mcp"][0]):
            pass


async def test_payment_demo_agent_against_the_local_testbed_needs_no_key():
    """The bundled payment testbed, with the bundled demo agent, gives real verdicts and remediation."""
    from argus.demo.payment_testbed.demo_agent import app as agent_mod
    from argus.probe import load_probe_library
    from argus.api import PROBES_DIR
    from argus import remediation

    spec = {**SPECS["payment"][0]}
    with servers.local_testbed(spec) as resolved, servers.serve_demo_agent(
            agent_mod, resolved["testbed_url"]) as agent_url:
        resolved["inner"] = {"kind": "openai_compat", "endpoint_url": agent_url, "model": "demo"}
        events = [e async for e in run_local(resolved, PAYMENT_PROBES, env={})]
    findings = [e for e in events if "verdict" in e]
    assert PAYMENT_PROBES
    assert {f["probe_id"] for f in findings} == set(PAYMENT_PROBES)
    assert not [f for f in findings if f["verdict"] == "error"], findings
    assert any(f["verdict"] == "fail" for f in findings)
    library = {p.id: p for p in load_probe_library(PROBES_DIR)}
    for f in findings:
        assert f["remediation"] == remediation.for_probe(library[f["probe_id"]]) != ""


def test_cli_run_local_with_local_testbed(tmp_path, monkeypatch):
    """The real CLI path: resolves "local", runs, records the URL it used, frees the port."""
    from argus.demo.mcp_testbed.demo_agent import app as agent_mod

    port = _free_port()
    monkeypatch.setenv(servers.PORT_ENV, str(port))
    origin = f"http://127.0.0.1:{port}"
    with servers.serve_demo_agent(agent_mod, origin) as agent_url:
        target = tmp_path / "t.json"
        target.write_text(json.dumps({**SPECS["mcp"][0], "inner": {
            "kind": "openai_compat", "endpoint_url": agent_url, "model": "demo"}}))
        out = tmp_path / "run.json"
        result = CliRunner().invoke(cmd_run, [
            "--local", "--target", str(target), "--probes", ",".join(servers.PROBE_IDS),
            "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert f"bundled MCP testbed on {origin}" in result.output
    run = json.loads(out.read_text())
    assert run["target_spec"]["testbed_url"] == origin
    assert len(run["findings"]) == 12
    assert not [f for f in run["findings"] if f["verdict"] == "error"]
    assert any(f["verdict"] == "fail" for f in run["findings"])
    assert all(f["remediation"] for f in run["findings"])
    assert _closed(port)


def test_server_mode_rejects_local(tmp_path):
    target = tmp_path / "t.json"
    target.write_text(json.dumps(SPECS["mcp"][0]))
    result = CliRunner().invoke(cmd_run, [
        "--target", str(target), "--probes", "mcp_shadow_near_name", "--out", str(tmp_path / "r.html"),
        "--api-url", "http://127.0.0.1:9", "--token", "t"])
    assert result.exit_code == 2, result.output
    assert '"local"' in result.output and "--local" in result.output


async def test_agent_that_cannot_reach_the_local_testbed_is_an_error_not_a_pass():
    """The demo agent only calls its pinned origin; a free-port testbed is elsewhere, so it answers 403."""
    from argus.demo.mcp_testbed.demo_agent import app as agent_mod

    with servers.local_testbed(SPECS["mcp"][0]) as resolved, servers.serve_demo_agent(
            agent_mod, f"http://127.0.0.1:{_free_port()}") as agent_url:
        resolved["inner"] = {"kind": "openai_compat", "endpoint_url": agent_url, "model": "demo"}
        events = [e async for e in run_local(resolved, ["mcp_shadow_near_name"], env={})]
    [finding] = [e for e in events if "verdict" in e]
    assert finding["verdict"] == "error"
    assert finding["reasoning"].startswith("agent returned HTTP 403 and never reached the testbed")


@pytest.mark.parametrize("name", ["mcp", "payment"])
def test_local_testbed_ignores_testbed_public_url(name, monkeypatch):
    """TESTBED_PUBLIC_URL is read at import; a shell that exports it must not redirect a local run."""
    import importlib

    mod = importlib.import_module(f"argus.demo.{name}_testbed.testbed.app")
    monkeypatch.setenv("TESTBED_PUBLIC_URL", "http://host.docker.internal:9")
    monkeypatch.setattr(mod, "PUBLIC_BASE_URL", "http://host.docker.internal:9")  # what import would read
    spec, url_key = SPECS[name]
    with servers.local_testbed(spec) as resolved:
        session = httpx.post(f"{resolved['testbed_url']}/sessions", json={}).json()
    assert session[url_key].startswith(resolved["testbed_url"] + "/s/")
    assert mod.PUBLIC_BASE_URL == "http://host.docker.internal:9"  # restored for whoever set it


def test_quickstart_demo_ignores_testbed_public_url(monkeypatch):
    from argus.demo.mcp_testbed.testbed import app as mod

    monkeypatch.setattr(mod, "PUBLIC_BASE_URL", "http://host.docker.internal:9")
    with servers.start_mcp_demo() as spec:
        session = httpx.post(f"{spec['testbed_url']}/sessions", json={}).json()
    assert session["mcp_url"].startswith(spec["testbed_url"] + "/s/")


def test_shutdown_does_not_wait_forever_on_a_half_sent_request(no_leftover_threads):
    """An agent cut off mid-request (Ctrl-C during a probe) must not keep the server thread alive."""
    with servers.local_testbed(SPECS["mcp"][0]) as resolved:
        port = _port(resolved["testbed_url"])
        half = socket.create_connection(("127.0.0.1", port))
        half.sendall(b"POST /sessions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 100\r\n\r\n{\"scen")
        time.sleep(0.2)  # let the server start reading the body
    half.close()
    assert _closed(port)


def test_a_testbed_that_fails_to_start_says_why_fast(no_leftover_threads):
    from contextlib import asynccontextmanager

    from fastapi import FastAPI

    @asynccontextmanager
    async def broken(app):
        raise RuntimeError("database file is locked")
        yield

    sock = servers._bind()
    port = sock.getsockname()[1]
    start = time.monotonic()
    with pytest.raises(RuntimeError, match="the broken server did not start: RuntimeError: database file is locked"):
        with servers._serve(FastAPI(lifespan=broken), sock, "broken server"):
            pass
    assert time.monotonic() - start < 3
    assert _closed(port)


def test_overlapping_runs_keep_the_local_url_and_restore_the_original(monkeypatch):
    """A starts, B starts, A ends, B ends: B still hands out its own URL, and the original comes back."""
    from argus.demo.mcp_testbed.testbed import app as mod

    monkeypatch.setattr(mod, "PUBLIC_BASE_URL", "http://public.example:9")
    a = servers.local_testbed(SPECS["mcp"][0])
    b = servers.local_testbed(SPECS["mcp"][0])
    a.__enter__()
    resolved_b = b.__enter__()
    a.__exit__(None, None, None)
    session = httpx.post(f"{resolved_b['testbed_url']}/sessions", json={}).json()
    assert session["mcp_url"].startswith(resolved_b["testbed_url"] + "/s/")
    b.__exit__(None, None, None)
    assert mod.PUBLIC_BASE_URL == "http://public.example:9"


def test_ctrl_c_right_after_entering_restores_the_public_url(monkeypatch):
    from contextlib import contextmanager

    from argus.demo.mcp_testbed.testbed import app as mod

    monkeypatch.setattr(mod, "PUBLIC_BASE_URL", "http://public.example:9")

    @contextmanager
    def interrupted(*a, **k):
        raise KeyboardInterrupt
        yield  # pragma: no cover

    monkeypatch.setattr(servers, "_serve", interrupted)
    with pytest.raises(KeyboardInterrupt):
        with servers.local_testbed(SPECS["mcp"][0]):
            pass
    assert mod.PUBLIC_BASE_URL == "http://public.example:9"
    assert servers._PUBLIC_URL_USERS[mod.__name__][0] == 0
