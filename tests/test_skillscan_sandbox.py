"""Tests for the scan-skill sandbox: decoys, docker checks, image tags, proxy policy."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from argus.skillscan import sandbox as sandbox_mod
from argus.skillscan.decoys import make_decoys, render_decoy_file
from argus.skillscan.sandbox import SandboxError, check_docker, image_tag

KINDS = {"ssh", "aws", "dotenv", "wallet", "claude_config", "keychain", "browser", "env"}
FAKE_REAL_KEY = "sk-ant-FAKE-REALKEY-123"
AWS_ID = "AK" + "IAQ7XKZP3M4N5B6V7C8X9Z"
_REAL_VERSION_CHECK = sandbox_mod._check_docker_version


@pytest.fixture(autouse=True)
def _docker_version_ok(monkeypatch):
    # Most fake `docker` runs answer "" to everything; the version check has its own tests below.
    monkeypatch.setattr(sandbox_mod, "_check_docker_version", lambda: None)


def test_make_decoys_unique_markers():
    a, b = make_decoys(), make_decoys()
    markers = [d.marker for d in a + b]
    assert len(markers) == len(set(markers))
    assert {d.kind for d in a} == KINDS
    for d in a + b:
        assert len(d.marker) >= 20
        assert len(set(d.marker)) >= 10  # high entropy, not a repeated pattern
    # No fingerprint shared across one run's markers.
    assert len({d.marker[:4] for d in a}) == len(a)


def test_decoys_carry_no_sandbox_fingerprint():
    for d in make_decoys():
        text = render_decoy_file(d)
        assert "argus" not in text.lower()
        assert "decoy" not in text.lower()


def test_dummy_key_is_realistic_and_fresh():
    k1, k2 = sandbox_mod.make_dummy_key(), sandbox_mod.make_dummy_key()
    assert k1 != k2
    assert k1.startswith("sk-ant-api03-") and len(k1) == 108
    assert "argus" not in k1.lower() and "dummy" not in k1.lower()


def test_make_decoys_paths_and_env_names():
    ds = make_decoys()
    paths = {d.path for d in ds if d.kind != "env"}
    assert paths == {
        ".ssh/id_ed25519",
        ".aws/credentials",
        "project/.env",
        ".config/solana/id.json",
        ".claude.json",
        "Library/Keychains/login.keychain-db",
        "Library/Application Support/Google/Chrome/Default/Login Data",
    }
    env_names = {d.path for d in ds if d.kind == "env"}
    assert {"OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"} <= env_names


def test_make_decoys_seed_is_deterministic():
    assert make_decoys("s1") == make_decoys("s1")
    assert make_decoys("s1") != make_decoys("s2")


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_render_decoy_file_contains_marker(kind):
    d = next(x for x in make_decoys() if x.kind == kind)
    text = render_decoy_file(d)
    assert d.marker in text
    if kind != "env":  # an env decoy's value is the marker itself
        assert len(text) > len(d.marker)


def test_render_decoy_shapes():
    by_kind = {d.kind: d for d in make_decoys()}
    assert render_decoy_file(by_kind["ssh"]).startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert "[default]" in render_decoy_file(by_kind["aws"])
    assert render_decoy_file(by_kind["aws"]) == render_decoy_file(by_kind["aws"])
    json.loads(render_decoy_file(by_kind["claude_config"]))
    json.loads(render_decoy_file(by_kind["wallet"]))


def test_check_docker_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(SandboxError) as ei:
        check_docker()
    assert ei.value.code == "docker_missing"
    assert "https://docs.docker.com/get-docker/" in str(ei.value)


def test_check_docker_down(monkeypatch, tmp_path):
    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(SandboxError) as ei:
        check_docker()
    assert ei.value.code == "docker_down"
    assert "\n" not in str(ei.value)


def test_check_docker_timeout_is_down(monkeypatch, tmp_path):
    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    def hang(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    monkeypatch.setattr(sandbox_mod.subprocess, "run", hang)
    with pytest.raises(SandboxError) as ei:
        check_docker()
    assert ei.value.code == "docker_down"


def test_check_docker_ok(monkeypatch, tmp_path):
    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    check_docker()


def test_image_tag_is_content_hash(tmp_path):
    docker_dir = tmp_path / "docker"
    shutil.copytree(sandbox_mod.DOCKER_DIR, docker_dir)
    agent1, proxy1 = image_tag("agent", docker_dir), image_tag("proxy", docker_dir)
    assert agent1 == image_tag("agent", sandbox_mod.DOCKER_DIR)
    name, tag = agent1.split(":")
    assert name == "argus-skillscan-agent"
    assert len(tag) == 12 and int(tag, 16) >= 0
    assert proxy1.startswith("argus-skillscan-proxy:")

    (docker_dir / "agent_entry.sh").write_text((docker_dir / "agent_entry.sh").read_text() + "\n# x\n")
    assert image_tag("agent", docker_dir) != agent1
    assert image_tag("proxy", docker_dir) == proxy1

    (docker_dir / "proxy_addon.py").write_text((docker_dir / "proxy_addon.py").read_text() + "\n# x\n")
    assert image_tag("proxy", docker_dir) != proxy1


def test_ensure_images_skips_existing(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    echoed = []
    agent, proxy = sandbox_mod.ensure_images(echoed.append)
    assert agent == image_tag("agent") and proxy == image_tag("proxy")
    assert echoed == []
    assert not any("build" in c for c in calls)


def test_ensure_images_bounds_inspect_and_build_time(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append((cmd[:3], kw.get("timeout")))
        if cmd[1] == "build":
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        return subprocess.CompletedProcess(cmd, 1, "", "No such image")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with pytest.raises(SandboxError) as e:
        sandbox_mod.ensure_images(lambda s: None)
    assert e.value.code == "build" and "900 seconds" in str(e.value)
    assert (["docker", "image", "inspect"], 30) in seen and (["docker", "build", "-f"], 900) in seen

    def hung(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(sandbox_mod.subprocess, "run", hung)
    with pytest.raises(SandboxError) as e:
        sandbox_mod.ensure_images(lambda s: None)
    assert e.value.code == "build" and "inspect timed out" in str(e.value)


def test_ensure_images_builds_missing_and_echoes_once(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        missing = cmd[:3] == ["docker", "image", "inspect"]
        return subprocess.CompletedProcess(cmd, 1 if missing else 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    echoed = []
    sandbox_mod.ensure_images(echoed.append)
    assert len(echoed) == 1
    assert "minute" in echoed[0] and "network" in echoed[0]
    builds = [c for c in calls if c[:2] == ["docker", "build"]]
    assert len(builds) == 2
    assert {c[c.index("-t") + 1] for c in builds} == {image_tag("agent"), image_tag("proxy")}


@pytest.mark.parametrize("line", [
    "E: Failed to fetch http://deb.debian.org/x  Temporary failure resolving 'deb.debian.org'",
    "npm error code EAI_AGAIN",
    "curl: (6) Could not resolve host: example.com",
])
def test_ensure_images_names_the_dns_fix(monkeypatch, line):
    monkeypatch.setattr(sandbox_mod.socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("x")))

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "build"]:
            return subprocess.CompletedProcess(cmd, 1, "", f"#7 {line}\n#7 ERROR: process did not complete\n")
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with pytest.raises(SandboxError) as ei:
        sandbox_mod.ensure_images(lambda s: None)
    assert ei.value.code == "build"
    assert "/etc/docker/daemon.json" in str(ei.value) and "ARGUS_SKILLSCAN_BUILD_NETWORK=host" in str(ei.value)
    # The local lookup failed, so no retry ran and the message must not claim one.
    assert "even with addresses" not in str(ei.value)


@pytest.mark.parametrize("value,expect", [(None, []), ("host", ["--network", "host"]), ("bridge", [])])
def test_ensure_images_build_network_opt_in(monkeypatch, value, expect):
    builds = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "build"]:
            builds.append(cmd)
        return subprocess.CompletedProcess(cmd, 1 if cmd[:3] == ["docker", "image", "inspect"] else 0, "", "")

    if value is None:
        monkeypatch.delenv("ARGUS_SKILLSCAN_BUILD_NETWORK", raising=False)
    else:
        monkeypatch.setenv("ARGUS_SKILLSCAN_BUILD_NETWORK", value)
    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    sandbox_mod.ensure_images(lambda s: None)
    assert len(builds) == 2 and all(c[2:2 + len(expect)] == expect for c in builds)
    assert all(("--network" in c) == bool(expect) for c in builds)


def test_ensure_images_build_failure(monkeypatch):
    def fake_run(cmd, **kw):
        rc = 1 if cmd[:3] == ["docker", "image", "inspect"] or cmd[:2] == ["docker", "build"] else 0
        return subprocess.CompletedProcess(cmd, rc, "", "boom")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with pytest.raises(SandboxError) as ei:
        sandbox_mod.ensure_images(lambda s: None)
    assert ei.value.code == "build"


def _resolver_fake(monkeypatch, retry_rc, lookup=lambda host: "203.0.113.%d" % (len(host) % 200)):
    builds = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "build"]:
            builds.append(cmd)
            if cmd[cmd.index("-t") + 1] != image_tag("agent"):
                return subprocess.CompletedProcess(cmd, 0, "", "")  # the proxy image fetches nothing
            if "--add-host" not in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "#7 E: Temporary failure resolving 'deb.debian.org'\n")
            return subprocess.CompletedProcess(cmd, retry_rc, "", "" if retry_rc == 0 else
                                               "#7 npm error code EAI_AGAIN registry.npmjs.org\n")
        return subprocess.CompletedProcess(cmd, 1 if cmd[:3] == ["docker", "image", "inspect"] else 0, "", "")

    def fake_getaddrinfo(host, port, family=0, type=0, *a):
        assert family == socket.AF_INET
        if lookup(host) is None:
            raise socket.gaierror("no")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (lookup(host), port))]

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox_mod.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.delenv("ARGUS_SKILLSCAN_BUILD_NETWORK", raising=False)
    return builds


def test_ensure_images_retries_with_host_resolved_addresses(monkeypatch):
    builds = _resolver_fake(monkeypatch, retry_rc=0)
    sandbox_mod.ensure_images(lambda s: None)
    agent = [c for c in builds if c[c.index("-t") + 1] == image_tag("agent")]
    assert len(agent) == 2 and "--add-host" not in agent[0]
    pins = [agent[1][i + 1] for i, a in enumerate(agent[1]) if a == "--add-host"]
    assert pins == ["deb.debian.org:203.0.113.14", "registry.npmjs.org:203.0.113.18"]


def test_ensure_images_retry_also_fails_names_the_dns_fix(monkeypatch):
    builds = _resolver_fake(monkeypatch, retry_rc=1)
    with pytest.raises(SandboxError) as ei:
        sandbox_mod.ensure_images(lambda s: None)
    assert ei.value.code == "build" and "/etc/docker/daemon.json" in str(ei.value)
    assert "even with addresses looked up on this machine" in str(ei.value)
    assert len([c for c in builds if c[c.index("-t") + 1] == image_tag("agent")]) == 2  # one retry, not a loop


def test_ensure_images_no_retry_when_host_lookup_fails(monkeypatch):
    builds = _resolver_fake(monkeypatch, retry_rc=0,
                            lookup=lambda h: None if h == "registry.npmjs.org" else "198.51.100.1")
    with pytest.raises(SandboxError) as ei:
        sandbox_mod.ensure_images(lambda s: None)
    assert "/etc/docker/daemon.json" in str(ei.value) and "even with addresses" not in str(ei.value)
    assert len([c for c in builds if c[c.index("-t") + 1] == image_tag("agent")]) == 1


def test_ensure_images_no_retry_for_other_failures(monkeypatch):
    builds = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "build"]:
            builds.append(cmd)
            return subprocess.CompletedProcess(cmd, 1, "", "#5 ERROR: failed to solve: no space left on device\n")
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with pytest.raises(SandboxError) as ei:
        sandbox_mod.ensure_images(lambda s: None)
    assert "no space left" in str(ei.value) and len(builds) == 1


# ---------------------------------------------------------------------------
# Proxy addon, driven with fake mitmproxy flows.
# ---------------------------------------------------------------------------
class _FakeHeaders(dict):
    """Case-insensitive enough for the addon: keys are stored lower-case."""

    def __init__(self, items):
        super().__init__({k.lower(): v for k, v in items.items()})

    def __setitem__(self, k, v):
        super().__setitem__(k.lower(), v)

    def __getitem__(self, k):
        return super().__getitem__(k.lower())

    def __contains__(self, k):
        return super().__contains__(k.lower())

    def pop(self, k, *default):
        return super().pop(k.lower(), *default)

    def get(self, k, default=None):
        return super().get(k.lower(), default)


class _FakeResponse:
    @classmethod
    def make(cls, status_code, content=b"", headers=None):
        r = cls()
        r.status_code, r.content, r.headers = status_code, content, headers or {}
        return r


class _FakeFlow(types.SimpleNamespace):
    killed = False

    def kill(self):
        self.killed = True


class _FakeRequest(types.SimpleNamespace):
    """The addon must only read raw bytes: mitmproxy's decoding accessors can raise or decode a bomb."""

    @property
    def content(self):
        raise AssertionError("addon read .content (full decode)")

    def get_content(self, strict=True):
        raise AssertionError("addon called get_content (full decode)")


def _flow(host, path, headers, body=b"", method="POST", scheme="https", port=443,
          pretty_host=None, server=None, sni=None):
    req = _FakeRequest(
        host=host, pretty_host=pretty_host or host, port=port, path=path, method=method,
        scheme=scheme, headers=_FakeHeaders(headers), raw_content=body,
    )
    return _FakeFlow(request=req, response=None, metadata={},
                     server_conn=types.SimpleNamespace(address=(server or host, port)),
                     client_conn=types.SimpleNamespace(sni=sni if sni is not None else
                                                       (host if scheme == "https" else None)))


_CC_BODY = json.dumps({"model": "claude-haiku-4-5", "max_tokens": 1000, "messages": [],
                       "tools": [{"name": "Bash", "input_schema": {}}]}).encode()


@pytest.fixture
def addon_mod(monkeypatch):
    monkeypatch.setattr(sys, "dont_write_bytecode", True)  # keep the image build dir clean
    fake_mitm = types.ModuleType("mitmproxy")
    fake_http = types.ModuleType("mitmproxy.http")
    fake_http.Response = _FakeResponse
    fake_mitm.http = fake_http
    monkeypatch.setitem(sys.modules, "mitmproxy", fake_mitm)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", fake_http)
    path = sandbox_mod.DOCKER_DIR / "proxy_addon.py"
    spec = importlib.util.spec_from_file_location("argus_proxy_addon_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # The host sets a task (models, cap, call limit) before any Messages call; most tests need one set.
    init = mod.ArgusProxy.__init__

    def init_with_task(self, *a, **kw):
        init(self, *a, **kw)
        self.set_task("test-task", ["claude-haiku-4-5"], 100.0, 1000)

    monkeypatch.setattr(mod.ArgusProxy, "__init__", init_with_task)
    return mod


def test_proxy_addon_policy(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))

    anth = _flow("api.anthropic.com", "/v1/messages?beta=true",
                 {"x-api-key": "sk-ant-api03-dummy", "Content-Type": "application/json"},
                 body=_CC_BODY.replace(b'"messages": []', b'"messages": [{"role": "user", "content": "secret-prompt"}]'))
    addon.request(anth)
    assert anth.request.headers["x-api-key"] == FAKE_REAL_KEY
    assert anth.response is None

    evil = _flow("evil.example", "/collect?k=" + AWS_ID,
                 {"Authorization": "Bearer xyz", "X-Api-Key": "sk-ant-api03-dummy",
                  "User-Agent": "curl/8"},
                 body=b"stolen=" + AWS_ID.encode())
    addon.request(evil)
    assert evil.response is not None and evil.response.status_code == 403

    text = log.read_text()
    assert FAKE_REAL_KEY not in text
    raw = [json.loads(line) for line in text.splitlines()]
    # The refused request is written on arrival and again after its scan, with the same rid and ts.
    assert len(raw) == 3 and raw[1]["rid"] == raw[2]["rid"] and raw[1]["ts"] == raw[2]["ts"]
    assert (raw[1]["body"], raw[1]["scan_complete"]) == ("", False)
    recs = sandbox_mod.merge_proxy_rows(raw)
    assert len(recs) == 2
    a, e = recs
    assert a["host"] == "api.anthropic.com" and a["allowed"] is True and a["body"] == ""
    assert (a["outcome"], a["markers_found"], a["scan_complete"]) == ("forwarded", [], True)
    assert "secret-prompt" not in text
    assert e == {
        "ts": e["ts"], "rid": e["rid"], "method": "POST", "host": "evil.example", "port": 443,
        "path": "/collect?k=" + AWS_ID,
        "headers": {"user-agent": "curl/8"},
        "body": "stolen=" + AWS_ID, "allowed": False,
        "outcome": "refused", "markers_found": [], "scan_complete": True,
    }
    assert isinstance(e["ts"], float)
    for r in recs:
        assert not {"x-api-key", "authorization"} & {k.lower() for k in r["headers"]}


def test_proxy_addon_plain_http_to_anthropic_is_denied(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "dummy"}, scheme="http", port=80)
    addon.request(f)
    assert f.response.status_code == 403
    assert f.request.headers["x-api-key"] == "dummy"
    assert FAKE_REAL_KEY not in log.read_text()


def test_proxy_addon_truncates_body(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    addon.request(_flow("x.example", "/", {}, body=b"a" * 100_000))
    (rec,) = _recs(log)
    assert len(rec["body"]) == 64 * 1024


def test_proxy_addon_redacts_real_key_if_echoed(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    addon.request(_flow("x.example", "/?k=" + FAKE_REAL_KEY, {"x-other": FAKE_REAL_KEY},
                        body=FAKE_REAL_KEY.encode()))
    assert FAKE_REAL_KEY not in log.read_text()


def _recs(log):
    return sandbox_mod.merge_proxy_rows([json.loads(line) for line in log.read_text().splitlines()])


@pytest.mark.parametrize("host,pretty,server,sni", [
    ("evil.example", "api.anthropic.com", "evil.example", "evil.example"),   # forged Host header
    ("api.anthropic.com", "evil.example", "api.anthropic.com", "api.anthropic.com"),
    ("api.anthropic.com", "api.anthropic.com", "evil.example", "api.anthropic.com"),  # tunnel elsewhere
    ("api.anthropic.com", "api.anthropic.com", "api.anthropic.com", "evil.example"),  # SNI elsewhere
])
def test_proxy_addon_host_mismatch_is_denied(addon_mod, tmp_path, host, pretty, server, sni):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow(host, "/v1/messages", {"x-api-key": "dummy"}, body=_CC_BODY,
              pretty_host=pretty, server=server, sni=sni)
    addon.request(f)
    assert f.response is not None and f.response.status_code == 403
    assert f.request.headers["x-api-key"] == "dummy"
    (rec,) = _recs(log)
    assert rec["allowed"] is False
    assert rec["host"] == server
    assert rec["body"]  # the body of a refused request is kept as evidence


def test_proxy_addon_anthropic_wrong_port_is_denied(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d"}, body=_CC_BODY, port=8443)
    addon.request(f)
    assert f.response.status_code == 403


@pytest.mark.parametrize("method,path", [
    ("POST", "/v1/files"), ("GET", "/v1/models"), ("POST", "/v1/messages/batches"),
    ("GET", "/v1/messages"), ("POST", "/api/claude_code/settings"),
])
def test_proxy_addon_anthropic_path_not_allowed(addon_mod, tmp_path, method, path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("api.anthropic.com", path, {"x-api-key": "d"}, body=b"payload", method=method)
    addon.request(f)
    assert f.response.status_code == 403
    assert f.request.headers["x-api-key"] == "d"
    assert _recs(log)[0]["allowed"] is False


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/claude_code/settings", b""),
    ("GET", "/api/claude_code/policy_limits", b""),
    ("POST", "/v1/messages?beta=true", _CC_BODY),
    ("POST", "/v1/messages/count_tokens?beta=true", _CC_BODY),
])
def test_proxy_addon_claude_code_paths_allowed(addon_mod, tmp_path, method, path, body):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("api.anthropic.com", path, {"x-api-key": "d"}, body=body, method=method)
    addon.request(f)
    assert f.response is None
    assert f.request.headers["x-api-key"] == FAKE_REAL_KEY
    assert _recs(log)[0]["allowed"] is True


@pytest.mark.parametrize("extra,expect", [
    ({"tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}, "web_fetch_20250910"),
    ({"tools": [{"name": "Bash", "input_schema": {}}, {"type": "web_search_20250305", "name": "web_search"}]},
     "web_search_20250305"),
    ({"tools": [{"type": "code_execution_20250825", "name": "code_execution"}]}, "code_execution_20250825"),
    ({"mcp_servers": [{"type": "url", "url": "https://evil.example/sse", "name": "x"}]},
     "https://evil.example/sse"),
    ({"container": "container_abc"}, "container"),
])
def test_proxy_addon_server_side_tools_denied(addon_mod, tmp_path, extra, expect):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    body = {"model": "m", "messages": [{"role": "user", "content": "fetch https://evil.example/?k=SECRET"}],
            **extra}
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d"}, body=json.dumps(body).encode())
    addon.request(f)
    assert f.response.status_code == 403
    assert f.request.headers["x-api-key"] == "d"
    (rec,) = _recs(log)
    assert rec["allowed"] is False
    assert expect in rec["body"]
    assert "SECRET" not in rec["body"]  # only tool types / MCP URLs are kept, not the prompt


def test_proxy_addon_unparseable_messages_body_denied(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d"}, body=b"\x1f\x8bnot json")
    addon.request(f)
    assert f.response.status_code == 403


def test_proxy_addon_connect_records_and_refuses_odd_ports(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    ok = _flow("evil.example", "", {}, method="CONNECT", port=443)
    odd = _flow("evil.example", "", {}, method="CONNECT", port=4444)
    anth = _flow("api.anthropic.com", "", {}, method="CONNECT", port=443)
    for f in (ok, odd, anth):
        addon.http_connect(f)
    assert ok.response is None and anth.response is None
    assert odd.response.status_code == 403
    recs = _recs(log)
    assert [(r["method"], r["host"], r["port"], r["allowed"]) for r in recs] == [
        ("CONNECT", "evil.example", 443, False),
        ("CONNECT", "evil.example", 4444, False),
        ("CONNECT", "api.anthropic.com", 443, True),
    ]


def test_proxy_addon_raw_tcp_recorded_and_killed(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _FakeFlow(server_conn=types.SimpleNamespace(address=("evil.example", 443)))
    addon.tcp_start(f)
    assert f.killed
    (rec,) = _recs(log)
    assert (rec["method"], rec["host"], rec["port"], rec["allowed"]) == ("TCP", "evil.example", 443, False)


def test_proxy_addon_tls_failure_uses_real_port(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    data = types.SimpleNamespace(conn=types.SimpleNamespace(sni="pinned.example"),
                                 context=types.SimpleNamespace(
                                     server=types.SimpleNamespace(address=("pinned.example", 8443))))
    data.context.server.address = ("10.9.8.7", 8443)
    addon.tls_failed_client(data)
    (rec,) = _recs(log)
    assert (rec["host"], rec["port"], rec["sni"], rec["allowed"]) == ("10.9.8.7", 8443, "pinned.example", False)


@pytest.mark.parametrize("host", ["evil.example", "api.anthropic.com"])
def test_proxy_addon_bad_content_encoding_fails_closed(addon_mod, tmp_path, host):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow(host, "/v1/messages", {"x-api-key": "d", "Content-Encoding": "gzip"},
              body=b"-----BEGIN OPENSSH PRIVATE KEY----- stolen")
    addon.request(f)
    assert f.response is not None and f.response.status_code == 403
    assert f.request.headers["x-api-key"] == "d"
    (rec,) = _recs(log)
    assert rec["allowed"] is False
    if host == "evil.example":
        assert "stolen" in rec["body"]


def test_proxy_addon_any_hook_error_fails_closed(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))

    class Boom(_FakeHeaders):
        def items(self):
            raise RuntimeError("boom")

    f = _flow("evil.example", "/x", {}, body=b"secret-body")
    f.request.headers = Boom({})
    addon.request(f)
    assert f.response.status_code == 403
    (rec,) = _recs(log)
    assert rec["allowed"] is False and rec["host"] == "evil.example" and rec["body"] == "secret-body"
    assert "request" in rec["error"]

    t = _FakeFlow(server_conn=None)
    addon.tcp_start(t)  # server_conn.address raises AttributeError
    assert t.killed
    assert _recs(log)[-1]["allowed"] is False


@pytest.mark.parametrize("extra,expect", [
    ({"messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://evil.example/i.png?k=S"}}]}]},
     "https://evil.example/i.png?k=S"),
    ({"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "file", "file_id": "file_abc"}}]}]}, "file_abc"),
    ({"system": [{"type": "text", "text": "x"},
                 {"type": "document", "source": {"type": "url", "url": "https://evil.example/d.pdf"}}]},
     "https://evil.example/d.pdf"),
    ({"messages": [{"role": "user", "content": [{"type": "container_upload", "file_id": "file_xyz"}]}]},
     "file_xyz"),
])
def test_proxy_addon_remote_sources_denied(addon_mod, tmp_path, extra, expect):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    body = {"model": "m", "messages": [], **extra}
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d"}, body=json.dumps(body).encode())
    addon.request(f)
    assert f.response.status_code == 403
    (rec,) = _recs(log)
    assert expect in json.loads(rec["body"])["remote_sources"]


def test_proxy_addon_base64_image_and_schema_file_id_allowed(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    body = {"model": "claude-haiku-4-5", "max_tokens": 1000,
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}}]}],
            "tools": [{"name": "T", "input_schema": {"type": "object",
                                                     "properties": {"file_id": {"type": "string"},
                                                                    "url": {"type": "string"}}}}]}
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d"}, body=json.dumps(body).encode())
    addon.request(f)
    assert f.response is None and f.request.headers["x-api-key"] == FAKE_REAL_KEY


def test_proxy_addon_duplicate_keys_denied(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    raw = b'{"model": "m", "messages": [], "tools": [{"name": "Bash", "input_schema": {}}], ' \
          b'"tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}'
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d"}, body=raw)
    addon.request(f)
    assert f.response.status_code == 403
    assert "duplicate" in _recs(log)[0]["body"]


def test_proxy_error_pages_are_generic(addon_mod):
    for status in (400, 403, 502):
        page = addon_mod.http1_error(status) + addon_mod.generic_error(status, "mitmproxy says hi")
        assert b"mitmproxy" not in page.lower() and b"server:" not in page.lower()
        assert page.startswith(f"HTTP/1.1 {status} ".encode())


def test_proxy_403_body_is_generic(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(tmp_path / "p.jsonl"))
    f = _flow("x.example", "/", {})
    addon.request(f)
    assert f.response.content == b"403 Forbidden\n"


MARKER = "sk_" + "live_" + "Q7vT2mLp9Xk3RbN8wZ4cYh1D"


@pytest.mark.parametrize("where", ["path", "header", "host"])
def test_proxy_addon_surrogates_still_recorded(addon_mod, tmp_path, where):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    bad = "x\udcff"  # how mitmproxy keeps a raw 0xff byte
    f = _flow(bad + ".example" if where == "host" else "evil.example",
              "/" + bad if where == "path" else "/", {"x-h": bad} if where == "header" else {},
              body=MARKER.encode())
    addon.request(f)
    assert f.response.status_code == 403
    rows = _recs(log)
    assert len(rows) == 1
    rec = rows[0]
    assert rec["allowed"] is False and MARKER in rec["body"]


def test_proxy_addon_record_failure_has_last_resorts(addon_mod, tmp_path, monkeypatch):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("evil.example", "/x", {}, body=MARKER.encode())
    f.request.host = object()  # not JSON-serialisable: the normal row fails, the repr() row must not
    f.request.headers = types.SimpleNamespace(items=lambda: 1 / 0)
    addon.request(f)
    assert f.response.status_code == 403
    (rec,) = _recs(log)
    assert rec["allowed"] is False and MARKER in rec["body"]

    real_write = addon._write
    monkeypatch.setattr(addon, "_write", lambda rec: (_ for _ in ()).throw(OSError("disk")))
    g = _flow("evil.example", "/y", {})
    g.request.headers = types.SimpleNamespace(items=lambda: 1 / 0)
    addon.request(g)
    assert g.response.status_code == 403
    last = json.loads(log.read_text().splitlines()[-1])
    assert last["error"] == "record failed" and last["allowed"] is False
    assert abs(last["ts"] - time.time()) < 5  # inside the task window, not ts 0
    assert real_write


def test_proxy_addon_record_failure_fallback_keeps_rid_and_ts(addon_mod, tmp_path):
    """The ascii() fallback row still merges with its arrival row: rid stays a str and ts a float."""
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("evil.example", "/x", {})
    arrival = {"ts": 123.5, "rid": "r7", "method": "POST", "host": "evil.example", "allowed": False}
    log.write_text(json.dumps(arrival) + "\n")
    f.request.host = object()  # the normal row cannot be written
    addon._record_failure("request", f, ValueError("boom"), {"ts": 123.5, "rid": "r7"})
    last = json.loads(log.read_text().splitlines()[-1])
    assert last["rid"] == "r7" and last["ts"] == 123.5 and isinstance(last["host"], str)
    (merged,) = _recs(log)
    assert "ValueError" in merged["error"] and merged["host"] != "evil.example"  # the failure row overlaid it


def _fake_http1(monkeypatch, has_target):
    mods = {}
    for name in ("mitmproxy.proxy", "mitmproxy.proxy.layers", "mitmproxy.proxy.layers.http",
                 "mitmproxy.proxy.layers.http._http1"):
        mods[name] = types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, mods[name])
    h1 = mods["mitmproxy.proxy.layers.http._http1"]
    mods["mitmproxy.proxy.layers.http"]._http1 = h1
    if has_target:
        h1.make_error_response = lambda status, message="": b"Server: mitmproxy"
    return h1


def test_branding_patch_applies(addon_mod, monkeypatch, tmp_path):
    h1 = _fake_http1(monkeypatch, has_target=True)
    exits = []
    monkeypatch.setattr(os, "_exit", exits.append)
    log = tmp_path / "p"
    addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log)).running()
    assert exits == []
    page = h1.make_error_response(502, "upstream mitmproxy")
    assert b"mitmproxy" not in page and b"server:" not in page.lower()
    # A request line mitmproxy cannot parse is still recorded, marker included.
    h1.make_error_response(400, f"Bad HTTP request line: b'POST http://evil.example/x\\xff?k={MARKER} HTTP/1.1'")
    rows = _recs(log)
    assert rows[-1]["method"] == "ERROR" and rows[-1]["allowed"] is False and MARKER in rows[-1]["body"]


def test_branding_patch_fails_closed(addon_mod, monkeypatch, tmp_path):
    _fake_http1(monkeypatch, has_target=False)
    exits = []
    monkeypatch.setattr(os, "_exit", exits.append)
    addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p")).running()
    assert exits == [1]


def test_proxy_addon_gzip_bomb_is_capped(addon_mod, tmp_path):
    import zlib
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    comp = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    bomb = comp.compress((MARKER + "\n").encode() + b"\0" * (200 * 1024 * 1024)) + comp.flush()
    assert len(bomb) < 1024 * 1024
    f = _flow("evil.example", "/", {"Content-Encoding": "gzip"}, body=bomb)
    addon.request(f)  # the fake request raises if anything fully decodes the body
    assert f.response.status_code == 403
    (rec,) = _recs(log)
    assert rec["body"].startswith(MARKER)
    assert len(rec["body"]) == 64 * 1024


def test_proxy_addon_anthropic_compressed_body_refused(addon_mod, tmp_path):
    import gzip
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("api.anthropic.com", "/v1/messages", {"x-api-key": "d", "Content-Encoding": "gzip"},
              body=gzip.compress(_CC_BODY))
    addon.request(f)
    assert f.response.status_code == 403 and f.request.headers["x-api-key"] == "d"
    assert "content-encoding gzip" in _recs(log)[0]["body"]


def _zstd_bomb(prefix: bytes, zeros: int) -> bytes:
    """A zstd frame by hand (no encoder needed): one raw block, then 128 KiB RLE blocks of zeros."""
    def block(last, kind, size):
        return (last | kind << 1 | size << 3).to_bytes(3, "little")
    n = zeros // (128 * 1024)
    out = bytearray(b"\x28\xb5\x2f\xfd\x00\x38")  # magic; no content size or checksum; 128 KiB window
    out += block(0, 0, len(prefix)) + prefix
    for i in range(n):
        out += block(int(i == n - 1), 1, 128 * 1024) + b"\0"
    return bytes(out)


def _brotli_bomb(prefix: bytes, zeros: int) -> bytes:
    brotli = pytest.importorskip("brotli")
    c = brotli.Compressor(quality=1)
    parts = [c.process(prefix)] + [c.process(b"\0" * (1 << 20)) for _ in range(zeros >> 20)]
    return b"".join(parts) + c.finish()


def _max_rss_mib():
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


@pytest.mark.parametrize("enc", ["br", "zstd"])
def test_proxy_addon_br_and_zstd_bombs_are_capped(addon_mod, tmp_path, enc):
    if enc == "zstd":
        pytest.importorskip("compression.zstd")  # stdlib from 3.14 when built with libzstd; the proxy has it
        bomb = _zstd_bomb((MARKER + "\n").encode(), 1 << 30)
    else:
        bomb = _brotli_bomb((MARKER + "\n").encode(), 1 << 30)
    assert len(bomb) < 512 * 1024
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("evil.example", "/", {"Content-Encoding": enc}, body=bomb)
    before = _max_rss_mib()
    addon.request(f)
    assert _max_rss_mib() - before < 256  # a full decode would need 1 GiB
    assert f.response.status_code == 403
    (rec,) = _recs(log)
    assert rec["body"].startswith(MARKER)
    assert len(rec["body"]) == 64 * 1024


@pytest.mark.parametrize("enc,lib", [("br", "brotli"), ("zstd", "zstd")])
def test_proxy_addon_br_zstd_raw_when_decoder_missing(addon_mod, tmp_path, monkeypatch, enc, lib):
    monkeypatch.setattr(addon_mod, lib, None)
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    raw = b"\x8b\x00" + b"x" * (100 * 1024)
    f = _flow("evil.example", "/", {"Content-Encoding": enc}, body=raw)
    addon.request(f)
    assert f.response.status_code == 403
    (rec,) = _recs(log)
    assert rec["body"] == raw[:64 * 1024].decode("utf-8", "replace")


def test_proxy_addon_corrupt_br_recorded_raw(addon_mod, tmp_path):
    pytest.importorskip("brotli")
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    f = _flow("evil.example", "/", {"Content-Encoding": "br"}, body=b"not brotli " + MARKER.encode())
    addon.request(f)
    assert f.response.status_code == 403 and MARKER in _recs(log)[0]["body"]


def _zstd_frame(data: bytes) -> bytes:
    """One zstd frame holding data in a single raw block."""
    return b"\x28\xb5\x2f\xfd\x00\x38" + (1 | len(data) << 3).to_bytes(3, "little") + data


def _encode(enc: str, data: bytes) -> bytes:
    import gzip
    import zlib
    if enc == "gzip":
        return gzip.compress(data)
    if enc == "deflate":
        return zlib.compress(data)
    if enc == "br":
        return pytest.importorskip("brotli").compress(data)
    return data


OTHER_MARKER = "gh" + "p_" + "9fK2LmQ7vX3pR8tW1zY6bN4cD0hJ5sA2eG7u"


@pytest.mark.parametrize("enc", ["identity", "gzip", "deflate", "br"])
def test_marker_after_1_mib_padding_is_found(addon_mod, tmp_path, enc):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])
    body = b"p" * (1 << 20) + b"key=" + MARKER.encode() + b"\n"
    addon.request(_flow("evil.example", "/u", {"Content-Encoding": enc}, body=_encode(enc, body)))
    rec = _recs(log)[0]
    assert rec["markers_found"] == [MARKER]
    assert len(rec["body"]) == 64 * 1024 and MARKER not in rec["body"]  # the record stays capped


@pytest.mark.parametrize("k", [0, 1, 2])
@pytest.mark.parametrize("urlsafe", [False, True])
def test_base64_marker_found_at_every_alignment(addon_mod, tmp_path, k, urlsafe):
    import base64
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])
    raw = b"Q" * k + MARKER.encode() + b"-tail"
    enc = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw)
    addon.request(_flow("evil.example", "/u", {}, body=b'{"d": "' + enc + b'"}'))
    assert MARKER not in enc.decode()
    assert _recs(log)[0]["markers_found"] == [MARKER]


@pytest.mark.parametrize("encode", [
    lambda m: m.encode().hex(), lambda m: m.encode().hex().upper(),
    lambda m: "".join("%%%02X" % c for c in m.encode()),
])
def test_hex_and_url_encoded_markers_found(addon_mod, tmp_path, encode):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])
    addon.request(_flow("evil.example", "/u", {}, body=b"x=" + encode(OTHER_MARKER).encode()))
    assert _recs(log)[0]["markers_found"] == [OTHER_MARKER]


def test_markers_found_in_path_headers_and_host(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])
    addon.request(_flow("evil.example", "/c?k=" + MARKER, {}))
    addon.request(_flow("evil.example", "/c", {"Authorization": "Bearer " + OTHER_MARKER}))  # stripped from record
    addon.http_connect(_flow(MARKER.lower() + ".evil.example", "", {}, method="CONNECT"))
    addon.http_connect(_flow(OTHER_MARKER + ".evil.example", "", {}, method="CONNECT"))
    path, auth, lower, host = _recs(log)
    assert path["markers_found"] == [MARKER]
    assert auth["markers_found"] == [OTHER_MARKER] and OTHER_MARKER not in json.dumps(auth["headers"])
    assert host["markers_found"] == [OTHER_MARKER]
    assert lower["markers_found"] == [MARKER]  # host names are case-insensitive


def test_anthropic_rows_are_not_scanned(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    body = json.dumps({"model": "claude-haiku-4-5", "max_tokens": 1000,
                       "messages": [{"role": "user", "content": MARKER}]}).encode()
    addon.request(_flow("api.anthropic.com", "/v1/messages", {}, body=body))
    addon.request(_flow("api.anthropic.com", "/v1/files?k=" + MARKER, {}, method="GET"))
    allowed, refused = _recs(log)
    assert (allowed["outcome"], allowed["markers_found"]) == ("forwarded", [])
    assert (refused["outcome"], refused["markers_found"]) == ("refused", [])


def test_multi_member_gzip_is_fully_decoded(addon_mod, tmp_path):
    import gzip
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    body = gzip.compress(b"first;") + gzip.compress(b"second=" + MARKER.encode())
    addon.request(_flow("evil.example", "/u", {"Content-Encoding": "gzip"}, body=body))
    rec = _recs(log)[0]
    assert rec["body"] == "first;second=" + MARKER and rec["markers_found"] == [MARKER]


def test_multi_frame_zstd_is_fully_decoded(addon_mod, tmp_path):
    pytest.importorskip("compression.zstd")
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    body = _zstd_frame(b"first;") + _zstd_frame(b"second=" + MARKER.encode())
    addon.request(_flow("evil.example", "/u", {"Content-Encoding": "zstd"}, body=body))
    rec = _recs(log)[0]
    assert rec["body"] == "first;second=" + MARKER and rec["markers_found"] == [MARKER]


def test_decoding_cap_is_cumulative_across_gzip_members(addon_mod):
    import zlib
    c = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    member = c.compress(b"\0" * (40 << 20)) + c.flush()
    total = sum(len(x) for x in addon_mod._decoded_chunks(member * 3, "gzip", addon_mod.SCAN_LIMIT))
    assert total == addon_mod.SCAN_LIMIT


class _FakeHttp1Server:
    """Stands in for mitmproxy's Http1Server, which calls make_error_response from its own method."""

    def __init__(self, addon, conn_id):
        self.addon, self.conn = addon, types.SimpleNamespace(id=conn_id)

    def send_error(self, status, message):
        return self.addon._error_response(status, message)


def _failed_flow(host, path, conn_id, msg):
    f = _flow(host, path, {})
    f.client_conn.id = conn_id
    f.error = types.SimpleNamespace(msg=msg)
    return f


def test_error_page_rows_name_the_real_failure(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    msg = "server connection failed: [Errno 111] refused"
    # Two failed flows with the same message on different connections: each page names its own flow.
    addon.error(_failed_flow("api.anthropic.com", "/v1/messages", "c1", msg))
    addon.error(_failed_flow("evil.example", "/x", "c2", msg))
    page = _FakeHttp1Server(addon, "c1").send_error(502, msg)
    _FakeHttp1Server(addon, "c2").send_error(502, msg)
    _FakeHttp1Server(addon, "c3").send_error(502, "server closed connection")  # no matching flow
    _FakeHttp1Server(addon, "c4").send_error(400, "Bad HTTP request line: b'x'")
    up, evil, unknown, bad = _recs(log)
    assert page.startswith(b"HTTP/1.1 502 Bad Gateway") and b"mitmproxy" not in page
    # A 502 on an allowed request keeps allowed=True: allowed is the policy, outcome is what happened.
    assert (up["host"], up["path"], up["allowed"], up["outcome"], up["error"]) == (
        "api.anthropic.com", "/v1/messages", True, "upstream_error", "upstream connection or response failed (502)")
    assert (evil["host"], evil["path"], evil["allowed"], evil["outcome"]) == (
        "evil.example", "/x", False, "upstream_error")
    assert (unknown["host"], unknown["allowed"], unknown["outcome"]) == ("", False, "upstream_error")
    assert (bad["error"], bad["outcome"], bad["allowed"]) == (
        "proxy refused a malformed request (400)", "parse_error", False)
    assert addon._error_targets == {}


def test_error_targets_cleared_on_disconnect(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    addon.error(_failed_flow("evil.example", "/stale", "c1", "boom"))
    addon.client_disconnected(types.SimpleNamespace(id="c1"))  # the page was never built
    assert addon._error_targets == {}
    _FakeHttp1Server(addon, "c1").send_error(502, "boom")  # a later page on a reused id names nothing
    assert _recs(log)[0]["host"] == ""


# ---------------------------------------------------------------------------
# File monitor pieces, run locally.
# ---------------------------------------------------------------------------
def _stamp_script(tmp_path):
    text = (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()
    body = text.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    path = tmp_path / "stamp.py"
    path.write_text(body)
    return path


def test_stamp_rows_cannot_be_forged_by_file_names(tmp_path):
    feed = (b"CREATE\0/home/agent/.claude/hooks/a\nOPEN|/home/agent/.ssh/id_ed25519\0"
            b"Q_OVERFLOW\0\0"
            b"OPEN\0/home/agent/.ssh/id_ed25519\0")
    out = subprocess.run([sys.executable, "-I", str(_stamp_script(tmp_path))], input=feed,
                         capture_output=True, check=True).stdout.decode().splitlines()
    rows = [json.loads(line) for line in out]
    assert [(r["path"], r["event"]) for r in rows] == [
        ("/home/agent/.claude/hooks/a\nOPEN|/home/agent/.ssh/id_ed25519", "CREATE"),
        ("", "Q_OVERFLOW"),
        ("/home/agent/.ssh/id_ed25519", "OPEN"),
    ]


def test_stamp_decoy_dirs_keep_only_decoys(tmp_path):
    watch = tmp_path / "watch-files"
    watch.write_text("/home/agent/.ssh/id_ed25519\n/home/agent/Library/Application Support/x/Login Data\n")
    feed = (b"DELETE\0/home/agent/.ssh/id_ed25519\0CREATE\0/home/agent/.ssh/id_ed25519\0"
            b"OPEN\0/home/agent/.ssh/id_ed25519\0ACCESS\0/home/agent/.ssh/known_hosts\0"
            b"OPEN\0/home/agent/Library/Application Support/x/Login Data\0"
            b"OPEN,ISDIR\0/home/agent/.ssh/\0DELETE_SELF\0/home/agent/.ssh/\0MOVE_SELF\0/home/agent/.ssh/\0")
    out = subprocess.run([sys.executable, "-I", str(_stamp_script(tmp_path)), "decoys", str(watch)], input=feed,
                         capture_output=True, check=True).stdout.decode().splitlines()
    assert [(r["path"], r["event"]) for r in map(json.loads, out)] == [
        ("/home/agent/.ssh/id_ed25519", "MODIFY"),
        ("/home/agent/.ssh/id_ed25519", "CREATE"),
        ("/home/agent/.ssh/id_ed25519", "OPEN"),
        ("/home/agent/Library/Application Support/x/Login Data", "OPEN"),
        # The watched decoy dir itself going away is a row; reading the dir is not.
        ("/home/agent/.ssh", "MODIFY"),
        ("/home/agent/.ssh", "MODIFY"),
    ]


def test_stamp_dirs_mode_keeps_decoys_and_their_dirs(tmp_path):
    watch = tmp_path / "watch-files"
    watch.write_text("/home/agent/.claude.json\n/home/agent/project/.env\n/home/agent/.config/solana/id.json\n")
    feed = (b"MODIFY\0/home/agent/.claude.json\0CREATE\0/home/agent/notes.txt\0"
            b"MODIFY\0/home/agent/project/.env\0MODIFY\0/home/agent/project/big.txt\0"
            b"DELETE,ISDIR\0/home/agent/.config\0MOVED_FROM,ISDIR\0/home/agent/.cache\0")
    out = subprocess.run([sys.executable, "-I", str(_stamp_script(tmp_path)), "dirs", str(watch)], input=feed,
                         capture_output=True, check=True).stdout.decode().splitlines()
    assert [(r["path"], r["event"]) for r in map(json.loads, out)] == [
        ("/home/agent/.claude.json", "MODIFY"),
        ("/home/agent/project/.env", "MODIFY"),
        ("/home/agent/.config", "MODIFY"),
    ]


_FAKE_INOTIFYWAIT = """#!/bin/sh
echo $$ >> "$FAKE_DIR/pids"
echo "$@" >> "$FAKE_DIR/argv"
read -r p
echo "$p" >> "$FAKE_DIR/stdin"
[ -n "$FAKE_RM" ] && rm -f "$p"
if [ -n "$FAKE_SWAP" ] && [ ! -e "$FAKE_DIR/swapped" ]; then touch "$FAKE_DIR/swapped"; cp "$p" "$p.n"; mv "$p.n" "$p"; fi
[ -e "$p" ] || { echo "Couldn't watch $p: No such file or directory" >&2; echo $$ >> "$FAKE_DIR/end"; exit 1; }
if [ "$FAKE_MODE" = fail ]; then
  echo "${FAKE_ERR:-Failed to watch $p; upper limit on inotify instances reached}" >&2; echo $$ >> "$FAKE_DIR/end"; exit 1
fi
echo x >> "$FAKE_DIR/est"
# Sync marker for the test: the filter reads stdout only after its post-setup inode check, so this row shows
# that check is done. Q_OVERFLOW is emitted for any watch; the helper counts it with its own sentinels.
printf 'Q_OVERFLOW\\0\\0'
echo "Setting up watches." >&2
echo "Watches established." >&2
[ -z "$FAKE_LATE" ] && printf 'ACCESS\\0%s%s\\0' "$p" "$FAKE_SUFFIX"
# The watcher lives until the test has fed every event, then ends (a late read is reported at that moment).
until [ -e "$FAKE_DIR/release" ]; do sleep 0.02; done
[ -n "$FAKE_LATE" ] && printf 'ACCESS\\0%s%s\\0' "$p" "$FAKE_SUFFIX"
echo $$ >> "$FAKE_DIR/end"
if [ -n "$FAKE_LAST" ]; then printf '%s\\0%s\\0' "$FAKE_LAST" "$p"; exec sleep 30; fi
"""
# Waits are on observed state (rows, the fake's marker files), each with a generous deadline. A state must also
# hold this long, which only covers the moment between the filter starting a fake and the fake writing its argv.
_QUIET_S = 0.5
_WAIT_S = 30


def _run_stamp_rewatch(tmp_path, mode, decoys, feed, *, fake_mode="ok", suffix="", err="",
                       last="", late="", max_per_path=None, rm="", swap=""):
    """Run the stamp filter with H under tmp_path and a fake inotifywait; return rows and what the fake saw."""
    home = tmp_path / "home"
    fake_dir = tmp_path / "fake"
    fake_dir.mkdir(exist_ok=True)
    for n in ("argv", "stdin", "swapped", "est", "end", "pids", "release"):  # each call reports only its own watchers
        (fake_dir / n).unlink(missing_ok=True)
    fake = fake_dir / "inotifywait"
    fake.write_text(_FAKE_INOTIFYWAIT)
    fake.chmod(0o755)
    script = _stamp_script(tmp_path)
    text = script.read_text().replace('H = "/home/agent"', f"H = {str(home)!r}") \
        .replace('INOTIFYWAIT = "/usr/bin/inotifywait"', f"INOTIFYWAIT = {str(fake)!r}")
    if max_per_path is not None:
        text = text.replace("MAX_PER_PATH = 4", f"MAX_PER_PATH = {max_per_path}")
    script.write_text(text)
    watch = tmp_path / "watch-files"
    watch.write_text("".join(f"{home}/{d}\n" for d in decoys))
    env = {**os.environ, "FAKE_DIR": str(fake_dir), "FAKE_MODE": fake_mode,
           "FAKE_SUFFIX": suffix, "FAKE_LAST": last, "FAKE_LATE": late, "FAKE_RM": rm, "FAKE_SWAP": swap}
    if err:
        env["FAKE_ERR"] = err
    p = subprocess.Popen([sys.executable, "-I", str(script), mode, str(watch)], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, env=env)
    rows: list[tuple[str, str]] = []
    threading.Thread(target=lambda: rows.extend(
        (r["path"].replace(str(home), "~"), r["event"]) for r in map(json.loads, p.stdout)), daemon=True).start()

    def lines(n):
        f = fake_dir / n
        return f.read_text().splitlines() if f.exists() else []

    def state():
        return (len(rows), len(lines("argv")), len(lines("stdin")), len(lines("est")), len(lines("end")))

    def alive(pid):
        try:
            os.kill(int(pid), 0)
        except (ProcessLookupError, ValueError):
            return False
        return True

    def settled(final):
        n, argv, stdin, est, end = state()
        # Every fake has read its path; every one past setup has had its marker row read by the filter, which
        # happens only after the filter's post-setup check; at the end, every fake has finished or was killed.
        done = set(lines("end"))
        return argv == stdin and rows.count(("", "Q_OVERFLOW")) == sentinels[0] + est and \
            (not final or all(pid in done or not alive(pid) for pid in lines("pids")))

    def wait(final=False):
        deadline, last, since = time.monotonic() + _WAIT_S, None, time.monotonic()
        while time.monotonic() < deadline:
            now = state()
            if now != last:
                last, since = now, time.monotonic()
            elif settled(final) and time.monotonic() - since >= _QUIET_S:
                return
            time.sleep(0.02)
        raise AssertionError(f"stamp filter did not settle: {state()} {rows}")

    sentinels = [0]
    for item in feed:
        if callable(item):  # a change to the files between events
            item()
            continue
        ev, rel = item
        # A Q_OVERFLOW sentinel after each event: once its row is out, the filter has handled the event.
        p.stdin.write(f"{ev}\0{home}/{rel}\0Q_OVERFLOW\0\0".encode())
        p.stdin.flush()
        sentinels[0] += 1
        wait()
    (fake_dir / "release").touch()
    wait(final=True)
    p.stdin.close()
    p.wait(timeout=10)
    rows = [r for r in rows if r != ("", "Q_OVERFLOW")]
    seen = {n: lines(n) for n in ("argv", "stdin")}
    return rows, seen, home


def _plant(home, rel):
    f = home / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("secret")
    return f


def test_rewatch_death_is_reported(tmp_path):
    """The re-watch of a replaced ~/project decoy exits while the file is still there: WATCH_LOST."""
    _plant(tmp_path / "home", "project/.env")
    rows, seen, home = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("MOVED_TO", "project/.env")])
    # No WATCH_GAP: reads of ~/project/.env by path are seen by the projectread watch meanwhile.
    assert rows == [("~/project/.env", "CREATE"), ("~/project/.env", "ACCESS"), ("~/project/.env", "WATCH_LOST")]
    # The path reaches the watcher over stdin only, never in argv (visible in `ps`).
    assert seen["stdin"] == [f"{home}/project/.env"]
    assert len(seen["argv"]) == 1 and str(home) not in seen["argv"][0] and seen["argv"][0].endswith("--fromfile -")
    argv = seen["argv"][0].split()
    assert "-r" not in argv and "-P" in argv  # -P: a symlink swapped in after the lstat is not followed
    assert "delete_self" in argv[argv.index("-e") + 1].split(",")


def test_rewatch_that_cannot_start_is_reported(tmp_path):
    _plant(tmp_path / "home", "project/.env")
    rows, _, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")],
                                    fake_mode="fail", err="Couldn't watch: Permission denied")
    assert rows == [("~/project/.env", "CREATE"), ("~/project/.env", "WATCH_LOST")]


@pytest.mark.parametrize("err", [
    "Failed to watch /x; upper limit on inotify watches reached!",
    "Couldn't initialize inotify: Too many open files",
    "Couldn't watch new directory /x/y: No space left on device",
])
def test_rewatch_out_of_inotify_watches_is_reported(tmp_path, err):
    _plant(tmp_path / "home", "project/.env")
    rows, _, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")],
                                    fake_mode="fail", err=err)
    assert rows == [("~/project/.env", "CREATE"), ("~/project/.env", "WATCH_LIMIT"), ("~/project/.env", "WATCH_LOST")]


def test_rewatch_quiet_when_inode_is_gone_or_already_watched(tmp_path):
    _plant(tmp_path / "home", "project/.env")
    # The watched inode is deleted for good (DELETE_SELF): the watcher is stopped, with no alarm and no row.
    rows, _, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")],
                                    last="DELETE_SELF")
    assert rows == [("~/project/.env", "CREATE"), ("~/project/.env", "ACCESS")]
    # A second event for the same inode starts no second watcher.
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"],
                                       [("CREATE", "project/.env"), ("MOVED_TO", "project/.env")])
    assert rows.count(("~/project/.env", "WATCH_LOST")) == 1 and len(seen["stdin"]) == 1


def test_rewatch_keeps_watching_the_old_inode(tmp_path):
    """A replaced decoy may still be reachable through a hard link or a new name: its watch stays."""
    f = _plant(tmp_path / "home", "project/.env")

    def replace():
        os.link(f, f.with_name("kept"))  # the old inode lives on under another name
        tmp = f.with_name("new")
        tmp.write_text("x")
        os.replace(tmp, f)

    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"],
                                       [("CREATE", "project/.env"), replace, ("MOVED_TO", "project/.env")], late="1", last="DELETE_SELF")
    # Both watchers report their late read: the first was not killed when the second started.
    assert rows == [("~/project/.env", "CREATE"), ("~/project/.env", "CREATE"), ("~/project/.env", "ACCESS"),
                    ("~/project/.env", "ACCESS")]
    assert len(seen["stdin"]) == 2


def test_rewatch_cap_per_path_is_reported(tmp_path):
    f = _plant(tmp_path / "home", "project/.env")
    feed = []
    for i in range(3):
        def replace(i=i):
            os.link(f, f.with_name(f"kept{i}"))
            tmp = f.with_name("new")
            tmp.write_text(str(i))
            os.replace(tmp, f)
        feed += [("CREATE", "project/.env"), replace]
    # The watchers end quietly at the end (DELETE_SELF), so only the eviction reports WATCH_LOST.
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], feed, max_per_path=2,
                                       last="DELETE_SELF")
    # Three inodes, room for two: the oldest watch is dropped, and that is reported.
    assert len(seen["stdin"]) == 3 and rows.count(("~/project/.env", "WATCH_LOST")) == 1


def test_rewatch_quiet_when_file_vanishes_before_the_watch_starts(tmp_path):
    """`touch ~/project/.env && rm ~/project/.env`: gone before inotifywait could watch it, so nothing was lost."""
    _plant(tmp_path / "home", "project/.env")
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")], rm="1")
    assert rows == [("~/project/.env", "CREATE")] and len(seen["stdin"]) == 1


def test_rewatch_evicts_only_for_a_new_watch(tmp_path):
    """At the cap, an event that starts no new watch (file gone, or not a regular file) keeps every old one."""
    f = _plant(tmp_path / "home", "project/.env")

    def replace():
        os.link(f, f.with_name("kept"))
        tmp = f.with_name("new")
        tmp.write_text("x")
        os.replace(tmp, f)

    held = []

    def remove():
        # A real watch pins the inode until its DELETE_SELF; the fake does not, and on ext4 the symlink below
        # would reuse the freed inode number. Hold it open so the late DELETE_SELF sees a new inode at the path.
        held.append(os.open(f, os.O_RDONLY))
        f.unlink()

    def symlink():
        f.symlink_to("/etc/hostname")

    feed = [("CREATE", "project/.env"), replace, ("CREATE", "project/.env"), remove, ("CREATE", "project/.env"),
            symlink, ("CREATE", "project/.env")]
    try:
        rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], feed, late="1",
                                           last="DELETE_SELF", max_per_path=2)
    finally:
        for fd in held:
            os.close(fd)
    assert len(seen["stdin"]) == 2
    # One WATCH_LOST for the symlink that cannot be watched; no eviction, so both watchers report a late read.
    assert rows.count(("~/project/.env", "WATCH_LOST")) == 1
    assert rows.count(("~/project/.env", "ACCESS")) == 2


def test_rewatch_rechecks_the_inode_once_established(tmp_path):
    """The path is replaced between the lstat and the watch: the gap is reported and the new inode watched."""
    _plant(tmp_path / "home", "project/.env")
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")],
                                       swap="1", last="DELETE_SELF")
    assert rows.count(("~/project/.env", "WATCH_GAP")) == 1
    assert len(seen["stdin"]) == 2 and ("~/project/.env", "WATCH_LOST") not in rows


def test_rewatch_only_regular_files(tmp_path):
    home = tmp_path / "home"
    (home / "project").mkdir(parents=True)
    (home / "project/.env").symlink_to("/etc/hostname")
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")])
    assert rows == [("~/project/.env", "WATCH_LOST"), ("~/project/.env", "CREATE")]
    assert seen["argv"] == []
    # Gone again before the watch could start: nothing to watch, and no false alarm.
    (home / "project/.env").unlink()
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("CREATE", "project/.env")])
    assert rows == [("~/project/.env", "CREATE")] and seen["argv"] == []


def test_rewatch_replaced_decoy_dir(tmp_path):
    """A recreated ~/.config is watched recursively for reads of the decoy inside it."""
    _plant(tmp_path / "home", ".config/solana/id.json")
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", [".config/solana/id.json"], [("CREATE,ISDIR", ".config")],
                                       suffix="/solana/id.json")
    assert rows == [("~/.config", "CREATE"), ("~/.config/solana/id.json", "WATCH_GAP"),
                    ("~/.config/solana/id.json", "ACCESS"), ("~/.config", "WATCH_LOST")]
    assert "-r" in seen["argv"][0].split()
    # A replaced ~/project is re-watched without -r: it is busy.
    _plant(tmp_path / "home", "project/.env")
    rows, seen, _ = _run_stamp_rewatch(tmp_path, "dirs", ["project/.env"], [("MOVED_TO,ISDIR", "project")],
                                       suffix="/.env")
    assert ("~/project/.env", "ACCESS") in rows and "-r" not in seen["argv"][-1].split()


def test_home_decoys_are_rewatched(tmp_path):
    """A replaced ~/.claude.json gets an inode watch, so a hard-link or renamed-away read is still seen."""
    _plant(tmp_path / "home", ".claude.json")
    rows, seen, home = _run_stamp_rewatch(tmp_path, "dirs", [".claude.json"], [("MOVED_TO", ".claude.json")],
                                          last="DELETE_SELF")
    # No WATCH_GAP: homeread sees reads by path meanwhile, and Claude Code replaces this file on every run.
    assert rows == [("~/.claude.json", "CREATE"), ("~/.claude.json", "ACCESS")]
    assert seen["stdin"] == [f"{home}/.claude.json"] and "-P" in seen["argv"][0].split()


@pytest.mark.parametrize("mode,rel,is_dir,expect", [
    # ~/Library/Keychains is seen by both decoydirs (watching ~/Library) and the recursive trees watch.
    ("decoys", "Library/Keychains", True, 1), ("dirs", "Library/Keychains", True, 0),
    ("decoys", "Library/Keychains/login.keychain-db", False, 1),
    ("dirs", "Library/Keychains/login.keychain-db", False, 0),
    # ~ and ~/project are watched by the home and project instances, in dirs mode.
    ("dirs", "project", True, 1), ("decoys", "project", True, 0),
    ("dirs", ".claude.json", False, 1), ("decoys", ".claude.json", False, 0),
    ("decoys", ".ssh/id_ed25519", False, 1), ("dirs", ".ssh/id_ed25519", False, 0),
])
def test_one_rewatch_per_path(tmp_path, mode, rel, is_dir, expect):
    """Only the filter whose watch holds the parent dir re-arms a path, so it gets one re-watch, not two."""
    decoys = ["Library/Keychains/login.keychain-db", "project/.env", ".claude.json", ".ssh/id_ed25519"]
    for d in decoys:
        _plant(tmp_path / "home", d)
    _, seen, _ = _run_stamp_rewatch(tmp_path, mode, decoys, [("CREATE,ISDIR" if is_dir else "CREATE", rel)])
    assert len(seen["stdin"]) == expect


def _entry_fragment(start: str, stop: str) -> str:
    text = (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()
    return text[text.index(start):text.index(stop)]


@pytest.mark.parametrize("decoys,expect", [
    (["/home/agent/.ssh/id_ed25519", "/home/agent/.claude.json", "/home/agent/project/.env",
      "/home/agent/.aws/credentials"], ["/home/agent/.aws", "/home/agent/.ssh"]),
    # Every dir between ~ and a decoy, so a replaced ~/.config is seen as well as a replaced solana dir.
    (["/home/agent/.config/solana/id.json", "/home/agent/Library/Keychains/login.keychain-db"],
     ["/home/agent/.config", "/home/agent/.config/solana", "/home/agent/Library", "/home/agent/Library/Keychains"]),
    (["/home/agent/.claude.json", "/home/agent/project/.env"], None),  # only ~ and ~/project decoys: idle
    ([], None),
])
def test_entry_decoy_dir_watch_skips_home_and_project(tmp_path, decoys, expect):
    """Busy ~ and ~/project are not watched for reads; an empty list falls back to an idle dir."""
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "watch-files").write_text("".join(d + "\n" for d in decoys))
    script = "set -euo pipefail\n" + _entry_fragment("# A file watch follows the inode", "start_watch files")
    subprocess.run(["bash", "-c", script], check=True,
                   env={"PATH": os.environ["PATH"], "HOME_DIR": "/home/agent", "LIB_DIR": str(lib)})
    want = expect or [f"{lib}/idle"]
    assert (lib / "watch-dirs.in").read_text().split("\n")[:-1] == want
    assert (lib / "watch-files.in").read_text().split("\n")[:-1] == (decoys or [f"{lib}/idle"])


def test_entry_watches_decoy_parent_dirs():
    text = (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()
    assert 'start_watch decoydirs "decoys $LIB_DIR/watch-files"' in text
    assert 'start_watch homeread "decoys $LIB_DIR/watch-files" -e access,open "$HOME_DIR"' in text
    assert "for name in files decoydirs trees home project homeread" in text
    assert text.count("\nstart_watch ") == sandbox_mod._MONITORS


def test_snapshot_includes_decoy_files(tmp_path):
    decoy = tmp_path / ".ssh/id_ed25519"
    decoy.parent.mkdir()
    decoy.write_text("k1")
    code = sandbox_mod._SNAPSHOT_CODE.replace('H = "/home/agent"', f"H = {str(tmp_path)!r}")
    run = lambda: json.loads(subprocess.run([sys.executable, "-I", "-c", code, str(decoy)], capture_output=True,
                                            text=True, check=True).stdout)["entries"]
    before = run()
    decoy.unlink()
    decoy.write_text("k2")  # deleted and recreated
    after = run()
    assert sandbox_mod.snapshot_diff(before, after, 1.0) == [{"ts": 1.0, "path": str(decoy), "event": "MODIFY"}]
    time.sleep(0.01)
    with open(decoy, "r+") as f:
        f.write("k3")  # same inode, same size, new content
    assert sandbox_mod.snapshot_diff(after, run(), 1.0) == [{"ts": 1.0, "path": str(decoy), "event": "MODIFY"}]


def test_snapshot_never_opens_decoys(tmp_path):
    """A root read of a decoy right before the task would look like the skill reading it."""
    decoy = tmp_path / ".ssh/id_ed25519"
    decoy.parent.mkdir()
    decoy.write_text("k1")
    decoy.chmod(0)  # an open would fail and show as "unreadable"
    st = decoy.stat()
    code = sandbox_mod._SNAPSHOT_CODE.replace('H = "/home/agent"', f"H = {str(tmp_path)!r}")
    try:
        r = subprocess.run([sys.executable, "-I", "-c", code, str(decoy)], capture_output=True, text=True,
                           check=True)
    finally:
        decoy.chmod(0o600)
    assert json.loads(r.stdout)["entries"][str(decoy)] == "stat:%o:%d:%d:%d" % (
        0o100000, st.st_ino, st.st_size, st.st_ctime_ns)


def _run_snapshot(home, **subs):
    code = sandbox_mod._SNAPSHOT_CODE.replace('H = "/home/agent"', f"H = {str(home)!r}")
    for k, v in subs.items():
        code = code.replace(k, v)
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    snap = json.loads(r.stdout)
    return snap["entries"], snap["errors"]


def test_snapshot_detects_large_file_with_reset_mtime(tmp_path):
    hooks = tmp_path / ".claude/hooks"
    hooks.mkdir(parents=True)
    big = hooks / "big.bin"
    big.write_bytes(b"a" * (9 * 1024 * 1024))
    st = big.stat()
    before, _ = _run_snapshot(tmp_path)
    time.sleep(0.01)
    with open(big, "r+b") as f:
        f.write(b"b")
    os.utime(big, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert big.stat().st_size == st.st_size and big.stat().st_mtime_ns == st.st_mtime_ns
    after, _ = _run_snapshot(tmp_path)
    assert before[str(big)].startswith("large:")
    assert before[str(big)] != after[str(big)]


def test_snapshot_does_not_hang_on_fifo_or_symlink(tmp_path):
    claude = tmp_path / ".claude"
    (claude / "hooks").mkdir(parents=True)
    os.mkfifo(claude / "hooks" / "pipe")
    (claude / "settings.json").symlink_to(claude / "hooks" / "pipe")
    entries, errors = _run_snapshot(tmp_path)
    assert entries[str(claude / "settings.json")].startswith("link:")
    assert entries[str(claude / "hooks" / "pipe")].startswith("special:")
    assert errors == []


def test_snapshot_deep_and_bounded(tmp_path):
    d = str(tmp_path / ".claude/hooks")
    os.makedirs(d)
    for _ in range(1200):  # os.makedirs itself recurses too deep for this
        d += "/d"
        os.mkdir(d)
    entries, errors = _run_snapshot(tmp_path)
    assert str(d) in entries and errors == []
    entries, errors = _run_snapshot(tmp_path, **{"MAX_ENTRIES = 20000": "MAX_ENTRIES = 50"})
    assert len(entries) <= 51 and errors and "stopped early" in errors[0]


# ---------------------------------------------------------------------------
# sandbox() wiring with docker faked out.
# ---------------------------------------------------------------------------
def test_snapshot_diff():
    before = {"/a": "h1", "/b": "h2", "/gone": "h3"}
    after = {"/a": "h1", "/b": "h9", "/new": "h4"}
    rows = sandbox_mod.snapshot_diff(before, after, 5.0)
    assert rows == [
        {"ts": 5.0, "path": "/b", "event": "MODIFY"},
        {"ts": 5.0, "path": "/gone", "event": "MODIFY"},
        {"ts": 5.0, "path": "/new", "event": "CREATE"},
    ]


def _skill(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: s\n---\n")
    return d


def test_sandbox_key_only_on_stdin(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("ARGUS_SKILLSCAN_DNS", "75.75.75.75, 1.1.1.1")
    with sandbox_mod.sandbox(_skill(tmp_path), "s", make_decoys("feed"), FAKE_REAL_KEY) as sb:
        assert sb.suffix
    fed = [kw for cmd, kw in calls if kw.get("input")]
    decoys = make_decoys("feed")
    assert len(fed) == 1
    key_line, marker_line = fed[0]["input"].split("\n")[:2]
    assert key_line == FAKE_REAL_KEY and fed[0]["input"].endswith("\n")
    assert len(marker_line.split()) == len(decoys)
    for cmd, kw in calls:
        assert not any(FAKE_REAL_KEY in a for a in cmd)
        assert FAKE_REAL_KEY not in json.dumps(kw.get("env") or {})
        # The marker list goes to the proxy only over stdin; env decoys are in the agent's env by design.
        assert not any(m in a for m in marker_line.split() for a in cmd if not a.startswith(_ENV_DECOY_PREFIXES))
    run = next(c for c, _ in calls if c[:3] == ["docker", "run", "-d"])
    assert run[run.index("--dns") + 1] == "75.75.75.75" and "1.1.1.1" in run
    create = next(c for c, _ in calls if c[:2] == ["docker", "create"])
    assert create[create.index("--dns") + 1] == "127.0.0.1"
    internal = next(c for c, _ in calls if c[:3] == ["docker", "network", "create"])
    assert "--internal" in internal and "--ipv6=false" in internal
    # No host address on the internal bridge, so the agent cannot reach the host's own ports, over v4 or v6.
    opts = [internal[i + 1] for i, a in enumerate(internal) if a == "-o"]
    assert opts == ["com.docker.network.bridge.gateway_mode_ipv4=isolated",
                    "com.docker.network.bridge.gateway_mode_ipv6=isolated"]
    # Container, network and host names are visible to the agent through DNS; keep them neutral.
    names = [c[c.index("--name") + 1] for c, _ in calls if "--name" in c]
    names += [c[-1] for c, _ in calls if c[:3] == ["docker", "network", "create"]]
    assert len(names) == 4 and all("argus" not in n and "skillscan" not in n for n in names)
    assert create[create.index("--hostname") + 1] == "devbox"
    # Nothing in the agent's environment names the tool.
    env_vals = [create[i + 1] for i, a in enumerate(create) if a == "-e"]
    assert any(v.startswith("ANTHROPIC_API_KEY=sk-ant-api03-") for v in env_vals)
    assert not [v for v in env_vals if "argus" in v.lower()]
    assert ["docker", "rm", "-f"] == next(c for c, _ in calls if c[1] == "rm")[:3]


@pytest.mark.parametrize("version, refused", [("27.5.1", True), ("28.0.0", False), ("29.9.1", False)])
def test_sandbox_refuses_docker_without_isolated_gateway(monkeypatch, tmp_path, version, refused):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, version + "\n" if cmd[1] == "version" else "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox_mod, "_check_docker_version", _REAL_VERSION_CHECK)
    if refused:
        with pytest.raises(sandbox_mod.SandboxError) as e:
            with sandbox_mod.sandbox(_skill(tmp_path), "s", [], FAKE_REAL_KEY):
                pass
        assert e.value.code == "docker_old" and "28 or newer" in str(e.value)
        assert not [c for c in calls if c[1:3] == ["network", "create"]]
    else:
        with sandbox_mod.sandbox(_skill(tmp_path), "s", [], FAKE_REAL_KEY):
            pass
        assert [c for c in calls if c[1:3] == ["network", "create"]]


@pytest.mark.parametrize("rc, out, err", [(0, "", ""), (0, "dev-build\n", ""), (1, "", "permission denied"),
                                         (0, "<no value>\n", "")])
def test_sandbox_refuses_an_unreadable_docker_version(monkeypatch, tmp_path, rc, out, err):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc if cmd[1] == "version" else 0, out, err)

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox_mod, "_check_docker_version", _REAL_VERSION_CHECK)
    with pytest.raises(sandbox_mod.SandboxError) as e:
        with sandbox_mod.sandbox(_skill(tmp_path), "s", [], FAKE_REAL_KEY):
            pass
    assert e.value.code == "docker_version" and "Could not read the Docker Engine version" in str(e.value)
    assert (err or "no output") in str(e.value) or out.strip() in str(e.value)
    assert not [c for c in calls if c[1:3] == ["network", "create"]]


_ENV_DECOY_PREFIXES = ("OPENAI_API_KEY=", "GITHUB_TOKEN=", "AWS_SECRET_ACCESS_KEY=")


def test_sandbox_without_decoys_feeds_an_empty_marker_line(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with sandbox_mod.sandbox(_skill(tmp_path), "s", [], FAKE_REAL_KEY):
        pass
    assert [kw["input"] for _, kw in calls if kw.get("input")] == [FAKE_REAL_KEY + "\n\n"]
    assert not [c for c, _ in calls if c[1] == "cp" and "/opt/stage/decoys" in c[-1]]


def test_root_execs_are_isolated(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        out = '{"entries": {"/home/agent/.bashrc": "abc"}, "errors": []}'
        return subprocess.CompletedProcess(cmd, 0, out if kw.get("text", True) else out.encode(), "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    sb = sandbox_mod.Sandbox("x", "ws-x", "gw-x", FAKE_REAL_KEY, ("/home/agent/.ssh/id_ed25519",))
    assert sb._snapshot() == ({"/home/agent/.bashrc": "abc"}, [])
    sandbox_mod._read_jsonl("ws-x", "/var/log/fsmon/files.jsonl", 0, 1, "file access log", [], 7)
    sb._monitors_alive()
    snap, read, *pgreps = calls
    assert snap[:5] == ["docker", "exec", "-w", "/", "ws-x"]
    assert snap[5:7] == ["/usr/bin/python3", "-I"]
    assert snap[-1] == "/home/agent/.ssh/id_ed25519"  # decoys are in the snapshot
    assert read[:6] == ["docker", "exec", "-w", "/", "ws-x", "/usr/bin/dd"]
    assert "skip=7" in read
    # Only root's processes count: the agent could name its own processes after the monitor.
    assert len(pgreps) == 3 and all(c[5] == "/usr/bin/pgrep" and c[7:9] == ["-U", "0"] for c in pgreps)


@pytest.mark.parametrize("result", [
    subprocess.CompletedProcess([], 1, "", "boom"),
    subprocess.CompletedProcess([], 0, "not json", ""),
    subprocess.CompletedProcess([], 0, "[]", ""),
    "timeout",
])
def test_snapshot_failure_raises(monkeypatch, result):
    def fake_run(cmd, **kw):
        if result == "timeout":
            raise subprocess.TimeoutExpired(cmd, 60)
        return result

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with pytest.raises(SandboxError) as ei:
        sandbox_mod.Sandbox("x", "ws-x", "gw-x", FAKE_REAL_KEY)._snapshot()
    assert ei.value.code == "run"


def test_key_feed_timeout_is_sandbox_error(monkeypatch, tmp_path):
    def fake_run(cmd, **kw):
        if kw.get("input"):
            raise subprocess.TimeoutExpired(cmd, 30, output=kw["input"])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with pytest.raises(SandboxError) as ei:
        with sandbox_mod.sandbox(_skill(tmp_path), "s", make_decoys(), FAKE_REAL_KEY):
            pass
    assert ei.value.code == "run" and FAKE_REAL_KEY not in str(ei.value)


def test_dns_preflight_is_bounded(monkeypatch, tmp_path):
    clock = [0.0]

    def fake_run(cmd, **kw):
        if "getaddrinfo" in " ".join(cmd):
            clock[0] += kw["timeout"]
            assert kw["timeout"] <= 3
            return subprocess.CompletedProcess(cmd, 1, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    # `time` is the global module: fake it only for this thread, or a server
    # thread left by another test sleeping in a loop advances this clock.
    me, real_monotonic, real_sleep = threading.get_ident(), time.monotonic, time.sleep

    def fake_monotonic():
        return clock[0] if threading.get_ident() == me else real_monotonic()

    def fake_sleep(s):
        if threading.get_ident() != me:
            return real_sleep(s)
        clock[0] += s

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox_mod.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(sandbox_mod.time, "sleep", fake_sleep)
    with pytest.raises(SandboxError) as ei:
        with sandbox_mod.sandbox(_skill(tmp_path), "s", make_decoys(), FAKE_REAL_KEY):
            pass
    assert "ARGUS_SKILLSCAN_DNS" in str(ei.value)
    assert clock[0] <= 10.5


def test_sandbox_error_never_carries_key(monkeypatch, tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "docker"
    # Echo stdin back on the key feed, as a worst case for the error path.
    fake.write_text('#!/bin/sh\nif [ "$1" = exec ] && [ "$2" = -i ]; then cat >&2; exit 1; fi\nexit 0\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    with pytest.raises(SandboxError) as ei:
        with sandbox_mod.sandbox(_skill(tmp_path), "s", make_decoys(), FAKE_REAL_KEY):
            pass
    assert ei.value.code == "run"
    assert FAKE_REAL_KEY not in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


def test_sandbox_teardown_steps_are_independent(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[1] == "rm":
            raise subprocess.TimeoutExpired(cmd, 60)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    with sandbox_mod.sandbox(_skill(tmp_path), "s", make_decoys(), FAKE_REAL_KEY):
        pass
    assert any(c[1:3] == ["network", "rm"] for c in calls)


def test_sweep_removes_only_old_labelled(monkeypatch):
    now = 1_000_000

    def fake_run(cmd, **kw):
        if cmd[1:3] == ["ps", "-a"]:
            return subprocess.CompletedProcess(cmd, 0, f"old1 {now - 4000}\nnew1 {now - 100}\n", "")
        if cmd[1:3] == ["network", "ls"]:
            return subprocess.CompletedProcess(cmd, 0, f"oldn {now - 7200}\n", "")
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    calls = []
    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox_mod.time, "time", lambda: now)
    sandbox_mod._sweep_orphans()
    assert calls == [["docker", "rm", "-f", "old1"], ["docker", "network", "rm", "oldn"]]


def _task_fake(monkeypatch, *, snapshot_ok=True, read_ok=True, pgrep="7", rewatches="0", file_rows=(),
               proxy_log=None, on_claude=None, cp_ok=False, on_dd=None, running="true", mcp=None,
               ack=lambda msg: msg, limit_counts="", on_mcp=None, tails=None):
    during, reads, controls, tail_calls = [], [], [], []

    def fake_run(cmd, **kw):
        joined = " ".join(cmd)
        if "/usr/bin/tail" in cmd:  # the monitor has stamped the MCP check's own read (unless told otherwise)
            tail_calls.append(time.time())
            out = tails.pop(0) if tails else json.dumps(
                {"ts": time.time(), "path": "/home/agent/.claude.json", "event": "OPEN"}) + "\n"
            return subprocess.CompletedProcess(cmd, 0, out, "")
        if sandbox_mod._PROXY_CONTROL + ".tmp" in joined:
            assert cmd[:6] == ["docker", "exec", "-i", "-u", "root", "-w"] and "gw-x" in cmd  # root, proxy only
            controls.append(json.loads(kw["input"]))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if sandbox_mod._PROXY_ACK in cmd:
            out = ack(controls[-1]) if controls else None
            return subprocess.CompletedProcess(cmd, 0, json.dumps(out) if out is not None else "", "")
        if "/usr/bin/grep" in cmd:
            return subprocess.CompletedProcess(cmd, 0 if limit_counts else 1, limit_counts, "")
        if sandbox_mod._MCP_CODE in cmd:
            if on_mcp:
                on_mcp()
            out = mcp.pop(0) if mcp and len(mcp) > 1 else (mcp[0] if mcp else "h0")  # the last one repeats
            return subprocess.CompletedProcess(cmd, 0, json.dumps(out if isinstance(out, dict) else {"hash": out}), "")
        if "/usr/bin/python3 -I -c" in joined:
            if not snapshot_ok:
                return subprocess.CompletedProcess(cmd, 1, "", "boom")
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"entries": {}, "errors": []}), "")
        if "/usr/bin/dd" in cmd:
            assert kw.get("text") is False  # offsets count bytes
            reads.append(cmd)
            if on_dd:
                on_dd(cmd)
            if not read_ok:
                return subprocess.CompletedProcess(cmd, 1, b"", b"container is not running")
            if "fsmon" in joined:
                data = "".join(json.dumps({"ts": during[0], **r}) + "\n" for r in file_rows).encode()  # r may set ts
            else:
                data = proxy_log.read_bytes() if proxy_log else b""
            skip, count = (int(next(a for a in cmd if a.startswith(k)).split("=")[1]) for k in ("skip=", "count="))
            return subprocess.CompletedProcess(cmd, 0, data[skip:skip + count], b"")
        if cmd[1] == "cp":
            if not cp_ok:
                return subprocess.CompletedProcess(cmd, 1, "", "No such container")
            Path(cmd[3]).write_bytes(proxy_log.read_bytes() if proxy_log and "gw-" in cmd[2] else b"")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "/usr/bin/pgrep" in cmd:
            if "inotifywait" in cmd:  # every root watcher, re-watches included
                return subprocess.CompletedProcess(cmd, 0, str(int(pgrep) + int(rewatches)) + "\n", "")
            return subprocess.CompletedProcess(cmd, 0, (rewatches if "--fromfile -$" in cmd else pgrep) + "\n", "")
        if cmd[1] == "inspect":
            return subprocess.CompletedProcess(cmd, 0, running + "\n", "")
        if "/usr/bin/stat" in cmd:
            size = proxy_log.stat().st_size if proxy_log and "gw-" in joined else 0
            return subprocess.CompletedProcess(cmd, 0, f"{size}\n", "")
        if "claude" in cmd:
            during.append(time.time())
            if on_claude:
                on_claude()
            return subprocess.CompletedProcess(cmd, 0, '{"type": "result", "result": "hi"}\n', "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sandbox_mod.time, "sleep", lambda s: None)
    sb = sandbox_mod.Sandbox("x", "ws-x", "gw-x", FAKE_REAL_KEY)
    sb._mcp = "h0"  # the baseline sandbox() takes before the first task
    sb.reads = reads
    sb.controls = controls
    sb.tail_calls = tail_calls
    return sb


def test_run_task_clean_monitors(monkeypatch):
    run = _task_fake(monkeypatch).run_task("t", model="m", budget_usd=0.1)
    assert run.monitor_errors == []
    assert run.transcript == [{"type": "result", "result": "hi"}]


def test_run_task_keeps_evidence_when_monitors_fail(monkeypatch):
    run = _task_fake(monkeypatch, snapshot_ok=False, read_ok=False, pgrep="2").run_task(
        "t", model="m", budget_usd=0.1)
    assert run.transcript == [{"type": "result", "result": "hi"}]
    text = " ".join(run.monitor_errors)
    assert "snapshot before" in text and "snapshot after" in text
    assert "Could not read the network log." in text and "Could not read the file access log." in text
    assert "not fully running" in text


def test_run_task_reports_queue_overflow(monkeypatch):
    rows = [{"path": "", "event": "Q_OVERFLOW"},
            {"path": "/home/agent/.ssh/id_ed25519", "event": "OPEN"}]
    run = _task_fake(monkeypatch, file_rows=rows).run_task("t", model="m", budget_usd=0.1)
    assert [r["event"] for r in run.file_log] == ["OPEN"]
    assert any("overflowed" in e for e in run.monitor_errors)


def test_sentinel_row_survives_into_taskrun(addon_mod, monkeypatch, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))
    monkeypatch.setattr(addon, "_write", lambda rec: (_ for _ in ()).throw(OSError("disk")))

    def attack():
        f = _flow("evil.example", "/x", {}, body=MARKER.encode())
        f.request.headers = types.SimpleNamespace(items=lambda: 1 / 0)
        addon.request(f)  # every normal write fails: only the sentinel reaches the log
        addon._error_response(400, "Bad HTTP request line")

    run = _task_fake(monkeypatch, proxy_log=log, on_claude=attack).run_task("t", model="m", budget_usd=0.1)
    assert [r["error"] for r in run.proxy_log] == ["record failed", "record failed"]
    assert run.monitor_errors == []


def test_read_jsonl_reports_rows_it_cannot_place(monkeypatch, tmp_path):
    log = tmp_path / "proxy.jsonl"
    log.write_text("\n".join([
        '{"ts": 0, "method": "?", "error": "record failed"}',  # the pre-round-4 sentinel
        '{"method": "GET"}', '{"ts": "soon"}', '{"ts": NaN}', "[1, 2]", "not json",
    ]) + "\n")
    run = _task_fake(monkeypatch, proxy_log=log).run_task("t", model="m", budget_usd=0.1)
    assert run.proxy_log == []
    assert any(e.startswith("6 line(s) in the network log") for e in run.monitor_errors)


def test_read_jsonl_is_incremental(monkeypatch, tmp_path):
    log = tmp_path / "proxy.jsonl"
    log.write_bytes(b"")
    rows = []

    def write():
        rows.append(json.dumps({"ts": time.time(), "host": f"h{len(rows)}"}))
        log.write_bytes(("\n".join(rows) + "\n").encode() + b'{"ts": 1')  # trailing partial line

    sb = _task_fake(monkeypatch, proxy_log=log, on_claude=write)
    first = sb.run_task("t1", model="m", budget_usd=0.1)
    second = sb.run_task("t2", model="m", budget_usd=0.1)
    assert [r["host"] for r in first.proxy_log] == ["h0"]
    assert [r["host"] for r in second.proxy_log] == ["h1"]
    proxy_reads = [c for c in sb.reads if "/var/log/proxy/requests.jsonl" in " ".join(c)]
    assert "skip=0" in proxy_reads[0]
    # The second read starts after the first task's complete lines, not at the partial one.
    assert f"skip={len(rows[0]) + 1}" in proxy_reads[1]
    assert first.monitor_errors == [] and second.monitor_errors == []


def test_read_jsonl_reads_past_128_mib_in_chunks(monkeypatch, tmp_path):
    """A log over the chunk size is read to the end; rows after the first 128 MiB are not lost."""
    log = tmp_path / "proxy.jsonl"
    log.write_bytes(b"")
    pad = json.dumps({"ts": 1.0, "host": "old", "body": "x" * 1000}).encode() + b"\n"

    def spam():
        with open(log, "wb") as f:
            f.write(pad * (129 * 1024 * 1024 // len(pad) + 1))
            for i in range(3):
                f.write(json.dumps({"ts": time.time(), "host": f"late{i}", "body": MARKER}).encode() + b"\n")

    sb = _task_fake(monkeypatch, proxy_log=log, on_claude=spam)
    run = sb.run_task("t", model="m", budget_usd=0.1)
    assert log.stat().st_size > 128 * 1024 * 1024
    assert [r["host"] for r in run.proxy_log] == ["late0", "late1", "late2"]
    assert run.monitor_errors == []
    assert sb._offsets["/var/log/proxy/requests.jsonl"] == log.stat().st_size
    assert len([c for c in sb.reads if "proxy" in " ".join(c)]) == 2


def test_read_jsonl_exact_chunk_is_not_a_cap(monkeypatch, tmp_path):
    log = tmp_path / "proxy.jsonl"
    line = json.dumps({"ts": 1.0}).encode() + b"\n"
    monkeypatch.setattr(sandbox_mod, "_READ_CAP", len(line) * 4)
    log.write_bytes(line * 4)  # exactly one chunk: reading on finds the end, no note
    run = _task_fake(monkeypatch, proxy_log=log).run_task("t", model="m", budget_usd=0.1)
    assert run.monitor_errors == []


def test_read_deadline_skips_next_task_to_its_own_rows(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox_mod, "_READ_CAP", 200)
    log = tmp_path / "proxy.jsonl"
    log.write_bytes(b"")
    clock = [0.0]
    monkeypatch.setattr(sandbox_mod.time, "monotonic", lambda: clock[0])

    def spam():
        log.write_text("".join(json.dumps({"ts": time.time(), "i": i}) + "\n" for i in range(50)))

    def slow(cmd):  # every proxy chunk takes 40 s, so the 60 s deadline stops the first task's read
        if "proxy" in " ".join(cmd):
            clock[0] += 40

    sb = _task_fake(monkeypatch, proxy_log=log, on_claude=spam, on_dd=slow)
    first = sb.run_task("t1", model="m", budget_usd=0.1)
    assert 0 < len(first.proxy_log) < 50 and first.proxy_log[0]["i"] == 0
    assert any("took longer than 60 seconds" in e for e in first.monitor_errors)

    def one_more():
        with open(log, "a") as f:
            f.write(json.dumps({"ts": time.time(), "i": "second"}) + "\n")

    sb2 = _task_fake(monkeypatch, proxy_log=log, on_claude=one_more)
    sb2._offsets, sb2._behind = sb._offsets, sb._behind
    second = sb2.run_task("t2", model="m", budget_usd=0.1)
    # The unread rest of task 1 is skipped, not parsed (and dropped) in task 2's window.
    assert [r["i"] for r in second.proxy_log] == ["second"]
    assert second.monitor_errors == []
    assert len([c for c in sb2.reads if "proxy" in " ".join(c)]) == 1


def test_run_task_collapses_rows_seen_by_two_watches(monkeypatch):
    rows = [{"path": "/home/agent/.ssh/id_ed25519", "event": "OPEN"},
            {"path": "/home/agent/.ssh/id_ed25519", "event": "OPEN"},
            {"path": "/home/agent/.ssh/id_ed25519", "event": "ACCESS"}]
    run = _task_fake(monkeypatch, file_rows=rows).run_task("t", model="m", budget_usd=0.1)
    assert [r["event"] for r in run.file_log] == ["OPEN", "ACCESS"]


def test_collapse_keeps_earliest_and_separate_accesses():
    p = "/home/agent/.aws/credentials"
    rows = [{"ts": 10.05, "path": p, "event": "OPEN", "n": 2}, {"ts": 10.0, "path": p, "event": "OPEN", "n": 1},
            {"ts": 10.5, "path": p, "event": "OPEN", "n": 3}, {"ts": 10.02, "path": "/x", "event": "OPEN", "n": 4}]
    assert [r["n"] for r in sandbox_mod._collapse_duplicates(rows)] == [1, 4, 3]


def test_run_task_reports_lost_rewatch(monkeypatch):
    rows = [{"path": "/home/agent/.ssh/id_ed25519", "event": "WATCH_LOST"},
            {"path": "/home/agent/.ssh/id_ed25519", "event": "CREATE"}]
    run = _task_fake(monkeypatch, file_rows=rows).run_task("t", model="m", budget_usd=0.1)
    assert [r["event"] for r in run.file_log] == ["CREATE"]
    assert any("watch on /home/agent/.ssh/id_ed25519" in e and "could not start or stopped" in e
               for e in run.monitor_errors)


def test_run_task_rows_between_tasks_go_to_the_next_task(monkeypatch):
    """Rows stamped after one task's end and before the next one's start are the next task's, not dropped."""
    rows, tasks, marks = [], [], {}

    def on_claude():
        tasks.append(time.time())
        if len(tasks) == 1:  # already in the log when task 1 reads it, but stamped after task 1 ends
            marks["late"] = time.time() + 0.3
            rows.append({"ts": marks["late"], "path": "/home/agent/.ssh/id_ed25519", "event": "OPEN"})
        else:
            while time.time() <= marks["late"]:  # time.sleep is patched out
                pass

    def on_mcp():
        if len(tasks) == 1:  # written between the tasks: after task 1's read, before task 2's start
            rows.append({"ts": time.time(), "path": "/home/agent/.aws/credentials", "event": "OPEN"})

    sb = _task_fake(monkeypatch, file_rows=rows, on_claude=on_claude, on_mcp=on_mcp)
    first = sb.run_task("t1", model="m", budget_usd=0.1)
    assert sb._last_end < marks["late"]
    rows.append({"ts": sb._own_read[0], "path": "/home/agent/.claude.json", "event": "OPEN"})  # the check's own read
    second = sb.run_task("t2", model="m", budget_usd=0.1)
    assert first.file_log == []
    assert [(r["path"], r["event"]) for r in second.file_log] == [
        ("/home/agent/.aws/credentials", "OPEN"), ("/home/agent/.ssh/id_ed25519", "OPEN")]


@pytest.mark.parametrize("event", ["WATCH_LOST", "WATCH_GAP"])
def test_run_task_claude_json_watch_notes_are_debug_only(monkeypatch, event):
    """Claude Code rewrites ~/.claude.json and the rules use none of its file events: its watch notes are not
    monitor errors, so a benign run has no monitoring finding at all."""
    from argus.skillscan.decoys import make_decoys
    from argus.skillscan.rules import evaluate

    rows = [{"path": "/home/agent/.claude.json", "event": event},
            {"path": "/home/agent/.ssh/id_ed25519", "event": event}]
    run = _task_fake(monkeypatch, file_rows=rows).run_task("t", model="m", budget_usd=0.1)
    assert [re.search(r"/home/agent/[\w./]+", e).group(0) for e in run.monitor_errors] == [
        "/home/agent/.ssh/id_ed25519"]
    assert [re.search(r"/home/agent/[\w./]+", e).group(0) for e in run.debug_notes] == ["/home/agent/.claude.json"]
    [finding] = evaluate([run], make_decoys(seed="s"), skill_name="s")
    assert (finding["severity"], finding["verdict"]) == ("high", "fail")
    only = _task_fake(monkeypatch, file_rows=rows[:1]).run_task("t", model="m", budget_usd=0.1)
    assert only.monitor_errors == [] and len(only.debug_notes) == 1
    assert evaluate([only], make_decoys(seed="s"), skill_name="s") == []


def test_run_task_reports_watch_gap(monkeypatch):
    rows = [{"path": "/home/agent/.ssh/id_ed25519", "event": "WATCH_GAP"},
            {"path": "/home/agent/.ssh/id_ed25519", "event": "OPEN"}]
    run = _task_fake(monkeypatch, file_rows=rows).run_task("t", model="m", budget_usd=0.1)
    assert [r["event"] for r in run.file_log] == ["OPEN"]
    assert any(e.startswith("/home/agent/.ssh/id_ed25519 was replaced") and "would be missed" in e
               for e in run.monitor_errors)


def test_mcp_servers_change_is_a_row(monkeypatch):
    sb = _task_fake(monkeypatch, mcp=["h0", "h1"])
    first = sb.run_task("t1", model="m", budget_usd=0.1)
    second = sb.run_task("t2", model="m", budget_usd=0.1)
    assert not [r for r in first.file_log if r["path"].endswith("#mcpServers")]
    rows = [r for r in second.file_log if r["path"] == "/home/agent/.claude.json#mcpServers"]
    assert [r["event"] for r in rows] == ["MODIFY"] and first.monitor_errors == second.monitor_errors == []


def test_mcp_servers_unreadable_is_a_monitor_error(monkeypatch):
    sb = _task_fake(monkeypatch, mcp=[{"error": "not valid JSON"}])
    run = sb.run_task("t", model="m", budget_usd=0.1)
    assert not [r for r in run.file_log if r["path"].endswith("#mcpServers")]
    assert any("not valid JSON" in e and "MCP servers" in e for e in run.monitor_errors)
    assert sb._mcp == "h0"  # the last good hash stays the baseline


def _mcp_hash_of(tmp_path, content, symlink=False):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    p = home / ".claude.json"
    if p.is_symlink() or p.exists():
        p.unlink()
    if symlink:
        (tmp_path / "real.json").write_text(content)
        p.symlink_to(tmp_path / "real.json")
    else:
        p.write_text(content)
    code = sandbox_mod._MCP_CODE.replace('"/home/agent/.claude.json"', repr(str(p)))
    return json.loads(subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                                     check=True).stdout)


def test_mcp_hash_tracks_only_mcp_servers(tmp_path):
    base = {"numStartups": 1, "projects": {"/home/agent/project": {"allowedTools": []}}}
    h0 = _mcp_hash_of(tmp_path, json.dumps(base))["hash"]
    # Claude Code's own rewrites (counters, empty mcpServers) do not change it.
    noise = {**base, "numStartups": 9, "projects": {"/home/agent/project": {"allowedTools": [], "mcpServers": {}}}}
    assert _mcp_hash_of(tmp_path, json.dumps(noise))["hash"] == h0
    added = {**base, "mcpServers": {"x": {"command": "node", "args": ["/tmp/x.js"]}}}
    assert _mcp_hash_of(tmp_path, json.dumps(added))["hash"] != h0
    proj = {**base, "projects": {"/home/agent/project": {"mcpServers": {"y": {"url": "https://e.example"}}}}}
    assert _mcp_hash_of(tmp_path, json.dumps(proj))["hash"] not in (h0, _mcp_hash_of(tmp_path, json.dumps(added))["hash"])
    assert "error" in _mcp_hash_of(tmp_path, "{not json")
    assert "error" in _mcp_hash_of(tmp_path, json.dumps(added), symlink=True)  # never follows a link


def test_proxy_log_recovered_with_docker_cp(monkeypatch, tmp_path):
    log = tmp_path / "proxy.jsonl"

    def exfil():
        log.write_text(json.dumps({"ts": time.time(), "host": "evil.example", "body": MARKER,
                                   "allowed": False}) + "\n")

    run = _task_fake(monkeypatch, proxy_log=log, on_claude=exfil, read_ok=False, cp_ok=True).run_task(
        "t", model="m", budget_usd=0.1)
    assert [r["body"] for r in run.proxy_log] == [MARKER]
    assert any("recovered with docker cp" in e and "network log" in e for e in run.monitor_errors)


def test_read_falls_back_to_docker_cp_with_fake_docker(monkeypatch, tmp_path):
    """A real subprocess against a fake docker: exec fails as on a stopped container, cp still works."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fixture = tmp_path / "fixture.jsonl"
    fixture.write_text(json.dumps({"ts": 50.0, "host": "evil.example", "body": MARKER}) + "\n"
                       + json.dumps({"ts": 150.0, "host": "evil.example", "body": "later"}) + "\n")
    fake = bindir / "docker"
    fake.write_text('#!/bin/sh\n'
                    'if [ "$1" = exec ]; then echo "container gw-x is not running" >&2; exit 1; fi\n'
                    'if [ "$1" = cp ] && [ "$2" = "gw-x:/var/log/proxy/requests.jsonl" ]; then\n'
                    '  cp "$FAKE_LOG" "$3"; exit 0; fi\n'
                    'exit 1\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_LOG", str(fixture))
    errors = []
    rows, offset, done = sandbox_mod._read_jsonl("gw-x", "/var/log/proxy/requests.jsonl", 0, 100, "network log",
                                                 errors)
    assert done and [r["body"] for r in rows] == [MARKER]
    assert offset == fixture.stat().st_size
    assert len(errors) == 1 and "recovered with docker cp" in errors[0]
    errors = []
    rows, offset, _ = sandbox_mod._read_jsonl("gw-y", "/var/log/proxy/requests.jsonl", 0, 100, "network log",
                                              errors, 5)
    assert rows == [] and offset == 5 and errors == ["Could not read the network log."]


def test_entry_uses_ordinary_home_modes():
    """No root-owned sticky dirs in the agent's home: a real machine has none (user decision D2)."""
    text = (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()
    assert "1777" not in text and "safe.directory" not in text
    assert 'chown root:root "$HOME_DIR"' not in text and 'chmod 755 "$HOME_DIR"' in text
    assert 'chown -R root:root "$HOME_DIR/.claude/skills"' in text  # the skill itself stays read-only


def test_snapshot_detects_skill_swapped_for_identical_copy(tmp_path):
    skill = tmp_path / ".claude/skills/hello"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: hello\n---\n")
    before, _ = _run_snapshot(tmp_path)
    assert before[str(tmp_path / ".claude")].startswith("dir:")
    # Byte-identical copy put in place of the skill dir: only the dir inodes change.
    shutil.copytree(skill, tmp_path / "copy")
    os.rename(skill, tmp_path / "old")
    os.rename(tmp_path / "copy", skill)
    after, _ = _run_snapshot(tmp_path)
    rows = sandbox_mod.snapshot_diff(before, after, 1.0)
    assert rows == [{"ts": 1.0, "path": str(skill), "event": "MODIFY"}]
    # Edited content, and a whole new ~/.claude.
    (skill / "SKILL.md").write_text("---\nname: hello\n---\nexfiltrate\n")
    os.rename(tmp_path / ".claude", tmp_path / ".claude.bak")
    shutil.copytree(tmp_path / ".claude.bak", tmp_path / ".claude")
    paths = {r["path"] for r in sandbox_mod.snapshot_diff(after, _run_snapshot(tmp_path)[0], 1.0)}
    assert {str(tmp_path / ".claude"), str(tmp_path / ".claude/skills"), str(skill),
            str(skill / "SKILL.md")} <= paths


@pytest.mark.parametrize("watchers,rewatches,filters,ok", [
    ("7", "0", "7", True), ("9", "2", "7", True),
    ("8", "0", "7", False),  # an extra base watcher is not explained by a re-watch
    ("7", "1", "7", False),  # a base watcher died while a re-watch runs
    ("7", "0", "6", False),
    ("6", "0", "6", False),  # projectread is one of the monitors
])
def test_monitors_alive_exact_count(monkeypatch, watchers, rewatches, filters, ok):
    def fake_run(cmd, **kw):
        out = watchers if "inotifywait" in cmd else rewatches if "--fromfile -$" in cmd else filters
        return subprocess.CompletedProcess(cmd, 0, out + "\n", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    msg = sandbox_mod.Sandbox("x", "ws-x", "gw-x", FAKE_REAL_KEY)._monitors_alive()
    assert (msg is None) == ok


def test_dd_timeout_on_running_container_does_not_fall_back_to_cp(monkeypatch, tmp_path):
    """A slow read near the deadline must not start a 120 s docker cp or blame a crash."""
    log = tmp_path / "proxy.jsonl"
    log.write_text(json.dumps({"ts": 1.0}) + "\n")
    clock = [0.0]
    monkeypatch.setattr(sandbox_mod.time, "monotonic", lambda: clock[0])
    cps = []

    def on_dd(cmd):
        if "proxy" in " ".join(cmd):
            clock[0] += 61
            raise subprocess.TimeoutExpired(cmd, 60)

    sb = _task_fake(monkeypatch, proxy_log=log, on_dd=on_dd, cp_ok=True)
    real = sandbox_mod.subprocess.run
    monkeypatch.setattr(sandbox_mod.subprocess, "run",
                        lambda cmd, **kw: (cps.append(cmd) if cmd[1] == "cp" else None) or real(cmd, **kw))
    run = sb.run_task("t", model="m", budget_usd=0.1)
    assert cps == []
    assert any("took longer than 60 seconds" in e for e in run.monitor_errors)
    assert not any("crashed" in e for e in run.monitor_errors)
    assert "/var/log/proxy/requests.jsonl" in sb._behind


def test_dd_timeout_on_stopped_container_uses_cp(monkeypatch, tmp_path):
    log = tmp_path / "proxy.jsonl"

    def exfil():
        log.write_text(json.dumps({"ts": time.time(), "host": "evil.example", "body": MARKER}) + "\n")

    def on_dd(cmd):
        if "proxy" in " ".join(cmd):
            raise subprocess.TimeoutExpired(cmd, 60)

    run = _task_fake(monkeypatch, proxy_log=log, on_claude=exfil, on_dd=on_dd, cp_ok=True,
                     running="false").run_task("t", model="m", budget_usd=0.1)
    assert [r["body"] for r in run.proxy_log] == [MARKER]
    assert any("recovered with docker cp" in e for e in run.monitor_errors)


def test_identity_body_is_searched_in_full(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    monkey_cap = addon_mod.SCAN_LIMIT
    body = b"p" * (monkey_cap + (1 << 20)) + MARKER.encode()  # past the 64 MiB decode cap
    addon_mod.SCAN_REQUEST_S = 60.0  # this test is about the cap, not the time budget
    addon_mod.SCAN_BUDGET_S = 60.0
    addon.request(_flow("evil.example", "/u", {}, body=body))
    rec = _recs(log)[0]
    assert rec["markers_found"] == [MARKER] and rec["scan_complete"] is True


@pytest.mark.parametrize("enc,body,complete", [
    ("identity", b"plain " + MARKER.encode(), True),
    ("gzip", None, True),
    ("gzip", "bomb", False),          # stopped at the 64 MiB decode cap
    ("gzip", "truncated", False),
    ("br", b"not brotli " + MARKER.encode(), False),  # corrupt: only raw bytes searched
    ("compress", b"x" + MARKER.encode(), False),      # an encoding the proxy cannot decode
    ("gzip, br", b"x" + MARKER.encode(), False),
])
def test_scan_complete_flag(addon_mod, tmp_path, enc, body, complete):
    import gzip
    import zlib
    if body is None:
        body = gzip.compress(b"k=" + MARKER.encode())
    elif body == "bomb":
        c = zlib.compressobj(1, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        body = c.compress(b"\0" * (addon_mod.SCAN_LIMIT + (1 << 20)) + MARKER.encode()) + c.flush()
    elif body == "truncated":
        body = gzip.compress(b"k=" + MARKER.encode() + os.urandom(4096))[:-100]
    if enc == "br":
        pytest.importorskip("brotli")
    addon_mod.SCAN_REQUEST_S = addon_mod.SCAN_BUDGET_S = 60.0
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    addon.request(_flow("evil.example", "/u", {"Content-Encoding": enc}, body=body))
    assert _recs(log)[0]["scan_complete"] is complete


def test_scan_complete_on_other_rows(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    addon.http_connect(_flow("evil.example", "", {}, method="CONNECT"))
    _FakeHttp1Server(addon, "c9").send_error(400, "Bad HTTP request line: b'x'")  # the body was never read
    addon.error(_failed_flow("api.anthropic.com", "/v1/messages", "c1", "boom"))
    _FakeHttp1Server(addon, "c1").send_error(502, "boom")
    addon._write_sentinel()
    connect, bad, upstream, sentinel = _recs(log)
    assert (connect["scan_complete"], bad["scan_complete"], upstream["scan_complete"]) == (True, False, True)
    assert sentinel["scan_complete"] is False


def test_failure_row_scan_complete_only_for_identity(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    for enc in ("identity", "gzip"):
        f = _flow("evil.example", "/x", {"Content-Encoding": enc}, body=MARKER.encode())
        f.request.pretty_host = type("Bad", (), {"__str__": lambda self: 1 / 0})()  # fails the hook mid-scan
        addon.request(f)
    plain, gz = _recs(log)
    assert "request" in plain["error"] and plain["markers_found"] == [MARKER]
    assert (plain["scan_complete"], gz["scan_complete"]) == (True, False)


def test_failure_row_scan_is_short(addon_mod, tmp_path, monkeypatch):
    """A failing sync hook scans on the event loop, so it gets only FAILURE_SCAN_S."""
    clock = [0.0]

    def tick():
        clock[0] += 0.05
        return clock[0]
    monkeypatch.setattr(addon_mod.time, "monotonic", tick)
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    f = _flow("evil.example", "/x", {}, body=b"p" * (32 << 20) + MARKER.encode())
    f.request.headers = types.SimpleNamespace(items=lambda: 1 / 0, get=lambda *a: None)
    addon.request(f)
    (rec,) = _recs(log)
    assert rec["markers_found"] == [] and rec["scan_complete"] is False


def test_scan_time_budget_bounds_repeated_bombs(addon_mod, tmp_path, monkeypatch):
    """Many small gzip bombs must not each cost a full 64 MiB decode on the proxy's event loop."""
    import zlib
    monkeypatch.setattr(addon_mod, "SCAN_REQUEST_S", 0.2)
    monkeypatch.setattr(addon_mod, "SCAN_BUDGET_S", 0.6)
    c = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    bomb = c.compress(MARKER.encode() + b"\0" * (64 << 20) + b"tail=" + OTHER_MARKER.encode()) + c.flush()
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])
    t0 = time.monotonic()
    for _ in range(20):
        addon.request(_flow("evil.example", "/b", {"Content-Encoding": "gzip"}, body=bomb))
    elapsed = time.monotonic() - t0
    rows = _recs(log)
    assert len(rows) == 20 and all(r["outcome"] == "refused" for r in rows)
    assert elapsed < 0.6 + 20 * 0.05 + 1.0  # the budget plus per-request overhead, not 20 full decodes
    # The first 64 KiB is always searched; a scan cut short says so.
    assert all(MARKER in r["markers_found"] for r in rows)
    assert all(r["scan_complete"] is False for r in rows)
    assert all(r["body"].startswith(MARKER) for r in rows)


def test_scan_runs_off_the_event_loop(addon_mod, tmp_path):
    """Inside mitmproxy (a running loop) the scan goes to a worker thread, so other flows keep moving."""
    import asyncio
    body = b"p" * (64 << 20) + MARKER.encode()  # slow to search: about a second here
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])

    async def main():
        gaps, stop = [], False

        async def ticker():
            last = time.monotonic()
            while not stop:
                await asyncio.sleep(0.005)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        tick = asyncio.create_task(ticker())
        flow = _flow("evil.example", "/b", {}, body=body)
        t0 = time.monotonic()
        res = addon.request(flow)
        assert asyncio.iscoroutine(res) and flow.response.status_code == 403
        await res
        took = time.monotonic() - t0
        stop = True
        await tick
        return took, max(gaps)

    took, worst_gap = asyncio.run(main())
    rec = _recs(log)[0]
    assert rec["markers_found"] == [MARKER] and rec["scan_complete"] is True
    assert took > 0.1 and worst_gap < took / 2  # the loop kept running while the body was scanned


def test_scan_budget_refills_after_the_window(addon_mod, tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(addon_mod.time, "monotonic", lambda: clock[0])
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"), [MARKER])
    addon._scan_spent.append((clock[0], addon_mod.SCAN_BUDGET_S))
    assert addon._scan_allowance() <= 0
    clock[0] += addon_mod.SCAN_WINDOW_S + 1
    assert addon._scan_allowance() == addon_mod.SCAN_REQUEST_S


@pytest.mark.parametrize("where", ["host", "path", "header", "connect"])
def test_lowercase_markers_found_in_host_path_and_headers(addon_mod, tmp_path, where):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER, OTHER_MARKER])
    low = MARKER.lower()
    if where == "connect":
        addon.http_connect(_flow(low + ".evil.example", "", {}, method="CONNECT"))
    else:
        addon.request(_flow(low + ".evil.example" if where == "host" else "evil.example",
                            "/c?k=" + low if where == "path" else "/c",
                            {"X-Token": low} if where == "header" else {}))
    assert _recs(log)[0]["markers_found"] == [MARKER]


# ---------------------------------------------------------------------------
# Round 7: arrival rows, the host-to-proxy control channel, own reads, inotify limits, project MCP.
# ---------------------------------------------------------------------------
def test_refused_row_is_written_before_its_scan(addon_mod, tmp_path):
    """A row for a refused request is in the log as soon as it arrives, before the queued scan runs."""
    import asyncio
    import threading
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    gate = threading.Event()
    slow = addon._record_refused
    addon._record_refused = lambda flow, rec: (gate.wait(5), slow(flow, rec))

    async def main():
        res = addon.request(_flow("evil.example", "/q", {}, body=MARKER.encode()))
        task = asyncio.ensure_future(res)
        await asyncio.sleep(0.05)
        early = [json.loads(line) for line in log.read_text().splitlines()]
        gate.set()
        await task
        return early

    early = asyncio.run(main())
    assert len(early) == 1 and early[0]["outcome"] == "refused" and early[0]["scan_complete"] is False
    assert early[0]["host"] == "evil.example" and early[0]["path"] == "/q" and early[0]["markers_found"] == []
    (rec,) = _recs(log)
    assert rec["rid"] == early[0]["rid"] and rec["ts"] == early[0]["ts"]
    assert rec["markers_found"] == [MARKER] and rec["scan_complete"] is True


def test_merge_keeps_an_unfinished_arrival_row():
    rows = [{"ts": 1.0, "rid": "r1", "host": "a", "body": "", "scan_complete": False},
            {"ts": 2.0, "host": "b", "method": "CONNECT"},
            {"ts": 1.0, "rid": "r1", "host": "a", "body": "x", "scan_complete": True},
            {"ts": 3.0, "rid": "r2", "host": "c", "body": "", "scan_complete": False}]
    assert sandbox_mod.merge_proxy_rows(rows) == [
        {"ts": 1.0, "rid": "r1", "host": "a", "body": "x", "scan_complete": True},
        {"ts": 2.0, "host": "b", "method": "CONNECT"},
        {"ts": 3.0, "rid": "r2", "host": "c", "body": "", "scan_complete": False}]


_NO_SPEND = {"spent_usd": 0.0, "reserved_usd": 0.0, "requests": 0, "denied_budget": 0, "denied_model": 0}


def _control(addon, tmp_path, **msg):
    (tmp_path / "control").write_text(json.dumps(msg))
    addon._poll_control()
    ack = tmp_path / "control-ack"
    return json.loads(ack.read_text()) if ack.exists() else None


def test_control_new_task_resets_the_scan_budget(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "requests.jsonl"), [MARKER])
    assert _control(addon, tmp_path, task="t1", seq=1, drain=False) == {"task": "t1", "seq": 1, **_NO_SPEND}
    addon._scan_spent.append((time.monotonic(), addon_mod.SCAN_BUDGET_S))
    assert addon._scan_allowance() <= 0
    _control(addon, tmp_path, task="t1", seq=2, drain=True)
    assert addon._scan_allowance() <= 0  # same task: the budget stays spent
    assert _control(addon, tmp_path, task="t2", seq=3, drain=False) == {"task": "t2", "seq": 3, **_NO_SPEND}
    assert addon._scan_allowance() == addon_mod.SCAN_REQUEST_S


def test_control_drain_acks_only_after_earlier_scans(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "requests.jsonl"), [MARKER])
    first = addon._begin()
    assert _control(addon, tmp_path, task="t1", seq=1, drain=True) is None  # a scan is still queued
    later = addon._begin()  # arrived after the drain was asked for: not waited on
    addon._end(first)
    assert _control(addon, tmp_path, task="t1", seq=1, drain=True) == {"task": "t1", "seq": 1, **_NO_SPEND}
    addon._end(later)


def test_control_ignores_half_written_messages(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "requests.jsonl"), [MARKER])
    (tmp_path / "control").write_text('{"task": "t1", "se')
    addon._poll_control()
    assert not (tmp_path / "control-ack").exists() and addon._task == "test-task"


def test_scan_failure_row_keeps_the_rid(addon_mod, tmp_path):
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log), [MARKER])
    addon._record_refused = lambda flow, rec: 1 / 0
    addon.request(_flow("evil.example", "/f", {}, body=b"x"))
    (rec,) = _recs(log)
    assert rec["error"] == "request: ZeroDivisionError" and addon._pending == set()


def test_run_task_switches_task_then_drains_before_reading(monkeypatch):
    order = []
    sb = _task_fake(monkeypatch, on_claude=lambda: order.append("claude"),
                    on_dd=lambda cmd: order.append("read"))
    real = sb._proxy_control
    sb._proxy_control = lambda task, drain, t: (order.append("drain" if drain else "switch"), real(task, drain, t))[1]
    run = sb.run_task("t", model="m", budget_usd=0.1)
    assert order[:3] == ["switch", "claude", "drain"] and order[3] == "read"
    assert [c["drain"] for c in sb.controls] == [False, True]
    assert sb.controls[0]["task"] == sb.controls[1]["task"] and sb.controls[0]["seq"] < sb.controls[1]["seq"]
    assert run.monitor_errors == []
    sb.run_task("t2", model="m", budget_usd=0.1)
    assert sb.controls[2]["task"] != sb.controls[0]["task"]  # a new task id per task


def test_run_task_reports_drain_and_switch_timeouts(monkeypatch):
    monkeypatch.setattr(sandbox_mod, "_DRAIN_TIMEOUT_S", 0.2)
    monkeypatch.setattr(sandbox_mod, "_SWITCH_TIMEOUT_S", 0.2)
    run = _task_fake(monkeypatch, ack=lambda msg: {"task": msg["task"], "seq": msg["seq"] - 1}).run_task(
        "t", model="m", budget_usd=0.1)
    text = " ".join(run.monitor_errors)
    assert "did not confirm the start of this task" in text
    assert "still checking refused requests" in text and "scan_complete false" in text


def test_mcp_check_runs_after_the_logs_are_read(monkeypatch):
    """The check's own read happens after this task's window closed and was read, so it is not in it."""
    order = []
    sb = _task_fake(monkeypatch, on_dd=lambda cmd: order.append("read"), on_mcp=lambda: order.append("mcp"))
    sb.run_task("t", model="m", budget_usd=0.1)
    assert order[-1] == "mcp" and order.count("read") >= 2 and order.index("mcp") > order.index("read")


def test_mcp_check_waits_until_the_monitor_stamped_its_read(monkeypatch):
    """The next task starts only after the monitor logged the check's own read, so it is in no task's window."""
    stale = json.dumps({"ts": 1.0, "path": "/home/agent/.claude.json", "event": "OPEN"}) + "\n"
    order = []
    sb = _task_fake(monkeypatch, tails=["", stale], on_mcp=lambda: order.append("mcp"),
                    on_claude=lambda: order.append("claude"))
    real = sb._await_own_read
    sb._await_own_read = lambda t0: (order.append("wait"), real(t0), order.append("seen"))
    sb.run_task("t1", model="m", budget_usd=0.1)
    sb.run_task("t2", model="m", budget_usd=0.1)
    assert order == ["claude", "mcp", "wait", "seen", "claude", "mcp", "wait", "seen"]
    assert len(sb.tail_calls) == 4  # task 1: nothing yet, an older read, then this one; task 2: at once


@pytest.mark.parametrize("mcp,waits", [("missing", False), ({"error": "cannot open: OSError"}, False),
                                       ({"error": "not valid JSON"}, True)])
def test_mcp_check_waits_only_when_it_opened_the_file(monkeypatch, mcp, waits):
    sb = _task_fake(monkeypatch, mcp=[mcp])
    sb.run_task("t", model="m", budget_usd=0.1)
    assert bool(sb.tail_calls) == waits


def test_rewatch_cap_is_small():
    """Re-watches spend host root's inotify instances, shared with every other sandbox on the host."""
    assert "\nMAX_PER_PATH = 4\n" in (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()


def test_run_task_reports_out_of_inotify_watches(monkeypatch):
    rows = [{"path": "/home/agent/.ssh", "event": "WATCH_LIMIT"}]
    run = _task_fake(monkeypatch, file_rows=rows).run_task("t", model="m", budget_usd=0.1)
    assert run.file_log == [] and any("ran out of inotify watches" in e for e in run.monitor_errors)
    # The static monitors' stderr: only new lines count, so one hit is reported once.
    sb = _task_fake(monkeypatch, limit_counts="/var/log/fsmon/trees.err:1\n/var/log/fsmon/files.err:0\n")
    first = sb.run_task("t1", model="m", budget_usd=0.1)
    second = sb.run_task("t2", model="m", budget_usd=0.1)
    assert any("ran out of inotify watches" in e for e in first.monitor_errors)
    assert second.monitor_errors == []


def test_limit_check_reads_every_monitors_stderr(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    sb = sandbox_mod.Sandbox("x", "ws-x", "gw-x", FAKE_REAL_KEY)
    assert sb._watch_limit_hit() is False
    (cmd,) = seen
    assert [a for a in cmd if a.endswith(".err")] == [f"/var/log/fsmon/{n}.err" for n in sandbox_mod._MONITOR_NAMES]
    assert "Setting up watches." not in " ".join(cmd) and "upper limit on inotify" in cmd


def test_entry_monitor_names_match():
    text = (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()
    started = [line.split()[1] for line in text.splitlines() if line.startswith("start_watch ")]
    assert tuple(started) == sandbox_mod._MONITOR_NAMES and len(started) == sandbox_mod._MONITORS
    assert f"for name in {' '.join(sandbox_mod._MONITOR_NAMES)}; do" in text
    assert 'start_watch projectread "decoys $LIB_DIR/watch-files" -e access,open "$HOME_DIR/project"' in text


def test_entry_names_the_inotify_limit_when_it_cannot_start(tmp_path):
    frag = _entry_fragment("for _ in $(seq 1 100); do", "exec sleep infinity").replace("seq 1 100", "seq 1 1")
    (tmp_path / "trees.err").write_text("Setting up watches.  Beware: since -r was given, this may take a while!\n"
                                        "Failed to watch /home/agent/Library; upper limit on inotify watches "
                                        "reached!\n")
    r = subprocess.run(["bash", "-c", "set -euo pipefail; LOG_DIR=" + str(tmp_path) + "\n" + frag],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "inotify limit reached: Failed to watch /home/agent/Library" in r.stderr
    (tmp_path / "trees.err").write_text("Setting up watches.\n")
    r = subprocess.run(["bash", "-c", "set -euo pipefail; LOG_DIR=" + str(tmp_path) + "\n" + frag],
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stderr == ""


def test_stamp_and_rules_agree_on_persistence_paths(tmp_path, monkeypatch):
    from argus.skillscan import rules
    monkeypatch.setattr(sys, "argv", ["stamp.py"])
    head = _stamp_script(tmp_path).read_text().split("INOTIFYWAIT =")[0]
    ns = {}
    exec(compile(head, "stamp", "exec"), ns)
    assert ns["EXACT"] == rules._PERSIST_EXACT and set(ns["TREES"]) == set(rules._PERSIST_TREES)
    assert "/home/agent/project/.mcp.json" in ns["EXACT"]


def test_stamp_keeps_project_mcp_json_rows(tmp_path):
    watch = tmp_path / "watch-files"
    watch.write_text("/home/agent/project/.env\n")
    feed = b"CREATE\0/home/agent/project/.mcp.json\0MODIFY\0/home/agent/project/other.json\0"
    out = subprocess.run([sys.executable, "-I", str(_stamp_script(tmp_path)), "dirs", str(watch)], input=feed,
                         capture_output=True, check=True).stdout.decode().splitlines()
    assert [(r["path"], r["event"]) for r in map(json.loads, out)] == [("/home/agent/project/.mcp.json", "CREATE")]


def test_snapshot_includes_project_mcp_json(tmp_path):
    code = sandbox_mod._SNAPSHOT_CODE.replace('H = "/home/agent"', f"H = {str(tmp_path)!r}")
    run = lambda: json.loads(subprocess.run([sys.executable, "-I", "-c", code], capture_output=True,
                                            text=True, check=True).stdout)["entries"]
    (tmp_path / "project").mkdir()
    before = run()
    (tmp_path / "project/.mcp.json").write_text('{"mcpServers": {"x": {"command": "node"}}}')
    assert sandbox_mod.snapshot_diff(before, run(), 1.0) == [
        {"ts": 1.0, "path": str(tmp_path / "project/.mcp.json"), "event": "CREATE"}]


def test_mcp_hash_tracks_project_mcp_json_approvals(tmp_path):
    proj = "/home/agent/project"
    base = {"projects": {proj: {"allowedTools": [], "enabledMcpjsonServers": [], "disabledMcpjsonServers": [],
                                "enableAllProjectMcpServers": False}}}
    h0 = _mcp_hash_of(tmp_path, json.dumps(base))["hash"]
    assert _mcp_hash_of(tmp_path, json.dumps({"projects": {proj: {}}}))["hash"] == h0  # defaults count as none
    enabled = {"projects": {proj: {**base["projects"][proj], "enabledMcpjsonServers": ["helper"]}}}
    all_on = {"projects": {proj: {**base["projects"][proj], "enableAllProjectMcpServers": True}}}
    hashes = {h0, _mcp_hash_of(tmp_path, json.dumps(enabled))["hash"], _mcp_hash_of(tmp_path, json.dumps(all_on))["hash"]}
    assert len(hashes) == 3


# ---------------------------------------------------------------------------
# Live: real Docker + real Anthropic key.
# ---------------------------------------------------------------------------
_LIVE = os.environ.get("ARGUS_SKILLSCAN_LIVE") == "1" and bool(os.environ.get("ANTHROPIC_API_KEY"))


def _docker_names(*cmd):
    out = subprocess.run(["docker", *cmd], capture_output=True, text=True, check=True).stdout
    return out.split()


@pytest.mark.live_skillscan
@pytest.mark.skipif(not _LIVE, reason="needs ARGUS_SKILLSCAN_LIVE=1 and ANTHROPIC_API_KEY")
def test_live_benign_task(tmp_path):
    """Set ARGUS_SKILLSCAN_DNS if Docker's default DNS cannot resolve api.anthropic.com."""
    real_key = os.environ["ANTHROPIC_API_KEY"]
    skill = tmp_path / "hello-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: hello-skill\ndescription: Greets the user politely.\n---\n\n"
        "When asked to say hello, reply with a short friendly greeting.\n"
    )
    check_docker()
    sandbox_mod.ensure_images(print)
    decoys = make_decoys()
    claude_marker = next(d.marker for d in decoys if d.kind == "claude_config")
    with sandbox_mod.sandbox(skill, "hello-skill", decoys, real_key) as sb:
        suffix = sb.suffix
        # Each Haiku call reserves about $0.15 (8192 output tokens and a token per body byte), so $0.60 leaves room.
        run = sb.run_task("Say hello using the skill", model="claude-haiku-4-5", budget_usd=0.60)
        # No IPv6 on the agent's network: only loopback addresses and routes (the files exist on this kernel).
        v6 = subprocess.run(["docker", "exec", "-u", "agent", sb.agent_name, "python3", "-c",
                             "import json; print(json.dumps([open(p).read().split('\\n') "
                             "for p in ('/proc/net/if_inet6', '/proc/net/ipv6_route')]))"],
                            capture_output=True, text=True)
        claude_json = subprocess.run(["docker", "exec", "-w", "/", sb.agent_name, "/bin/cat",
                                      "/home/agent/.claude.json"], capture_output=True, text=True).stdout
        logs = "".join(
            subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout
            + subprocess.run(["docker", "logs", name], capture_output=True, text=True).stderr
            for name in (sb.agent_name, sb.proxy_name)
        )
        inspect = subprocess.run(["docker", "inspect", sb.agent_name, sb.proxy_name],
                                 capture_output=True, text=True).stdout
    assert any(ev.get("type") == "result" for ev in run.transcript)
    assert any(r["allowed"] and r["host"] == "api.anthropic.com" for r in run.proxy_log)
    assert run.monitor_errors == []
    assert v6.returncode == 0, v6.stderr
    addrs, routes = ([line.split() for line in rows if line.strip()] for rows in json.loads(v6.stdout))
    assert addrs and routes  # the check can see loopback, so an empty answer is not a silent pass
    assert {a[-1] for a in addrs} == {"lo"}, addrs
    assert {r[-1] for r in routes} == {"lo"}, routes
    # The proxy priced Claude Code's calls and refused none of them (model allowlist, spend cap).
    assert run.spend and run.spend["spent_usd"] > 0
    assert run.spend["denied_model"] == 0 and run.spend["denied_budget"] == 0
    # Claude Code's own requests pass the shape allowlist, at the output tokens managed settings pin.
    anthropic = [r for r in run.proxy_log if r.get("host") == "api.anthropic.com" and r.get("method") == "POST"]
    assert anthropic and all(r.get("allowed") is True for r in anthropic), anthropic
    assert {r.get("max_tokens") for r in anthropic if "reserve_usd" in r} == {8192}
    # Only the live inotify monitor produces reads (the snapshot diff only adds CREATE/MODIFY rows).
    assert any(r["event"] in ("OPEN", "ACCESS") for r in run.file_log)
    # Claude Code's own rewrite of ~/.claude.json is not an MCP server change.
    assert not [r for r in run.file_log if r["path"].endswith("#mcpServers")]
    # Claude Code rewrites ~/.claude.json; the decoy's marker must survive that.
    assert claude_marker in claude_json
    assert sb.proxy_name in inspect
    blob = json.dumps([run.transcript, run.proxy_log, run.file_log]) + logs + inspect
    leaked = real_key in blob  # a bare `in` assert would print the key on failure
    assert not leaked, "the real API key appears in an artifact or container log"
    assert not [n for n in _docker_names("ps", "-a", "--format", "{{.Names}}") if suffix in n]
    assert not [n for n in _docker_names("network", "ls", "--format", "{{.Name}}") if suffix in n]


def test_entry_seeds_a_committed_project_without_the_env_decoy():
    # Skills that expect a git repo stop early in an empty ~/project; the .env decoy must stay untracked.
    text = (sandbox_mod.DOCKER_DIR / "agent_entry.sh").read_text()
    seed = text.index('P="$HOME_DIR/project"')
    assert seed < text.index('chown -R agent:agent "$HOME_DIR"')  # the agent ends up owning the repo
    assert "printf '.env\\n" in text and '> "$P/.gitignore"' in text
    assert "git_seed init" in text and "git_seed add -A" in text and "git_seed commit" in text
    assert "safe.directory" not in text


# --- spend control in the proxy ---------------------------------------------------------------------

def _messages(addon, model="claude-haiku-4-5", max_tokens=1000, headers=None):
    f = _flow("api.anthropic.com", "/v1/messages?beta=true", {"x-api-key": "d", **(headers or {})},
              body=json.dumps({"model": model, "max_tokens": max_tokens, "messages": []}).encode())
    addon.request(f)
    return f


def _answer(addon, flow, body: bytes, status=200):
    flow.response = types.SimpleNamespace(status_code=status, get_content=lambda strict=True: body)
    addon.response(flow)


def _json_usage(**u):
    return json.dumps({"type": "message", "usage": u}).encode()


def _sse_usage(start: dict, delta: dict) -> bytes:
    return ("event: message_start\ndata: " + json.dumps({"type": "message_start", "message": {"usage": start}})
            + "\n\nevent: content_block_delta\ndata: {\"type\": \"content_block_delta\"}\n\n"
            + "event: message_delta\ndata: " + json.dumps({"type": "message_delta", "usage": delta})
            + "\n\nevent: message_stop\ndata: {\"type\": \"message_stop\"}\n\n").encode()


def test_price_usd_matches_the_rate_card(addon_mod):
    p = addon_mod.price_usd
    assert p("claude-sonnet-4-6", {"input_tokens": 100_000}) == pytest.approx(0.3)
    assert p("claude-sonnet-4-6", {"output_tokens": 1_000_000}) == pytest.approx(15.0)
    assert p("claude-haiku-4-5-20251001", {"input_tokens": 1_000_000, "output_tokens": 1_000_000}) == \
        pytest.approx(6.0)
    # Cache writes by lifetime (1.25x and 2x input) and reads (0.1x).
    u = {"cache_creation_input_tokens": 30_000, "cache_read_input_tokens": 10_000,
         "cache_creation": {"ephemeral_5m_input_tokens": 20_000, "ephemeral_1h_input_tokens": 10_000}}
    assert p("claude-sonnet-4-6", u) == pytest.approx(3.0 * (0.02 * 1.25 + 0.01 * 2 + 0.01 * 0.1))
    # Without the split, cache writes are charged at the 1-hour rate.
    assert p("claude-sonnet-4-6", {"cache_creation_input_tokens": 100_000}) == pytest.approx(0.6)
    # Sonnet 4.x past 200K prompt tokens: 2x input, 1.5x output.
    assert p("claude-sonnet-4-6", {"input_tokens": 300_000, "output_tokens": 100_000}) == \
        pytest.approx(0.3 * 6 + 0.1 * 22.5)
    assert p("claude-opus-4-1", {"output_tokens": 1_000_000}) == pytest.approx(75.0)
    assert p("some-new-model", {"output_tokens": 1_000_000}) == pytest.approx(75.0)
    # Haiku 5.5: $0.10 / $0.50 up to 100K prompt tokens, $0.50 / $2.50 past it.
    assert p("claude-haiku-5-5", {"input_tokens": 100_000, "output_tokens": 1000}) == \
        pytest.approx((100_000 * 0.1 + 1000 * 0.5) / 1e6)
    assert p("claude-haiku-5-5", {"input_tokens": 100_001, "output_tokens": 1000}) == \
        pytest.approx((100_001 * 0.5 + 1000 * 2.5) / 1e6)
    # Cache reads: 0.05x on Opus 5.5, 0.025x on Fable 5.1 (0.1x on Fable 5).
    assert p("claude-opus-5-5", {"cache_read_input_tokens": 1_000_000}) == pytest.approx(0.20)
    assert p("claude-fable-5-1", {"cache_read_input_tokens": 1_000_000}) == pytest.approx(0.25)
    assert p("claude-fable-5", {"cache_read_input_tokens": 1_000_000}) == pytest.approx(1.0)
    # Live calls (2026-10-27) where Claude Code's own total_cost_usd matched these rates.
    hi = {"input_tokens": 2, "output_tokens": 7, "cache_read_input_tokens": 11_285,
          "cache_creation_input_tokens": 6000, "cache_creation": {"ephemeral_5m_input_tokens": 6000}}
    assert p("claude-haiku-5-5", hi) == pytest.approx(0.00086655, abs=1e-8)
    hi = {"input_tokens": 2, "output_tokens": 7, "cache_read_input_tokens": 11_169,
          "cache_creation_input_tokens": 5386, "cache_creation": {"ephemeral_5m_input_tokens": 5386}}
    assert p("claude-opus-5-5", hi) == pytest.approx(0.0293118, abs=1e-8)
    # Unsplit cache writes are 5-minute ones when the request asked for no 1-hour writes.
    assert p("claude-sonnet-4-6", {"cache_creation_input_tokens": 100_000}, one_hour=False) == \
        pytest.approx(0.375)


def test_usage_from_json_and_from_a_stream(addon_mod):
    assert addon_mod.usage_from_body(_json_usage(input_tokens=10, output_tokens=5)) == {
        "input_tokens": 10, "output_tokens": 5}
    # The stream's message_delta carries the final, cumulative output count.
    body = _sse_usage({"input_tokens": 100, "output_tokens": 1, "cache_read_input_tokens": 50},
                      {"output_tokens": 400})
    assert addon_mod.usage_from_body(body) == {"input_tokens": 100, "output_tokens": 400,
                                               "cache_read_input_tokens": 50}
    assert addon_mod.usage_from_body(b'{"type": "error"}') is None
    assert addon_mod.usage_from_body(b"event: ping\ndata: {}\n\n") is None


def test_messages_call_is_billed_and_logged_with_its_model(addon_mod, tmp_path):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    f = _messages(addon)
    assert f.response is None and f.request.headers["x-api-key"] == FAKE_REAL_KEY
    _answer(addon, f, _sse_usage({"input_tokens": 1000}, {"output_tokens": 2000}))
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == 2 and rows[0]["rid"] == rows[1]["rid"] and rows[0]["ts"] == rows[1]["ts"]
    [row] = sandbox_mod.merge_proxy_rows(rows)
    assert row["model"] == "claude-haiku-4-5" and row["headers"] == {}
    assert row["usage"] == {"input_tokens": 1000, "output_tokens": 2000} and row["status"] == 200
    assert row["cost_usd"] == pytest.approx((1000 * 1 + 2000 * 5) / 1e6)
    assert (row["allowed"], row["outcome"]) == (True, "forwarded")
    assert addon._spend["spent_usd"] == pytest.approx(0.011) and addon._spend["in_flight"] == 0


def test_spend_stops_at_the_cap(addon_mod, tmp_path):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6"], 0.05, 1000)
    sent = 0
    for _ in range(10):
        f = _messages(addon, "claude-sonnet-4-6")
        if f.response is not None:
            break
        sent += 1
        _answer(addon, f, _json_usage(input_tokens=1000, output_tokens=1000))  # $0.018 each
    # Each call reserves about $0.023; call 2 is admitted at $0.018 spent, call 3 would pass the cap.
    assert sent == 2 and f.response.status_code == 403
    refused = _recs(log)[-1]
    assert (refused["allowed"], refused["outcome"]) == (False, "refused")
    reason = json.loads(refused["body"])
    assert (reason["reason"], reason["spent_usd"], reason["reserved_usd"], reason["cap_usd"]) == \
        ("task budget exhausted", 0.036, 0.0, 0.05)
    assert reason["call_reserve_usd"] == pytest.approx(
        addon_mod.reserve_usd("claude-sonnet-4-6", refused["body_bytes"], 1000), abs=1e-6)
    ack = _control(addon, tmp_path, task="t", seq=1, drain=True)
    assert ack["spent_usd"] == pytest.approx(0.036) and ack["requests"] == 2 and ack["denied_budget"] == 1
    # A new task starts from zero.
    addon.set_task("t2", ["claude-sonnet-4-6"], 0.05, 1000)
    assert _messages(addon, "claude-sonnet-4-6").response is None


def test_only_the_scan_models_are_allowed(addon_mod, tmp_path):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6", "claude-haiku-4-5-20251001"], 1.0, 1000)
    assert _messages(addon, "claude-haiku-4-5-20251001").response is None
    f = _messages(addon, "claude-opus-4-1")
    assert f.response.status_code == 403 and f.request.headers["x-api-key"] == "d"
    reason = json.loads(_recs(log)[-1]["body"])
    assert reason["reason"] == "model not allowed" and reason["model"] == "claude-opus-4-1"
    assert addon._spend["denied_model"] == 1 and addon._spend["denied_budget"] == 0


def test_messages_refused_until_a_task_is_set(addon_mod, tmp_path):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon._limits = None
    f = _messages(addon)
    assert f.response.status_code == 403
    assert json.loads(_recs(log)[-1]["body"]) == {"reason": "no task budget set"}
    # A control message without limits leaves the task with none, so calls stay refused.
    _control(addon, tmp_path, task="t1", seq=1, drain=False)
    assert _messages(addon).response.status_code == 403
    _control(addon, tmp_path, task="t2", seq=2, drain=False, models=["claude-haiku-4-5"], cap_usd=0.5,
             max_requests=10)
    assert _messages(addon).response is None


def test_call_limit_and_in_flight_limit(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    addon.set_task("t", ["claude-haiku-4-5"], 100.0, 3)
    for _ in range(3):
        _answer(addon, _messages(addon), _json_usage(input_tokens=1))
    f = _messages(addon)
    assert json.loads(_recs(tmp_path / "p.jsonl")[-1]["body"])["reason"] == "task request limit reached"
    addon.set_task("t2", ["claude-haiku-4-5"], 100.0, 1000)
    open_calls = [_messages(addon) for _ in range(addon_mod.MAX_IN_FLIGHT)]
    assert all(c.response is None for c in open_calls)
    assert _messages(addon).response.status_code == 403
    # A call that failed upstream gets no response; the error hook frees its slot.
    open_calls[0].error = None
    addon.error(open_calls[0])
    assert _messages(addon).response is None


def test_unreadable_usage_is_charged_its_reservation_and_errors_are_free(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    f = _messages(addon, max_tokens=2000)
    reserve = f.metadata["argus_bill"][4]
    assert reserve == pytest.approx(addon_mod.reserve_usd("claude-haiku-4-5", len(f.request.raw_content), 2000))
    _answer(addon, f, b"not json", status=200)
    assert addon._spend["spent_usd"] == pytest.approx(reserve) and addon._spend["reserved_usd"] == 0.0
    # A stream cut off before message_delta has no final usage: charged the reservation, not message_start's.
    f = _messages(addon, max_tokens=2000)
    cut = _sse_usage({"input_tokens": 10, "output_tokens": 1}, {}).split(b"event: message_delta")[0]
    _answer(addon, f, cut, status=200)
    assert addon._spend["spent_usd"] == pytest.approx(2 * reserve)
    # An Anthropic error answer is not billed.
    _answer(addon, _messages(addon), b'{"type": "error", "error": {"type": "overloaded_error"}}', status=529)
    assert addon._spend["spent_usd"] == pytest.approx(2 * reserve)
    # A 5xx that is not Anthropic's error JSON keeps the reservation.
    f = _messages(addon, max_tokens=2000)
    _answer(addon, f, b"<html>bad gateway</html>", status=502)
    assert addon._spend["spent_usd"] == pytest.approx(3 * reserve)
    rows = [r for r in _recs(tmp_path / "p.jsonl") if "cost_usd" in r]
    assert [r["cost_usd"] for r in rows] == [round(reserve, 6), round(reserve, 6), 0.0, round(reserve, 6)]
    assert "charged its reservation" in rows[0]["error"] and "error" not in rows[2]


def test_client_disconnect_keeps_the_reservation(addon_mod, tmp_path):
    # The reviewer's probe: the client drops each call while Anthropic generates (mitmproxy fires error,
    # not response). Before reservations these 50 calls cost $0 and the cap never applied.
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6"], 0.05, 1000)
    forwarded = 0
    for n in range(50):
        f = _messages(addon, "claude-sonnet-4-6", max_tokens=1000)
        if f.response is not None:
            break
        forwarded += 1
        f.error = types.SimpleNamespace(msg="Client disconnected.")
        f.client_conn.id = n
        addon.error(f)
    reserve = addon_mod.reserve_usd("claude-sonnet-4-6", _recs(log)[0]["body_bytes"], 1000)
    assert forwarded == int(0.05 // reserve) == 2
    assert addon._spend["spent_usd"] == pytest.approx(forwarded * reserve)
    assert addon._spend["spent_usd"] <= 0.05
    assert addon._spend["in_flight"] == 0 and addon._spend["reserved_usd"] == pytest.approx(0)
    assert json.loads(f.response and _recs(log)[-1]["body"])["reason"] == "task budget exhausted"
    billed = [r for r in _recs(log) if "cost_usd" in r]
    assert len(billed) == forwarded and all(r["cost_usd"] == round(reserve, 6) and r["status"] == 0
                                            and "Client disconnected." in r["error"] for r in billed)


def test_calls_in_flight_count_against_the_cap(addon_mod, tmp_path):
    # Calls still running hold their reservations, so concurrent calls cannot pass the cap together.
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    addon.set_task("t", ["claude-sonnet-4-6"], 0.10, 1000)
    calls = [_messages(addon, "claude-sonnet-4-6", max_tokens=2000) for _ in range(8)]
    admitted = [c for c in calls if c.response is None]
    reserve = admitted[0].metadata["argus_bill"][4]
    assert len(admitted) == int(0.10 // reserve) == 2
    assert addon._spend["reserved_usd"] == pytest.approx(2 * reserve)
    # Each settles to its real usage, at most its reservation, which frees room for the next call.
    for c in admitted:
        _answer(addon, c, _json_usage(input_tokens=10, output_tokens=2000))
    assert addon._spend["spent_usd"] <= 0.10 and addon._spend["reserved_usd"] == pytest.approx(0)
    assert _messages(addon, "claude-sonnet-4-6", max_tokens=100).response is None


def test_max_tokens_is_required_and_bounded(addon_mod, tmp_path):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    for mt in (None, 0, "100", True):
        f = _messages(addon, max_tokens=mt)
        assert f.response.status_code == 403 and f.request.headers["x-api-key"] == "d"
        assert json.loads(_recs(log)[-1]["body"])["reason"] == "max_tokens missing"
    # The refusal names the output-token limit, so the finding can say why the call was refused.
    f = _messages(addon, max_tokens=addon_mod.MAX_OUTPUT_TOKENS + 1)
    assert f.response.status_code == 403
    assert json.loads(_recs(log)[-1]["body"]) == {"reason": "request exceeded the output-token limit",
                                                  "max_tokens": 8193, "limit": 8192}
    assert _messages(addon, max_tokens=addon_mod.MAX_OUTPUT_TOKENS).response is None
    assert addon._spend["requests"] == 1


def test_long_context_beta_is_refused(addon_mod, tmp_path):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    for beta in ("context-1m-2025-08-07", "claude-code-20250219,Context-1M-2026-01-01", "long-context-2026"):
        f = _messages(addon, headers={"anthropic-beta": beta})
        assert f.response.status_code == 403
        assert json.loads(_recs(log)[-1]["body"])["reason"] == "anthropic-beta not allowed"
    # Claude Code 2.1.311's own betas (seen in a live run) pass, context-management among them.
    cc = ("claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,"
          "prompt-caching-scope-2026-01-05,effort-2025-11-24")
    assert _messages(addon, headers={"anthropic-beta": cc}).response is None
    f = _flow("api.anthropic.com", "/v1/messages/count_tokens", {"anthropic-beta": "context-1m-2025-08-07"},
              body=b'{"model": "claude-haiku-4-5", "messages": []}')
    addon.request(f)
    assert f.response.status_code == 403


def test_count_tokens_counts_toward_the_call_limit_and_the_models(addon_mod, tmp_path):
    # The reviewer's probe: count_tokens was neither counted nor limited to the scan's models.
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-haiku-4-5-20251001"], 0.05, 2)

    def count(model):
        f = _flow("api.anthropic.com", "/v1/messages/count_tokens", {"x-api-key": "d"},
                  body=json.dumps({"model": model, "messages": []}).encode())
        addon.request(f)
        return f

    assert count("claude-opus-4-1").response.status_code == 403
    assert json.loads(_recs(log)[-1]["body"])["reason"] == "model not allowed"
    assert count("claude-haiku-4-5-20251001").response is None
    assert _messages(addon, "claude-haiku-4-5-20251001").response is None
    f = count("claude-haiku-4-5-20251001")
    assert f.response.status_code == 403
    assert json.loads(_recs(log)[-1]["body"])["reason"] == "task request limit reached"
    assert (addon._spend["requests"], addon._spend["denied_model"], addon._spend["denied_budget"]) == (2, 1, 1)
    assert addon._spend["reserved_usd"] > 0 and addon._spend["spent_usd"] == 0.0  # count_tokens reserves nothing


def test_response_message_id_is_logged(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    f = _messages(addon)
    start = {"type": "message_start", "message": {"id": "msg_01abc", "usage": {"input_tokens": 5}}}
    body = ("event: message_start\ndata: " + json.dumps(start) + "\n\nevent: message_delta\ndata: "
            + json.dumps({"type": "message_delta", "usage": {"output_tokens": 7}}) + "\n\n").encode()
    _answer(addon, f, body)
    _answer(addon, g := _messages(addon), json.dumps({"id": "msg_02", "type": "message",
                                                      "usage": {"output_tokens": 1}}).encode())
    assert [r["msg_id"] for r in _recs(tmp_path / "p.jsonl") if "cost_usd" in r] == ["msg_01abc", "msg_02"]
    assert g.metadata == {}


def test_responses_to_refused_calls_are_not_billed(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    f = _messages(addon, "not-allowed")
    _answer(addon, f, _json_usage(output_tokens=10_000_000), status=403)
    assert addon._spend["spent_usd"] == 0.0


def test_run_task_sends_limits_and_keeps_the_spend(monkeypatch):
    spend = {"spent_usd": 0.12, "requests": 7, "denied_budget": 0, "denied_model": 1}
    sb = _task_fake(monkeypatch, ack=lambda msg: {**msg, **spend})
    run = sb.run_task("t", model="claude-sonnet-4-6", budget_usd=0.3)
    start = sb.controls[0]
    assert start["models"] == sorted({"claude-sonnet-4-6", *sandbox_mod.BACKGROUND_MODELS})
    assert (start["cap_usd"], start["max_requests"]) == (0.3, sandbox_mod.MAX_REQUESTS)
    assert run.spend == spend and run.monitor_errors == []


def test_run_task_pins_claude_codes_background_model(monkeypatch):
    seen = []
    sb = _task_fake(monkeypatch)
    real_run = sandbox_mod.subprocess.run
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda cmd, **kw: (seen.append(cmd), real_run(cmd, **kw))[1])
    sb.run_task("t", model="claude-sonnet-4-6", budget_usd=0.3)
    [claude] = [c for c in seen if "claude" in c]
    env = [claude[i + 1] for i, a in enumerate(claude) if a == "-e"]
    # Only allowed models: --model, and the one background model the proxy also allows.
    assert f"ANTHROPIC_SMALL_FAST_MODEL={sandbox_mod.BACKGROUND_MODELS[0]}" in env
    assert f"ANTHROPIC_DEFAULT_HAIKU_MODEL={sandbox_mod.BACKGROUND_MODELS[0]}" in env
    assert claude[claude.index("--model") + 1] == "claude-sonnet-4-6"


def test_run_task_flags_an_exhausted_budget_but_not_as_monitoring(monkeypatch):
    sb = _task_fake(monkeypatch, ack=lambda msg: {**msg, "spent_usd": 0.31, "reserved_usd": 0.0, "requests": 9,
                                                  "denied_budget": 4, "denied_model": 0})
    run = sb.run_task("t", model="m", budget_usd=0.3)
    assert run.budget_exhausted is True and run.monitor_errors == []
    assert run.spend == {"spent_usd": 0.31, "reserved_usd": 0.0, "requests": 9, "denied_budget": 4,
                         "denied_model": 0}
    sb = _task_fake(monkeypatch, ack=lambda msg: {**msg, "spent_usd": 0.1, "requests": 2, "denied_budget": 0,
                                                  "denied_model": 3})
    assert sb.run_task("t", model="m", budget_usd=0.3).budget_exhausted is False


def test_run_task_pins_claude_codes_output_tokens(monkeypatch):
    seen = []
    sb = _task_fake(monkeypatch)
    real_run = sandbox_mod.subprocess.run
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda cmd, **kw: (seen.append(cmd), real_run(cmd, **kw))[1])
    sb.run_task("t", model="claude-sonnet-4-6", budget_usd=0.5)
    [claude] = [c for c in seen if "claude" in c]
    env = [claude[i + 1] for i, a in enumerate(claude) if a == "-e"]
    assert "CLAUDE_CODE_MAX_OUTPUT_TOKENS=8192" in env
    assert sandbox_mod.CLAUDE_CODE_MAX_OUTPUT_TOKENS <= 32768


def test_priced_models_match_the_proxys_rate_card(addon_mod):
    assert sandbox_mod.PRICED_MODEL_PREFIXES == tuple(p[0] for p in addon_mod._PRICES)
    assert sandbox_mod.is_priced_model("claude-sonnet-4-6") and sandbox_mod.is_priced_model(
        sandbox_mod.BACKGROUND_MODELS[0])
    assert not sandbox_mod.is_priced_model("claude-unknown-9") and not sandbox_mod.is_priced_model("")


def test_reservation_prices_input_as_cache_writes(addon_mod):
    r, pad = addon_mod.reserve_usd, addon_mod.INPUT_PAD_TOKENS
    # One token per body byte plus the framing pad, at Sonnet's 5-minute cache-write rate ($3.75/M).
    assert r("claude-sonnet-4-6", 4000, 0) == pytest.approx((4000 + pad) * 3.75 / 1e6)
    assert r("claude-sonnet-4-6", 4000, 1000) == pytest.approx(((4000 + pad) * 3.75 + 1000 * 15) / 1e6)
    assert r("claude-sonnet-4-6", 4000, 0, one_hour_cache=True) == pytest.approx((4000 + pad) * 6 / 1e6)
    assert r("claude-sonnet-4-6", 4000, 0, images=2) == pytest.approx(
        (4000 + pad + 2 * addon_mod.IMAGE_TOKENS) * 3.75 / 1e6)
    # Past 200K tokens Sonnet 4.x is reserved at its long-prompt rate (2x input, 1.5x output).
    assert r("claude-sonnet-4-6", 250_000, 1000) == pytest.approx(((250_000 + pad) * 7.5 + 1000 * 22.5) / 1e6)
    # Claude Code's measured first call: 85,773 bytes, max_tokens 8192; it cost $0.0807, about 1/5 of this.
    assert r("claude-sonnet-4-6", 85_773, 8192) == pytest.approx(0.4520, abs=1e-4)


def test_one_hour_cache_request_reserves_more(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    body = {"model": "claude-haiku-4-5", "max_tokens": 10, "messages": [], "system": [
        {"type": "text", "text": "x" * 4000, "cache_control": {"type": "ephemeral", "ttl": "1h"}}]}
    f = _flow("api.anthropic.com", "/v1/messages", {}, body=json.dumps(body).encode())
    addon.request(f)
    plain = addon_mod.reserve_usd("claude-haiku-4-5", len(f.request.raw_content), 10)
    assert f.metadata["argus_bill"][4] > plain



# --- request shape allowlist and the reservation bound (third fix wave) ------------------------------------

_BETAS_SONNET_46 = ("claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,"
                    "prompt-caching-scope-2026-01-05,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,"
                    "effort-2025-11-24,thinking-binding-controls-2026-08-01,thinking-display-updates-2026-08-18,"
                    "cache-diagnosis-2026-04-07")
_BETAS_5X = ("claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,"
             "prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,"
             "thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,mid-conversation-system-clear-at-2026-08-21,"
             "effort-2025-11-24,thinking-binding-controls-2026-08-01,cache-diagnosis-2026-04-07")
# Header names Claude Code 2.1.311 sent in every measured call.
_CC_HEADERS = {
    "Accept": "application/json", "Content-Type": "application/json", "User-Agent": "claude-cli/2.1.311",
    "X-Claude-Code-Session-Id": "s", "X-Stainless-Arch": "x64", "X-Stainless-Lang": "js", "X-Stainless-OS": "Linux",
    "X-Stainless-Package-Version": "0.128.0", "X-Stainless-Retry-Count": "0", "X-Stainless-Runtime": "node",
    "X-Stainless-Runtime-Version": "v26", "X-Stainless-Timeout": "600", "anthropic-beta": _BETAS_SONNET_46,
    "anthropic-dangerous-direct-browser-access": "true", "anthropic-version": "2023-06-01", "x-app": "cli",
    "x-claude-code-prompt-id": "p", "x-claude-code-request-class": "main", "x-client-request-id": "r",
    "Connection": "keep-alive", "Host": "api.anthropic.com", "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Length": "1", "x-api-key": "sk-ant-api03-dummy",
    "x-claude-code-prev-tool-durations": "Read=4",  # sent on calls after a tool ran
}


def _cc_body(model="claude-sonnet-4-6", text="Do every setup step.", n_turns=3, **over) -> dict:
    """A body with every field and block kind measured in Claude Code 2.1.311's live calls."""
    eph = {"type": "ephemeral"}
    msgs = [{"role": "user", "content": [{"type": "text", "text": text, "cache_control": eph}]}]
    for i in range(n_turns):
        msgs += [
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "", "signature": "sig" * 40},
                {"type": "text", "text": "Reading the skill."},
                {"type": "tool_use", "id": f"toolu_{i}", "name": "Read", "input": {"file_path": "/x"},
                 "caller": {"type": "direct"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": f"toolu_{i}", "is_error": False, "cache_control": eph,
                 "content": [{"type": "text", "text": text}]},
                {"type": "tool_result", "tool_use_id": f"toolu_{i}b", "content": text}]},
        ]
    msgs += [{"role": "system", "content": [{"type": "text", "text": "x"}], "output_config": {"effort": "low"}}]
    # Fable 5.1's turn-scoped system message (live, 2026-10-27).
    msgs.insert(1, {"role": "system", "content": [{"type": "text", "text": "y"}], "clear_at": "next_user_message"})
    body = {
        "model": model, "max_tokens": 8192, "stream": True,
        "metadata": {"user_id": '{"device_id":"d","session_id":"s"}'},
        "thinking": {"type": "adaptive", "display": "updates"}, "output_config": {"effort": "high"},
        "context_management": {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
        "diagnostics": {"previous_message_id": None},
        "system": [{"type": "text", "text": "You are Claude Code."},
                   {"type": "text", "text": "x" * 50, "cache_control": {"type": "ephemeral", "scope": "global"}}],
        "tools": [{"name": "Read", "description": "Read a file", "defer_loading": True,
                   "input_schema": {"$schema": "x", "type": "object", "additionalProperties": False,
                                    "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}}],
        "messages": msgs,
    }
    body.update(over)
    return body


def _send(addon, body, headers=None, path="/v1/messages?beta=true", raw=None):
    f = _flow("api.anthropic.com", path, {**_CC_HEADERS, **(headers or {})},
              body=raw if raw is not None else json.dumps(body, ensure_ascii=False).encode())
    addon.request(f)
    return f


def _reason(log):
    return json.loads(_recs(log)[-1]["body"])


@pytest.mark.parametrize("headers", [{}, {"anthropic-beta": _BETAS_5X}])
def test_claude_codes_measured_request_shape_is_forwarded(addon_mod, tmp_path, headers):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6", "claude-haiku-4-5-20251001"], 100.0, 1000)
    assert _send(addon, _cc_body(), headers).response is None
    # Haiku 4.5's shape: budget thinking, no output_config; an image a Read returned inside a tool result.
    body = _cc_body("claude-haiku-4-5-20251001", thinking={"type": "enabled", "budget_tokens": 8191,
                                                           "display": "omitted"})
    del body["output_config"]
    body["messages"][-2]["content"][0]["content"].append(
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}})
    f = _send(addon, body, headers)
    assert f.response is None and f.metadata["argus_bill"][4] == pytest.approx(addon_mod.reserve_usd(
        "claude-haiku-4-5-20251001", len(f.request.raw_content), 8192, images=1))
    assert _send(addon, {"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "hi"}]},
                 headers, path="/v1/messages/count_tokens?beta=true").response is None


@pytest.mark.parametrize("change,detail", [
    ({"speed": "fast"}, "'speed'"),
    ({"fallbacks": "default"}, "'fallbacks'"),
    ({"fallbacks": [{"model": "claude-opus-4-8"}]}, "'fallbacks'"),
    ({"inference_geo": "us"}, "'inference_geo'"),
    ({"service_tier": "auto"}, "'service_tier'"),
    ({"tool_choice": {"type": "auto"}}, "'tool_choice'"),
    ({"cache_control": {"type": "ephemeral"}}, "'cache_control'"),
    ({"output_config": {"effort": "max", "task_budget": {"type": "tokens", "total": 1}}}, "'task_budget'"),
    ({"context_management": {"edits": [{"type": "compact_20260112"}]}}, "compact_20260112"),
    ({"thinking": {"type": "enabled", "budget_tokens": 10, "x": 1}}, "'x'"),
    ({"system": [{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "24h"}}]},
     "cache_control"),
    ({"tools": [{"name": "Bash", "input_schema": {}, "type": "custom"}]}, "'type'"),
    ({"messages": [{"role": "user", "content": [{"type": "search_result", "source": "x"}]}]}, "search_result"),
    ({"messages": [{"role": "user", "content": [{"type": "text", "text": "x", "citations": []}]}]}, "'citations'"),
    ({"messages": [{"role": "user", "content": [{"type": "image", "source": {
        "type": "base64", "media_type": "image/png", "data": "x", "extra": 1}}]}]}, "'extra'"),
    ({"messages": [{"role": "developer", "content": "x"}]}, "role"),
    ({"messages": [{"role": "user", "content": "x", "clear_at": "next_user_message"}]}, "clear_at"),
    ({"messages": [{"role": "system", "content": "x", "clear_at": "never"}]}, "clear_at"),
])
def test_request_shape_outside_claude_codes_is_refused(addon_mod, tmp_path, change, detail):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6"], 100.0, 1000)
    f = _send(addon, _cc_body(**change))
    assert f.response.status_code == 403 and f.request.headers["x-api-key"] != FAKE_REAL_KEY
    why = _reason(log)
    assert why["reason"] == "request shape not allowed" and detail in why["detail"]
    assert addon._spend["requests"] == 0 and addon._spend["reserved_usd"] == 0.0


def test_pdf_documents_are_refused_with_their_own_reason(addon_mod, tmp_path):
    # Claude Code sends one when the agent Reads a PDF; a page costs a rendered image whatever its byte size.
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6"], 100.0, 1000)
    body = _cc_body()
    body["messages"][-2]["content"][0]["content"] = [
        {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBER"}}]
    assert _send(addon, body).response.status_code == 403
    assert _reason(log)["reason"] == "document content not allowed"


@pytest.mark.parametrize("headers,why", [
    ({"anthropic-beta": _BETAS_SONNET_46 + ",fast-mode-2026-02-01"}, "anthropic-beta not allowed"),
    ({"anthropic-beta": "server-side-fallback-2026-07-01"}, "anthropic-beta not allowed"),
    ({"anthropic-beta": "context-1m-2025-08-07"}, "anthropic-beta not allowed"),
    ({"anthropic-beta": "compact-2026-01-12"}, "anthropic-beta not allowed"),
    ({"anthropic-priority": "high"}, "request header not allowed"),
    ({"anthropic-version": "2099-01-01"}, "request header not allowed"),
])
def test_unknown_betas_and_headers_are_refused(addon_mod, tmp_path, headers, why):
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-sonnet-4-6"], 100.0, 1000)
    assert _send(addon, _cc_body(), headers).response.status_code == 403
    assert _reason(log)["reason"] == why
    assert _send(addon, _cc_body(), headers, path="/v1/messages/count_tokens").response.status_code == 403


def test_fast_mode_and_fallbacks_are_refused_before_any_spend(addon_mod, tmp_path):
    # The reviewer's probes: fast mode was priced at the standard rate, and fallbacks could bill another model.
    log = tmp_path / "p.jsonl"
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(log))
    addon.set_task("t", ["claude-opus-5-5"], 1.0, 100)
    f = _send(addon, _cc_body("claude-opus-5-5", speed="fast"),
              {"anthropic-beta": _BETAS_5X + ",fast-mode-2026-02-01"})
    assert f.response.status_code == 403 and "argus_bill" not in f.metadata
    f = _send(addon, _cc_body("claude-opus-5-5", speed="fast"), {"anthropic-beta": _BETAS_5X})
    assert f.response.status_code == 403 and "'speed'" in _reason(log)["detail"]
    f = _send(addon, _cc_body("claude-opus-5-5", fallbacks="default"), {"anthropic-beta": _BETAS_5X})
    assert f.response.status_code == 403 and "'fallbacks'" in _reason(log)["detail"]
    assert addon._spend == {**addon._new_spend()}


def test_query_strings_other_than_beta_are_refused(addon_mod, tmp_path):
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    addon.set_task("t", ["claude-sonnet-4-6"], 100.0, 1000)
    assert _send(addon, _cc_body(), path="/v1/messages").response is None
    assert _send(addon, _cc_body(), path="/v1/messages?beta=true&priority=1").response.status_code == 403


def test_one_hour_ttl_is_read_from_the_parsed_body(addon_mod, tmp_path):
    # The reviewer's probe: "ttl" is "ttl" once parsed, so it must reserve the 1-hour rate.
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    addon.set_task("t", ["claude-sonnet-4-6"], 100.0, 1000)
    body = _cc_body(system=[{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "1h"}}])
    raw = json.dumps(body).encode()
    escaped = raw.replace(b'"ttl"', b'"t\\u0074l"')
    plain, esc = _send(addon, None, raw=raw), _send(addon, None, raw=escaped)
    assert plain.metadata["argus_bill"][5] is True and esc.metadata["argus_bill"][5] is True
    assert esc.metadata["argus_bill"][4] == pytest.approx(
        addon_mod.reserve_usd("claude-sonnet-4-6", len(escaped), 8192, one_hour_cache=True))
    # A ttl only inside text is not a cache setting.
    other = _send(addon, _cc_body(text='"ttl": "1h"'))
    assert other.metadata["argus_bill"][5] is False


# count_tokens readings (free) on 2026-10-27: (bytes of the body, input tokens) on Sonnet 4.6 and Opus 5.5.
# Dense CJK, emoji, ZWJ sequences and astral-plane text all stay under one token per byte; the tool-use
# system prompt the API adds is the only case above it, by at most 527 tokens.
_MEASURED_TOKENS = {
    "tiny": [(78, 8), (76, 9)], "tiny+tool": [(159, 527), (157, 323)], "tiny+12tools": [(943, 781), (941, 643)],
    "many-empty-msgs": [(14678, 1608), (14676, 1209)], "cjk": [(9077, 6348), (9075, 6348)],
    "emoji": [(8077, 5561), (8075, 5561)], "zwj": [(9077, 5008), (9075, 5008)],
    "rare-planes": [(601, 529), (599, 529)], "tool-use-loop": [(20659, 5228), (20657, 3323)],
    "claude-code-first-call": [(85_772, 21_074)],
}


def test_measured_tokens_stay_within_bytes_plus_the_pad(addon_mod):
    for readings in _MEASURED_TOKENS.values():
        for n_bytes, tokens in readings:
            assert tokens <= n_bytes + addon_mod.INPUT_PAD_TOKENS


def _worst_usages(tokens: int, max_tokens: int, one_hour: bool):
    """Every way a call with this many input tokens can be billed: all plain, all cache writes, all reads,
    or a mix, with max_tokens of output."""
    write_key = "ephemeral_1h_input_tokens" if one_hour else "ephemeral_5m_input_tokens"
    third = tokens // 3
    for plain, write, read in ((tokens, 0, 0), (0, tokens, 0), (0, 0, tokens), (third, third, tokens - 2 * third)):
        yield {"input_tokens": plain, "output_tokens": max_tokens, "cache_read_input_tokens": read,
               "cache_creation_input_tokens": write, "cache_creation": {write_key: write}}
        yield {"input_tokens": plain, "output_tokens": max_tokens, "cache_read_input_tokens": read,
               "cache_creation_input_tokens": write}  # not split by lifetime


@pytest.mark.parametrize("model", ["claude-sonnet-4-6", "claude-haiku-4-5-20251001", "claude-haiku-5-5",
                                   "claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-1"])
@pytest.mark.parametrize("case", ["claude-code", "cjk", "emoji", "long-context", "one-hour", "images",
                                  "tiny-with-tools"])
def test_reservation_covers_the_settled_charge(addon_mod, tmp_path, model, case):
    """For every allowed request, the charge at settle is at most the reservation made at admission."""
    random = __import__("random").Random(7)
    over = {}
    text = "Do every setup step."
    if case == "cjk":
        text = "".join(chr(random.randint(0x4E00, 0x9FFF)) for _ in range(20_000))
    elif case == "emoji":
        text = "".join(chr(random.randint(0x1F300, 0x1F64F)) for _ in range(20_000))
    elif case == "long-context":
        text = "".join(chr(random.randint(0x4E00, 0x9FFF)) for _ in range(30_000)) * 3  # ~270 KB of text
    elif case == "one-hour":
        over["system"] = [{"type": "text", "text": "x" * 5000, "cache_control": {"type": "ephemeral", "ttl": "1h"}}]
    body = _cc_body(model, text=text, **over)
    if case == "images":
        body["messages"][-2]["content"][0]["content"] = [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}}] * 3
    if case == "tiny-with-tools":
        body = {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "a"}],
                "tools": [{"name": f"t{i}", "input_schema": {}} for i in range(3)]}
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    addon.set_task("t", [model], 1000.0, 1000)
    f = _send(addon, body)
    assert f.response is None
    _, _, _, _, reserve, flagged = f.metadata["argus_bill"]
    # Billed at the 1-hour write rate only when the body asks for it; the proxy must have seen that.
    one_hour = case == "one-hour"
    assert flagged is one_hour
    n_bytes = len(f.request.raw_content)
    # The most input the API can bill: a token per byte, the framing measured above, the image allowance.
    tokens = n_bytes + 527 + 4784 * (3 if case == "images" else 0)
    if case == "long-context":
        assert tokens > 200_000
    for usage in _worst_usages(tokens, body["max_tokens"], one_hour):
        assert addon_mod.price_usd(model, usage, one_hour) <= reserve + 1e-12, usage
    # Settle through the proxy with the dearest of them: no "above its reservation" error, spend <= reserve.
    worst = max(_worst_usages(tokens, body["max_tokens"], one_hour),
                key=lambda u: addon_mod.price_usd(model, u, one_hour))
    _answer(addon, f, _json_usage(**worst))
    row = [r for r in _recs(tmp_path / "p.jsonl") if "cost_usd" in r][-1]
    assert "error" not in row and addon._spend["spent_usd"] <= reserve + 1e-12


def test_dense_disconnect_loop_stays_under_the_cap(addon_mod, tmp_path):
    # Adversarial loop: dense CJK prompts, each call dropped by its client (charged its reservation) or
    # answered with the most usage its shape allows. Spend never passes the cap.
    random = __import__("random").Random(3)
    addon = addon_mod.ArgusProxy(FAKE_REAL_KEY, str(tmp_path / "p.jsonl"))
    addon.set_task("t", ["claude-sonnet-4-6"], 0.05, 1000)
    for n in range(40):
        text = "".join(chr(random.randint(0x4E00, 0x9FFF)) for _ in range(random.randint(10, 3000)))
        body = {"model": "claude-sonnet-4-6", "max_tokens": random.randint(1, 8192),
                "messages": [{"role": "user", "content": text}]}
        f = _send(addon, body)
        if f.response is not None:
            continue
        if n % 2:
            f.error, f.client_conn.id = types.SimpleNamespace(msg="Client disconnected."), n
            addon.error(f)
        else:
            tokens = len(f.request.raw_content) + 527
            _answer(addon, f, _json_usage(cache_creation_input_tokens=tokens, output_tokens=body["max_tokens"],
                                          cache_creation={"ephemeral_5m_input_tokens": tokens}))
        assert addon._spend["spent_usd"] + addon._spend["reserved_usd"] <= 0.05 + 1e-12
    assert addon._spend["denied_budget"] > 0 and addon._spend["spent_usd"] <= 0.05


def test_output_tokens_are_pinned_in_managed_settings():
    # Managed settings outrank ~/.claude/settings.json and the process env (measured on 2.1.311).
    text = (sandbox_mod.DOCKER_DIR / "agent.Dockerfile").read_text()
    pin = f'{{"env": {{"CLAUDE_CODE_MAX_OUTPUT_TOKENS": "{sandbox_mod.CLAUDE_CODE_MAX_OUTPUT_TOKENS}"}}}}'
    assert pin in text and "/etc/claude-code/managed-settings.json" in text


def test_claude_codes_pinned_output_fits_the_proxy_limit(addon_mod):
    assert sandbox_mod.CLAUDE_CODE_MAX_OUTPUT_TOKENS == addon_mod.MAX_OUTPUT_TOKENS


# --- closing fix wave: per-model caps, a broken bound, the measured Claude Code version ------------

def test_host_reservation_matches_the_proxys(addon_mod):
    # The CLI's default and minimum caps come from this copy of the proxy's rate card.
    assert sandbox_mod._INPUT_PAD_TOKENS == addon_mod.INPUT_PAD_TOKENS
    assert sandbox_mod._LONG_PROMPT == addon_mod._LONG_PROMPT
    for prefix in sandbox_mod.PRICED_MODEL_PREFIXES:
        for size in (100_000, 150_000, 250_000):
            assert sandbox_mod.call_reserve_usd(prefix, size, 8192) == pytest.approx(
                addon_mod.reserve_usd(prefix, size, 8192), rel=1e-12), (prefix, size)


@pytest.mark.parametrize("model,default,minimum", [
    ("claude-sonnet-4-6", 1.50, 0.51), ("claude-haiku-4-5-20251001", 1.00, 0.17), ("claude-sonnet-5-5", 1.00, 0.34),
    ("claude-opus-5-5", 2.00, 0.68), ("claude-fable-5-1", 4.75, 1.69), ("claude-haiku-5-5", 1.00, 0.09),
])
def test_default_cap_is_two_large_calls_and_the_minimum_one_100kb_call(model, default, minimum):
    assert sandbox_mod.default_cap_usd(model) == pytest.approx(default)
    assert sandbox_mod.min_cap_usd(model) == pytest.approx(minimum)
    two = 2 * sandbox_mod.call_reserve_usd(model, 150_000, sandbox_mod.CLAUDE_CODE_MAX_OUTPUT_TOKENS)
    assert two <= default < max(two, 1.0) + 0.25 and round(default * 4, 9) == int(default * 4)


def test_a_settle_above_its_reservation_is_a_high_monitor_note(addon_mod, monkeypatch, tmp_path):
    from argus.skillscan.rules import evaluate, monitor_severity
    assert sandbox_mod._SETTLED_ABOVE == addon_mod.SETTLED_ABOVE
    log = tmp_path / "proxy.jsonl"
    addon = addon_mod.ArgusProxy(real_key=FAKE_REAL_KEY, log_path=str(log))

    def call():
        addon.set_task("t", ["claude-haiku-4-5"], 5.0, 100)
        flow = _messages(addon, max_tokens=10)
        # A charge the reservation cannot cover (an output far past max_tokens).
        _answer(addon, flow, _json_usage(input_tokens=10, output_tokens=1_000_000))

    run = _task_fake(monkeypatch, proxy_log=log, on_claude=call).run_task("t", model="m", budget_usd=0.1)
    [note] = run.monitor_errors
    assert note.startswith("Spend accounting bound broken: 1 API call(s) cost more than the proxy reserved")
    assert "charged $5.0" in note and monitor_severity(note) == "high"
    [f] = [f for f in evaluate([run], [], skill_name="s") if f["probe_id"] == "skill_monitoring_disrupted"]
    assert f["severity"] == "high"


def test_the_pinned_claude_code_is_the_version_the_allowlist_was_measured_on(addon_mod):
    pinned = re.findall(r"@anthropic-ai/claude-code@(\S+)", (sandbox_mod.DOCKER_DIR / "agent.Dockerfile").read_text())
    assert pinned == [addon_mod.CLAUDE_CODE_VERSION], (
        f"agent.Dockerfile installs Claude Code {pinned} but proxy_addon.py's request-shape allowlist was measured "
        f"on {addon_mod.CLAUDE_CODE_VERSION}. Re-measure the request shape (body keys, block types, betas, headers) "
        f"on the new version, update the allowlist, then update CLAUDE_CODE_VERSION.")
