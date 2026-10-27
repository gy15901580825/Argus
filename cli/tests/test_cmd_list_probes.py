"""Tests for `argus-probe list-probes`. The engine is faked in sys.modules so
the CLI suite needs no orchestrator install."""

import sys
import types
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from argus_probe.__main__ import main


def _install_fake_library(monkeypatch, ids):
    for name in ("orchestrator", "orchestrator.redteam"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    api = types.ModuleType("orchestrator.redteam.api")
    api.PROBES_DIR = Path("/fake/probes")
    probe = types.ModuleType("orchestrator.redteam.probe")
    probe.load_probe_library = lambda d: [SimpleNamespace(id=i) for i in ids] if d == api.PROBES_DIR else []
    monkeypatch.setitem(sys.modules, "orchestrator.redteam.api", api)
    monkeypatch.setitem(sys.modules, "orchestrator.redteam.probe", probe)


def test_list_probes_local_uses_bundled_library(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    _install_fake_library(monkeypatch, ["pi-b", "mcp-a", "mcp-c"])
    result = CliRunner().invoke(main, ["list-probes", "--filter", "mcp"])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[:2] == ["mcp-a", "mcp-c"]
    assert "2 probes" in result.output


def test_list_probes_local_without_engine_prints_install_hint(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.setitem(sys.modules, "orchestrator", None)
    result = CliRunner().invoke(main, ["list-probes"])
    assert result.exit_code == 2
    assert "argus-probe" in result.output and "install" in result.output


def test_list_probes_server_mode_needs_token(monkeypatch):
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    result = CliRunner().invoke(main, ["list-probes", "--api-url", "https://x"])
    assert result.exit_code == 2
    assert "--token" in result.output


def test_list_probes_server_mode_lists_from_api(monkeypatch):
    calls = []

    def fake_list(api_url, token):
        calls.append((api_url, token))
        return ["b", "a"]

    monkeypatch.setattr("argus_probe.api_client.list_probes", fake_list)
    result = CliRunner().invoke(main, ["list-probes", "--api-url", "https://x", "--token", "t"])
    assert result.exit_code == 0, result.output
    assert calls == [("https://x", "t")]
    assert result.output.splitlines()[:2] == ["a", "b"]
