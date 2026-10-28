"""Tests for `argus-probe list-probes`."""

from click.testing import CliRunner

from argus.api import PROBES_DIR
from argus.cli.__main__ import main
from argus.probe import load_probe_library


def test_list_probes_local_uses_bundled_library(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    wanted = sorted(p.id for p in load_probe_library(PROBES_DIR) if "mcp_rugpull" in p.id.lower())
    assert len(wanted) >= 2
    result = CliRunner().invoke(main, ["list-probes", "--filter", "mcp_rugpull"])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[:len(wanted)] == wanted
    assert f"{len(wanted)} probes" in result.output


def test_list_probes_local_lists_the_whole_library(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    result = CliRunner().invoke(main, ["list-probes"])
    assert result.exit_code == 0, result.output
    assert f"\n{len(load_probe_library(PROBES_DIR))} probes" in result.output


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

    monkeypatch.setattr("argus.cli.api_client.list_probes", fake_list)
    result = CliRunner().invoke(main, ["list-probes", "--api-url", "https://x", "--token", "t"])
    assert result.exit_code == 0, result.output
    assert calls == [("https://x", "t")]
    assert result.output.splitlines()[:2] == ["a", "b"]
