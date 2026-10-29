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


def _write(tmp_path, spec: dict) -> str:
    import json
    p = tmp_path / "t.json"
    p.write_text(json.dumps(spec))
    return str(p)


def _ids_in(output: str) -> list[str]:
    lines = output.splitlines()
    return lines[:lines.index("")]


def test_list_probes_target_shows_only_what_that_target_can_run(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    spec = _write(tmp_path, {"kind": "mcp_agent", "testbed_url": "http://127.0.0.1:1", "sandbox": True,
                             "inner": {"kind": "openai_compat", "endpoint_url": "http://x/v1", "model": "m"}})
    result = CliRunner().invoke(main, ["list-probes", "--target", spec])
    assert result.exit_code == 0, result.output
    wanted = sorted(p.id for p in load_probe_library(PROBES_DIR) if "mcp_agent" in p.target_class)
    assert 0 < len(wanted) < len(load_probe_library(PROBES_DIR))
    assert _ids_in(result.output) == wanted
    assert f"\n{len(wanted)} probes" in result.output


def test_list_probes_target_reads_testbed_agent_environment(tmp_path, monkeypatch):
    # testbed_agent sets its classes from `environment`, so the filter must use the built target.
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    spec = _write(tmp_path, {"kind": "testbed_agent", "environment": "payment", "testbed_url": "http://127.0.0.1:1",
                             "sandbox": True, "inner": {"kind": "openai_compat", "endpoint_url": "http://x/v1",
                                                        "model": "m"}})
    result = CliRunner().invoke(main, ["list-probes", "--target", spec])
    assert result.exit_code == 0, result.output
    assert _ids_in(result.output) == sorted(
        p.id for p in load_probe_library(PROBES_DIR) if "payment_agent" in p.target_class)


def test_list_probes_target_class_filter_and_combines_with_filter(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    result = CliRunner().invoke(main, ["list-probes", "--target-class", "browser-using"])
    assert result.exit_code == 0, result.output
    wanted = sorted(p.id for p in load_probe_library(PROBES_DIR) if "browser-using" in p.target_class)
    assert wanted and _ids_in(result.output) == wanted

    result = CliRunner().invoke(main, ["list-probes", "--target-class", "browser-using", "--filter", wanted[0]])
    assert _ids_in(result.output) == [wanted[0]]
    # A chat probe id never passes a browser-using filter.
    chat = next(p.id for p in load_probe_library(PROBES_DIR) if p.target_class == ("http-chat",))
    result = CliRunner().invoke(main, ["list-probes", "--target-class", "browser-using", "--filter", chat])
    assert "\n0 probes" in result.output


def test_list_probes_rejects_unknown_target_class():
    result = CliRunner().invoke(main, ["list-probes", "--target-class", "nope"])
    assert result.exit_code == 2
    assert "nope" in result.output


def test_list_probes_bad_target_spec_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    result = CliRunner().invoke(main, ["list-probes", "--target", _write(tmp_path, {"kind": "nope"})])
    assert result.exit_code == 2
    assert "unknown target.kind" in result.output


def test_list_probes_target_filters_need_the_local_library():
    for flag, value in (("--target", "{}"), ("--target-class", "llm_chat")):
        result = CliRunner().invoke(main, ["list-probes", "--api-url", "https://x", "--token", "t", flag, value])
        assert result.exit_code == 2
        assert f"{flag} filters the local library" in result.output
