"""Tests for `argus-probe list-probes`."""

import pytest
from click.testing import CliRunner

from argus.api import PROBES_DIR
from argus.cli.__main__ import main
from argus.probe import Probe, ProbeMappings, load_probe_library


def test_list_probes_local_uses_bundled_library(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    wanted = sorted(p.id for p in load_probe_library(PROBES_DIR) if "mcp_rugpull" in p.id.lower())
    assert len(wanted) >= 2
    result = CliRunner().invoke(main, ["list-probes", "--filter", "mcp_rugpull"])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[:len(wanted)] == wanted
    assert f"{len(wanted)} probes" in result.output


@pytest.mark.parametrize("filter_text", ["MCP_RUGPULL", "Mcp_RugPull", "mCp_RuGpUlL"])
def test_list_probes_filter_is_case_insensitive(monkeypatch, filter_text):
    """Pasted or typed filter text matches regardless of capitalization."""
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    wanted = sorted(p.id for p in load_probe_library(PROBES_DIR) if "mcp_rugpull" in p.id.lower())
    result = CliRunner().invoke(main, ["list-probes", "--filter", filter_text])
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
    wanted = sorted(p.id for p in load_probe_library(PROBES_DIR) if "mcp_agent" in p.target_class and not p.domain_only)
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


@pytest.fixture
def detail_library(monkeypatch):
    from dataclasses import replace

    free = Probe(id="a_free", name="Deterministic check", severity="medium",
                 target_class=("llm_chat",), attack_class=("prompt-injection",),
                 prompts=("test",), mappings=ProbeMappings(), judge_rubric_path="test.md",
                 assertions=({"type": "contains", "value": "test"},), domains=("legal",))
    judged = replace(free, id="b_judged", name="Judged check", severity="high", assertions=())
    hybrid = replace(free, id="c_hybrid", name="Hybrid check", severity="critical",
                     judge_when_assertions_pass=True)
    optional = replace(free, id="d_optional", name="Optional check", opt_in=True)
    other = replace(free, id="z_other", name="Server check", severity="low",
                    target_class=("mcp_server",), domains=("financial-services",))
    probes = [other, optional, hybrid, judged, free]
    monkeypatch.setattr("argus.probe.load_probe_library", lambda _: probes)
    monkeypatch.setattr("argus.api.load_probe_library", lambda _: probes)
    monkeypatch.delenv("ARGUS_API_URL", raising=False)


CHAT_TARGET = '{"kind":"openai_compat","endpoint_url":"http://127.0.0.1:9/v1","model":"m"}'


def test_list_probes_long_shows_aligned_metadata(detail_library):
    result = CliRunner().invoke(main, ["list-probes", "--long"])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "id          severity  judge  name\n"
        "a_free      medium    no     Deterministic check\n"
        "b_judged    high      yes    Judged check\n"
        "c_hybrid    critical  yes    Hybrid check\n"
        "d_optional  medium    no     Optional check [opt-in]\n"
        "z_other     low       no     Server check\n"
        "\n5 probes\n"
    )


@pytest.mark.parametrize("extra,wanted", [
    ([], ["a_free", "d_optional [opt-in]", "z_other"]),
    (["--target", CHAT_TARGET], ["a_free"]),
    (["--domain", "legal"], ["a_free", "d_optional [opt-in]"]),
    (["--target-class", "http-chat"], ["a_free", "d_optional [opt-in]"]),
    (["--filter", "Z_OTHER"], ["z_other"]),
    (["--filter", "judged"], []),
])
def test_list_probes_no_judge_filters_and_counts(detail_library, extra, wanted):
    result = CliRunner().invoke(main, ["list-probes", "--no-judge", *extra])
    assert result.exit_code == 0, result.output
    assert result.output == "".join(f"{pid}\n" for pid in wanted) + f"\n{len(wanted)} probes\n"


def test_list_probes_long_no_judge_combines_target_domain_and_filter(detail_library):
    result = CliRunner().invoke(main, ["list-probes", "--long", "--no-judge", "--target", CHAT_TARGET,
                                      "--domain", "legal", "--filter", "FREE"])
    assert result.exit_code == 0, result.output
    assert result.output == (
        "id      severity  judge  name\n"
        "a_free  medium    no     Deterministic check\n"
        "\n1 probes\n"
    )


def test_list_probes_long_empty_selection(detail_library):
    result = CliRunner().invoke(main, ["list-probes", "--long", "--filter", "absent"])
    assert result.exit_code == 0, result.output
    assert result.output == "id  severity  judge  name\n\n0 probes\n"


@pytest.mark.parametrize("flag", ["--long", "--no-judge"])
def test_list_probes_detail_flags_need_local_metadata(flag, monkeypatch):
    monkeypatch.setattr("argus.cli.api_client.list_probes", lambda *args: [])
    result = CliRunner().invoke(main, ["list-probes", flag, "--api-url", "http://127.0.0.1:9",
                                      "--token", "test"])
    assert result.exit_code == 2, result.output
    assert f"{flag} needs probe metadata from the local library; do not combine it with --api-url" in result.output


@pytest.mark.parametrize("extra,wanted", [
    ([], "a_free\nb_judged\nc_hybrid\nd_optional [opt-in]\nz_other\n\n5 probes\n"),
    (["--target", CHAT_TARGET], "a_free\nb_judged\nc_hybrid\n\n3 probes\n"),
    (["--domain", "legal"], "a_free\nb_judged\nc_hybrid\nd_optional [opt-in]\n\n4 probes\n"),
    (["--target-class", "mcp_server"], "z_other\n\n1 probes\n"),
    (["--filter", "JUDGED"], "b_judged\n\n1 probes\n"),
    (["--filter", "absent"], "\n0 probes\n"),
])
def test_list_probes_default_preserves_original_bytes(detail_library, extra, wanted):
    result = CliRunner().invoke(main, ["list-probes", *extra])
    assert result.exit_code == 0, result.output
    assert result.stdout_bytes == wanted.encode()
