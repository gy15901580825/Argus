"""Placeholder credentials preserve prose while whole values stay masked."""

import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.cli.reports import render_html
from argus.cli.run_json import render_json, scrub_run
from argus.mcp_scan.known_secrets import VALUE_MIN
from argus.redaction import _scrub, mask_text, run_secrets
from test_cmd_run_local import _install_fake_engine
from test_run_json import _finding, _run


@pytest.mark.parametrize("key", ["e", "x", "no"])
def test_short_key_preserves_report_prose_and_masks_echoed_fields(key):
    prose = "no judge key: skipped; example"
    run = _run(target_spec={"kind": "openai_compat", "api_key": key},
               findings=[_finding(reasoning=prose, target_response=key,
                                  evidence={"echo": [key, {"nested": key}], key: "key"})])
    clean = json.loads(render_json(run))
    assert clean["target_spec"]["api_key"] == "***"
    finding = clean["findings"][0]
    assert finding["reasoning"] == prose
    assert finding["target_response"] == "***"
    assert finding["evidence"] == {"echo": ["***", {"nested": "***"}], "***": "key"}
    html = render_html(scrub_run(run))
    assert prose in html


@pytest.mark.parametrize("key", ["e", "x", "no"])
@pytest.mark.parametrize("fmt", ["html", "json"])
def test_local_skipped_report_with_placeholder_key(tmp_path, monkeypatch, key, fmt):
    async def skipped_run(target, probe_ids, **kwargs):
        yield _finding(verdict="skipped", severity="info", reasoning="no judge key: skipped; example", evidence={})
        yield {"type": "coverage", "coverage": {"thin_threshold": 2, "standards": {}}}

    _install_fake_engine(monkeypatch, skipped_run)
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1",
                                  "model": "placeholder", "api_key": key}))
    out = tmp_path / f"report.{fmt}"
    result = CliRunner().invoke(main, ["run", "--local", "--skip-judged", "--target", str(target),
                                       "--probes", "owasp_01_prompt_injection_basic",
                                       "--format", fmt, "--out", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert "no judge key: skipped; example" in text
    assert "skipped" in text
    if fmt == "json":
        assert '"api_key": "***"' in text
        data = json.loads(text)
        assert data["summary"]["by_verdict"]["skipped"] == 1
        assert data["findings"][0]["verdict"] == "skipped"


@pytest.mark.parametrize("key", ["q" * (VALUE_MIN - 1), "q" * VALUE_MIN, "long-placeholder-secret"])
def test_masking_length_boundary_and_long_secret_in_reports(key):
    prose = f"prefix-{key}-suffix"
    expected = prose if len(key) < VALUE_MIN else "prefix-***-suffix"
    run = _run(target_spec={"kind": "openai_compat", "api_key": key},
               findings=[_finding(reasoning=prose, target_response=key, evidence={})])
    clean = json.loads(render_json(run))
    assert clean["findings"][0]["reasoning"] == expected
    assert clean["findings"][0]["target_response"] == "***"
    assert clean["target_spec"]["api_key"] == "***"
    assert expected in render_html(scrub_run(run))
    assert mask_text(prose, run_secrets(run["target_spec"])) == expected


def test_short_bearer_credential_and_explicit_secret_mask_whole_values():
    secrets = run_secrets({"headers": {"Authorization": "Bearer e"}}, secret_values=["no"])
    assert _scrub(["judge key skipped", "e", "no", "prefix-Bearer e-suffix"], secrets) == [
        "judge key skipped", "***", "***", "prefix-***-suffix"]


def test_secret_named_invalid_field_keeps_error_readable(tmp_path):
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1",
                                  "model": "placeholder", "token": "e"}))
    result = CliRunner().invoke(main, ["run", "--local", "--skip-judged", "--target", str(target),
                                       "--probes", "owasp_01_prompt_injection_basic", "--out", str(tmp_path / "report.html")])
    assert result.exit_code != 0
    assert "unknown field 'token'" in result.output
    message = "target spec invalid: unexpected keyword argument 'token'"
    assert mask_text(message, run_secrets({"token": "e"})) == message
    assert "***" not in result.output
