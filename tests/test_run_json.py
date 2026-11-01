"""Tests for run.json: the versioned, redacted run record written by `run --format json`."""

import json
from datetime import datetime, timezone
from uuid import UUID

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.cli.run_json import redact, render_json
from argus.cli.target_loader import load_target_spec, load_target_spec_with_secrets
from argus.coverage import build_summary
from test_cmd_run_local import FAIL_FINDING, _LocalRunError, _install_fake_engine

TOP_LEVEL_KEYS = ["schema_version", "id", "status", "started_at", "finished_at",
                  "argus_version", "target_spec", "coverage", "summary", "findings"]


def _finding(**overrides):
    f = {
        "id": "00000000-0000-0000-0000-000000000001",
        "probe_id": "p1",
        "attack_prompt": "a",
        "target_response": "r",
        "target_latency_ms": 1.0,
        "probed_at": "2026-01-01T00:00:00+00:00",
        "verdict": "fail",
        "severity": "high",
        "confidence": 0.9,
        "reasoning": "x",
        "judge_model": "j",
        "escalated_model": None,
        "atlas_id": [],
        "owasp_id": [],
        "nist_id": [],
        "eu_ai_act_id": [],
        "created_at": "2026-01-01T00:00:00+00:00",
        "evidence": {"tool_calls": [{"name": "pay"}]},
    }
    f.update(overrides)
    return f


def _run(target_spec=None, findings=()):
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "status": "completed",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "target_spec": target_spec or {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"},
        "coverage": {"thin_threshold": 2, "standards": {}},
        "findings": list(findings),
    }


def _spec_file(tmp_path, spec):
    p = tmp_path / "t.json"
    p.write_text(json.dumps(spec))
    return str(p)


def test_run_json_has_schema_version_and_findings():
    out = json.loads(render_json(_run(findings=[_finding()])))
    assert out["schema_version"] == "argus.run/1"
    assert out["findings"][0]["probe_id"] == "p1"
    assert out["findings"][0]["evidence"] == {"tool_calls": [{"name": "pay"}]}


def test_run_json_top_level_key_order():
    assert list(json.loads(render_json(_run())).keys()) == TOP_LEVEL_KEYS


def test_run_json_summary_counts_findings_and_keeps_other_keys():
    fs = [_finding(), _finding(verdict="pass", severity="info"),
          _finding(verdict="error", severity="info")]
    run = _run(findings=fs)
    out = json.loads(render_json(run))
    assert out["summary"] == build_summary(fs)
    assert out["summary"]["total"] == 3
    assert out["summary"]["evaluated"] == 2
    assert out["summary"]["failed_by_severity"]["high"] == 1
    assert [key for key in out if key != "summary"] == [key for key in TOP_LEVEL_KEYS if key != "summary"]
    assert out["coverage"] == run["coverage"]
    assert out["findings"] == fs
    assert out["schema_version"] == "argus.run/1"


def test_run_json_summary_survives_one_char_secret():
    fs = [_finding(), _finding(verdict="pass", severity="info")]
    out = json.loads(render_json(_run(findings=fs), secret_values=["a"]))
    assert out["summary"] == build_summary(fs)
    assert out["summary"]["evaluated_verdicts"] == ["fail", "pass", "warn"]


def test_run_json_summary_for_no_findings():
    out = json.loads(render_json(_run()))
    assert out["summary"]["total"] == 0
    assert out["summary"]["evaluated"] == 0


def test_run_json_keeps_every_finding_key():
    f = _finding()
    assert json.loads(render_json(_run(findings=[f])))["findings"][0] == f


def test_run_json_redacts_secrets():
    spec = {"kind": "openai_compat", "endpoint_url": "https://x", "api_key": "sk-SECRET",
            "extra_headers": [["Authorization", "Bearer SECRET2"], ["X-Trace", "abc"]]}
    text = render_json(_run(target_spec=spec))
    assert "SECRET" not in text
    out = json.loads(text)["target_spec"]
    assert out["api_key"] == "***"
    assert out["extra_headers"] == [["Authorization", "***"], ["X-Trace", "***"]]
    assert out["endpoint_url"] == "https://x"


def test_redact_key_names_nested_and_header_dicts():
    spec = {"kind": "payment_agent", "inner": {"access_token": "t1", "db_password": "p1",
                                              "headers": {"X-Api": "h1"}, "model": "m"},
            "upload_headers": [["Cookie", "c1"]], "client_secret": "s1", "hmac_key": "k1"}
    out = redact(spec)
    assert out["inner"] == {"access_token": "***", "db_password": "***",
                            "headers": {"X-Api": "***"}, "model": "m"}
    assert out["upload_headers"] == [["Cookie", "***"]]
    assert out["client_secret"] == "***" and out["hmac_key"] == "***"
    assert out["kind"] == "payment_agent"


def test_run_json_serialises_odd_evidence():
    ev = {"at": datetime(2026, 1, 1, tzinfo=timezone.utc), "id": UUID(int=1), "raw": b"\x00ok"}
    out = json.loads(render_json(_run(findings=[_finding(evidence=ev)])))
    assert out["findings"][0]["evidence"]["at"] == "2026-01-01T00:00:00+00:00"
    assert out["findings"][0]["evidence"]["id"] == str(UUID(int=1))
    assert out["findings"][0]["evidence"]["raw"] == "\x00ok"


def test_redact_does_not_mutate_input():
    spec = {"api_key": "k"}
    redact(spec)
    assert spec == {"api_key": "k"}


def test_load_target_spec_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_KEY", "qs-SECRET-123")
    path = _spec_file(tmp_path, {"kind": "openai_compat", "endpoint_url": "https://x?k=${ARGUS_T_KEY}", "model": "m"})
    spec, secrets = load_target_spec_with_secrets(path)
    assert spec == load_target_spec(path)
    assert secrets == ["qs-SECRET-123"]


def test_loader_reports_each_value_once_and_skips_unset_and_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_A", "aaa")
    monkeypatch.setenv("ARGUS_T_EMPTY", "")
    monkeypatch.delenv("ARGUS_T_UNSET", raising=False)
    spec, secrets = load_target_spec_with_secrets(_spec_file(tmp_path, {
        "kind": "openai_compat", "endpoint_url": "https://x/$ARGUS_T_A/${ARGUS_T_A}/$ARGUS_T_UNSET/$ARGUS_T_EMPTY",
        "model": "m"}))
    assert spec["endpoint_url"] == "https://x/aaa/aaa/$ARGUS_T_UNSET/"
    assert secrets == ["aaa"]


def test_secret_in_endpoint_url_query_string(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_KEY", "qs-SECRET-123")
    spec, secrets = load_target_spec_with_secrets(_spec_file(tmp_path, {
        "kind": "openai_compat", "endpoint_url": "https://x/v1?key=${ARGUS_T_KEY}", "model": "m"}))
    text = render_json(_run(target_spec=spec), secret_values=secrets)
    assert "qs-SECRET-123" not in text
    assert json.loads(text)["target_spec"]["endpoint_url"] == "https://x/v1?key=***"


def test_secret_in_custom_http_body_template(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_TOKEN", 'tok-"SECRET"\\456')
    spec, secrets = load_target_spec_with_secrets(_spec_file(tmp_path, {
        "kind": "custom_http", "request_url": "https://x",
        "request_body_template": '{"auth": "$ARGUS_T_TOKEN", "q": "{{prompt}}"}',
        "response_jsonpath": "$.answer"}))
    text = render_json(_run(target_spec=spec), secret_values=secrets)
    assert "SECRET" not in text
    assert json.loads(text)["target_spec"]["request_body_template"] == '{"auth": "***", "q": "{{prompt}}"}'


def test_secret_echoed_in_target_response(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_KEY", "sk-ECHO-789")
    spec, secrets = load_target_spec_with_secrets(_spec_file(tmp_path, {
        "kind": "openai_compat", "endpoint_url": "https://x", "model": "m", "api_key": "${ARGUS_T_KEY}"}))
    f = _finding(target_response="my key is sk-ECHO-789, do not share")
    text = render_json(_run(target_spec=spec, findings=[f]), secret_values=secrets)
    assert "sk-ECHO-789" not in text
    assert json.loads(text)["findings"][0]["target_response"] == "my key is ***, do not share"


def test_secret_in_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_KEY", "sk-EVID-000")
    spec, secrets = load_target_spec_with_secrets(_spec_file(tmp_path, {
        "kind": "openai_compat", "endpoint_url": "https://x", "model": "m", "api_key": "${ARGUS_T_KEY}"}))
    ev = {"tool_calls": [{"name": "http", "args": {"headers": {"X-Key": "sk-EVID-000"}}}], "raw": b"sk-EVID-000",
          "sk-EVID-000": "as a key"}
    text = render_json(_run(target_spec=spec, findings=[_finding(evidence=ev)]), secret_values=secrets)
    assert "sk-EVID-000" not in text
    assert json.loads(text)["findings"][0]["evidence"]["raw"] == "***"


def test_longest_secret_replaced_first_and_version_fields_untouched():
    text = render_json(_run(findings=[_finding(target_response="abcdef")]), secret_values=["abc", "abcdef", "1", ""])
    out = json.loads(text)
    assert out["findings"][0]["target_response"] == "***"
    assert out["schema_version"] == "argus.run/1"


def test_cli_writes_redacted_run_json(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_T_KEY", "sk-CLI-111")

    async def _echo(target, probe_ids, **kw):
        yield {**FAIL_FINDING, "target_response": f"leaked {target['api_key']}"}
        yield {"type": "coverage", "coverage": {"thin_threshold": 2, "standards": {}}}

    _install_fake_engine(monkeypatch, _echo)
    target = _spec_file(tmp_path, {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m",
                                   "api_key": "${ARGUS_T_KEY}"})
    out = tmp_path / "run.json"
    result = CliRunner().invoke(main, ["run", "--local", "--target", target, "--probes", "all",
                                       "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert "sk-CLI-111" not in text
    data = json.loads(text)
    assert list(data.keys()) == TOP_LEVEL_KEYS
    assert data["findings"][0]["target_response"] == "leaked ***"


def test_cost_abort_writes_the_findings_so_far_marked_incomplete(tmp_path, monkeypatch):
    async def _cost_after_first(target, probe_ids, **kw):
        yield FAIL_FINDING
        raise _LocalRunError("daily cap crossed", "cost")

    _install_fake_engine(monkeypatch, _cost_after_first)
    target = _spec_file(tmp_path, {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"})
    result = CliRunner().invoke(main, ["run", "--local", "--target", target, "--probes", "all",
                                       "--format", "json", "--out", str(tmp_path / "run.json")])
    assert result.exit_code == 4
    record = json.loads((tmp_path / "run.json").read_text())
    assert record["status"] == "incomplete"
    assert len(record["findings"]) == 1
    assert record["summary"]["total"] == 1
    assert record["summary"]["by_verdict"]["fail"] == 1
    assert record["summary"]["failed_by_severity"]["critical"] == 1


def test_json_format_needs_local(tmp_path):
    target = _spec_file(tmp_path, {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"})
    result = CliRunner().invoke(main, ["run", "--target", target, "--probes", "all", "--format", "json",
                                       "--out", str(tmp_path / "run.json"), "--api-url", "https://a", "--token", "t"])
    assert result.exit_code == 2
    assert "--format json needs --local" in result.output


def test_key_name_rule_survives_env_value_inside_key_name():
    out = json.loads(render_json(_run(target_spec={"kind": "x", "api_key": "literal-sk"}), secret_values=["key"]))
    assert "literal-sk" not in json.dumps(out)


def test_unknown_evidence_type_is_stringified():
    from decimal import Decimal
    out = json.loads(render_json(_run(findings=[_finding(evidence={"amount": Decimal("1.50")})])))
    assert out["findings"][0]["evidence"]["amount"] == "1.50"


def test_literal_secrets_echoed_by_target_are_masked():
    spec = {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m", "api_key": "sk-LIT-AAA",
            "extra_headers": [["Authorization", "Bearer LIT-BBB"]]}
    f = _finding(target_response="key sk-LIT-AAA and token LIT-BBB",
                 evidence={"echo": ["Bearer LIT-BBB", {"k": "sk-LIT-AAA"}]})
    text = render_json(_run(target_spec=spec, findings=[f]))
    assert "LIT-AAA" not in text and "LIT-BBB" not in text
    assert json.loads(text)["findings"][0]["target_response"] == "key *** and token ***"


def test_one_char_secret_does_not_mangle_structural_fields():
    f = _finding(id="a1a1", probe_id="owasp_01_a", verdict="fail", severity="high", target_response="a1",
                 judge_model="gpt-5.4-mini", escalated_model="gpt-5.4")
    run = _run(target_spec={"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"}, findings=[f])
    out = json.loads(render_json(run, secret_values=["a", "1", "4"]))
    assert out["id"] == run["id"] and out["status"] == "completed"
    assert out["started_at"] == run["started_at"] and out["finished_at"] == run["finished_at"]
    assert out["target_spec"]["kind"] == "openai_compat"
    got = out["findings"][0]
    for k in ("id", "probe_id", "verdict", "severity", "probed_at", "created_at", "confidence",
              "judge_model", "escalated_model"):
        assert got[k] == f[k], k
    assert got["target_response"] == "******"


def test_key_name_rule_is_case_insensitive_and_skips_token_counters():
    out = redact({"apiKey": "s1", "API_KEY": "s2", "Authorization": "s3", "sessionCookie": "s4",
                  "credentials": {"u": "s5"}, "accessToken": "s6", "max_tokens": 512, "num_tokens": 3,
                  "Extra_Headers": [["X-A", "s7"]], "model": "m"})
    assert out == {"apiKey": "***", "API_KEY": "***", "Authorization": "***", "sessionCookie": "***",
                   "credentials": "***", "accessToken": "***", "max_tokens": 512, "num_tokens": 3,
                   "Extra_Headers": [["X-A", "***"]], "model": "m"}


def test_loader_records_windows_percent_vars(monkeypatch):
    import ntpath
    import os
    import posixpath
    monkeypatch.setenv("ARGUS_T_WIN", "win-SECRET-1")
    monkeypatch.setattr(posixpath, "expandvars", ntpath.expandvars)
    monkeypatch.setattr(os, "name", "nt")
    spec, secrets = load_target_spec_with_secrets(
        '{"kind": "openai_compat", "endpoint_url": "https://x?k=%ARGUS_T_WIN%", "model": "m"}')
    monkeypatch.undo()
    assert spec["endpoint_url"] == "https://x?k=win-SECRET-1"
    assert secrets == ["win-SECRET-1"]


@pytest.mark.parametrize("fmt", ["html", "sarif", "junit", "json"])
def test_every_format_masks_env_and_literal_secrets(tmp_path, monkeypatch, fmt):
    monkeypatch.setenv("ARGUS_T_KEY", "sk-FMT-ENV")

    async def _echo(target, probe_ids, **kw):
        yield {**FAIL_FINDING, "target_response": f"{target['api_key']} {target['extra_headers'][0][1]}",
               "reasoning": "saw sk-FMT-ENV and FMT-LIT"}
        yield {"type": "coverage", "coverage": {"thin_threshold": 2, "standards": {}}}

    _install_fake_engine(monkeypatch, _echo)
    target = _spec_file(tmp_path, {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m",
                                   "api_key": "${ARGUS_T_KEY}", "extra_headers": [["X-Auth", "Bearer FMT-LIT"]]})
    out = tmp_path / f"report.{fmt}"
    result = CliRunner().invoke(main, ["run", "--local", "--target", target, "--probes", "all",
                                       "--format", fmt, "--out", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert FAIL_FINDING["probe_id"] in text
    assert "sk-FMT-ENV" not in text and "FMT-LIT" not in text


def test_key_rule_matches_camel_and_compact_forms():
    out = redact({"privateKey": "s1", "accessKey": "s2", "clientSecret": "s3", "auth_header": "s4",
                  "authHeader": "s5", "api-key": "s6", "max_tokens": 512, "num_tokens": 3, "kind": "x"})
    assert out == {"privateKey": "***", "accessKey": "***", "clientSecret": "***", "auth_header": "***",
                   "authHeader": "***", "api-key": "***", "max_tokens": 512, "num_tokens": 3, "kind": "x"}


def test_evidence_keys_that_mask_alike_are_both_kept():
    ev = {"sk-AAA": "first", "sk-BBB": "second"}
    out = json.loads(render_json(_run(findings=[_finding(evidence=ev)]), secret_values=["sk-AAA", "sk-BBB"]))
    assert out["findings"][0]["evidence"] == {"***": "first", "***#2": "second"}


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_compliance_ids_and_coverage_survive_digit_secrets(tmp_path, monkeypatch, fmt):
    monkeypatch.setenv("ARGUS_T_ONE", "1")
    monkeypatch.setenv("ARGUS_T_ZERO", "0")
    cov = {"thin_threshold": 2, "standards": {"owasp_llm": {"LLM01": 1}, "atlas": {"AML.T0051": 1}}}

    async def _run_ids(target, probe_ids, **kw):
        yield {**FAIL_FINDING, "owasp_id": ["LLM01"], "owasp_agentic": ["ASI01"], "atlas_id": ["AML.T0051"], "nist_id": ["MS-2.10"],
               "eu_ai_act_id": ["Art.10"]}
        yield {"type": "coverage", "coverage": cov}

    _install_fake_engine(monkeypatch, _run_ids)
    target = _spec_file(tmp_path, {"kind": "openai_compat", "endpoint_url": "https://x:$ARGUS_T_ONE$ARGUS_T_ZERO",
                                   "model": "m"})
    out = tmp_path / f"r.{fmt}"
    result = CliRunner().invoke(main, ["run", "--local", "--target", target, "--probes", "all",
                                       "--format", fmt, "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    if fmt == "json":
        f = data["findings"][0]
        assert (f["owasp_id"], f["atlas_id"], f["nist_id"], f["eu_ai_act_id"]) == (
            ["LLM01"], ["AML.T0051"], ["MS-2.10"], ["Art.10"])
        assert data["coverage"] == cov
        assert f["owasp_agentic"] == ["ASI01"]
    else:
        run = data["runs"][0]
        props = run["tool"]["driver"]["rules"][0]["properties"]
        assert props["owasp_llm"] == ["LLM01"] and props["atlas"] == ["AML.T0051"]
        assert props["owasp_agentic"] == ["ASI01"]
        assert run["properties"]["coverage"] == cov


def test_run_json_masks_event_text_but_keeps_graph_ids():
    from argus.events import validate_events

    events = [
        {"event_id": "t1:E2", "parent_event_ids": [], "ts": "2026-11-01T04:10:24.123Z",
         "actor": "planner", "operation": "invoke_agent", "tool_name": None, "tool_call_id": "M9",
         "object_ref": "a2a.message:M9", "basis": "reported", "atlas_technique": "AML.T0051",
         "source": "a2a_world", "summary": "planner invoke_agent a2a.message", "seq": 0},
        {"event_id": "t1:E3", "parent_event_ids": ["t1:E2"], "ts": None,
         "actor": "executor", "operation": "execute_tool", "tool_name": "pay_invoice", "tool_call_id": None,
         "object_ref": None, "basis": "observed", "atlas_technique": None,
         "source": "a2a_world", "summary": "executor execute_tool pay_invoice", "seq": 1},
    ]
    secrets = ["E2", "M9", "planner", "invoke_agent", "pay_invoice", "reported", "a2a_world", "AML.T0051", "2026"]
    out = json.loads(render_json(_run(findings=[_finding(events=events)]), secret_values=secrets))
    got = out["findings"][0]["events"]
    assert [e["event_id"] for e in got] == ["t1:E2", "t1:E3"]
    assert got[1]["parent_event_ids"] == ["t1:E2"]
    assert got[0]["object_ref"] == "a2a.message:***"
    assert got[0]["actor"] == "***" and "planner" not in got[0]["summary"]
    assert got[0]["tool_call_id"] == "***" and got[1]["tool_name"] == "***"
    assert [e["seq"] for e in got] == [0, 1]
    assert got[0]["ts"] == "2026-11-01T04:10:24.123Z"
    assert got[0]["atlas_technique"] == "AML.T0051"
    assert validate_events(got) is None


def test_run_json_masked_object_kind_becomes_null():
    from dataclasses import asdict
    from argus.events import new_event, validate_events

    event = new_event(event_id="E1", parent_event_ids=[], ts=None, actor="planner", operation="invoke_agent",
                      basis="reported", source="a2a_world", object_ref="a2a.message:M9")
    out = json.loads(render_json(_run(findings=[_finding(events=[asdict(event)])]), secret_values=["a2a.message"]))
    events = out["findings"][0]["events"]
    assert events[0]["object_ref"] is None
    assert "a2a.message" not in events[0]["summary"]
    assert validate_events(events) is None


def test_run_json_clips_summary_after_secret_masking():
    from dataclasses import asdict
    from argus.events import new_event, validate_events

    event = new_event(event_id="E1", parent_event_ids=[], ts=None, actor="a" * 190, operation="invoke_agent",
                      basis="observed", source="a2a_world")
    out = json.loads(render_json(_run(findings=[_finding(events=[asdict(event)])]), secret_values=["a"]))
    events = out["findings"][0]["events"]
    assert len(events[0]["summary"]) == 200
    assert events[0]["actor"] == "***" * 190
    assert validate_events(events) is None
