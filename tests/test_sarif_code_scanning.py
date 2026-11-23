"""Code scanning contracts, using deterministic findings and no model calls."""

import hashlib
import json

import pytest
from click.testing import CliRunner

from argus.cli import reports, run_json
from argus.cli.__main__ import main
from argus.cli.baseline_key import baseline_key


def finding(probe="probe", verdict="fail", severity="critical", **extra):
    return {"probe_id": probe, "verdict": verdict, "severity": severity,
            "reasoning": "Observed a weakness", **extra}


def run(*findings, **extra):
    return {"id": "run-1", "status": "completed", "started_at": "2026-11-22T00:00:00Z",
            "finished_at": "2026-11-22T00:01:00Z",
            "target_spec": {"kind": "python", "name": "agent", "callable": "demo:reply"},
            "findings": list(findings), **extra}


def sarif(record, **kwargs):
    return json.loads(reports.render_sarif(record, **kwargs))["runs"][0]


def test_only_fail_and_warn_are_alerts_and_all_verdicts_are_counted():
    verdicts = ["pass", "fail", "warn", "error", "skipped", "blocked_by_target", "aborted_cost"]
    output = sarif(run(*(finding(v, v) for v in verdicts),
                       coverage={"standards": {}}, notes=["Run caveat"]))
    assert [(r["ruleId"], r["level"], r["kind"]) for r in output["results"]] == [
        ("fail", "error", "fail"), ("warn", "warning", "review")]
    assert output["properties"]["verdict_counts"] == dict.fromkeys(verdicts, 1)
    assert output["properties"]["coverage"] == {"standards": {}}
    assert output["properties"]["notes"] == ["Run caveat"]


def test_passing_critical_probe_has_no_result_and_zero_counts_are_present():
    output = sarif(run(finding(verdict="pass")))
    assert output["results"] == []
    assert output["properties"]["verdict_counts"] == {
        "pass": 1, "fail": 0, "warn": 0, "error": 0, "skipped": 0}


@pytest.mark.parametrize("severity,score,level", [
    ("critical", "9.5", "error"), ("high", "8.0", "error"),
    ("medium", "5.5", "warning"), ("low", "2.0", "note"), ("info", None, "note")])
def test_security_severity_and_failure_level(severity, score, level):
    output = sarif(run(finding(severity=severity)))
    properties = output["tool"]["driver"]["rules"][0]["properties"]
    assert properties.get("security-severity") == score
    assert ("security-severity" in properties) == (score is not None)
    assert "security" in properties["tags"]
    assert output["results"][0]["level"] == level


@pytest.mark.parametrize("severity", ["critical", "info"])
def test_warning_level_overrides_probe_severity(severity):
    assert sarif(run(finding(verdict="warn", severity=severity)))["results"][0]["level"] == "warning"


def test_fingerprints_use_probe_and_existing_target_baseline_key():
    record = run(finding("one"), finding("two"))
    record["baseline_key"] = baseline_key(record["target_spec"])
    first = sarif(record)["results"]
    second = sarif({**record, "id": "another-run", "started_at": "2026-11-23T00:00:00Z",
                    "finished_at": "2026-11-23T00:01:00Z"})["results"]
    assert [r["partialFingerprints"] for r in first] == [r["partialFingerprints"] for r in second]
    assert first[0]["partialFingerprints"] != first[1]["partialFingerprints"]
    expected = hashlib.sha256(json.dumps(["one", record["baseline_key"]]).encode()).hexdigest()
    assert first[0]["partialFingerprints"] == {"primaryLocationLineHash": expected}
    assert sarif(run(finding("one")))["results"][0]["partialFingerprints"] == first[0]["partialFingerprints"]
    # The stored key survives masking of expanded public target fields.
    masked = {**record, "target_spec": {"kind": "python", "name": "***"}}
    assert sarif(masked)["results"][0]["partialFingerprints"] == first[0]["partialFingerprints"]
    other = run(finding("one"), target_spec={"kind": "python", "name": "different-agent"})
    assert sarif(other)["results"][0]["partialFingerprints"] != first[0]["partialFingerprints"]


def test_repeated_trials_are_one_alert_with_fail_and_highest_failure_winning():
    trials = [finding(verdict="warn", severity="critical"), finding(severity="low"),
              finding(severity="high"), finding(verdict="pass"), finding(verdict="error")]
    output = sarif(run(*trials))
    assert len(output["results"]) == 1
    result = output["results"][0]
    assert result["properties"]["verdict"] == "fail"
    assert result["properties"]["severity"] == "high"
    assert output["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    assert result["properties"]["trial_verdict_counts"] == {"fail": 2, "warn": 1, "pass": 1, "error": 1}
    assert result["partialFingerprints"] == sarif(run(*reversed(trials)))["results"][0]["partialFingerprints"]
    assert result["partialFingerprints"] == sarif(run(finding()))["results"][0]["partialFingerprints"]


def test_target_location_is_relative_and_uri_encoded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "specs" / "agent #1.json"
    output = sarif(run(finding()), target_path=str(target))
    assert output["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "specs/agent%20%231.json", "uriBaseId": "%SRCROOT%"}
    assert output["originalUriBaseIds"]["%SRCROOT%"]["uri"] == tmp_path.as_uri() + "/"
    assert output["automationDetails"] == sarif(run(finding()), target_path="specs/agent #1.json")["automationDetails"]
    assert output["automationDetails"]["id"].endswith("/")
    assert output["automationDetails"] != sarif(run(finding()), target_path="specs/other.json")["automationDetails"]


def test_unknown_or_outside_target_location_has_documented_fallback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    record = run(finding())
    outside = sarif(record, target_path=str(tmp_path.parent / "outside.json"))
    unknown = sarif(record)
    for output in (outside, unknown):
        assert output["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "target.json"
        assert "fallback" in output["properties"]["target_location_note"]
    assert unknown["automationDetails"] == sarif({**record, "id": "next"})["automationDetails"]
    assert unknown["automationDetails"] != sarif(run(finding(), target_spec={"name": "other"}))["automationDetails"]


def test_report_from_uses_fallback_without_adding_path_to_run_json(tmp_path):
    source = tmp_path / "run.json"
    source.write_text(run_json.render_json(run(finding())))
    output = tmp_path / "report.sarif"
    result = CliRunner().invoke(main, ["report", "--from", str(source), "--out", str(output)])
    assert result.exit_code == 0, result.output
    document = json.loads(output.read_text())["runs"][0]
    assert document["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "target.json"
    assert "fallback" in document["properties"]["target_location_note"]
    assert "target_path" not in json.loads(source.read_text())


def test_optional_times_are_omitted_and_result_message_is_nonempty():
    output = sarif(run(finding(reasoning=""), started_at=None, finished_at=None))
    assert "startTimeUtc" not in output["invocations"][0]
    assert "endTimeUtc" not in output["invocations"][0]
    assert output["results"][0]["message"]["text"] == "Argus probe probe: fail"


def test_non_alert_evidence_notes_survive_without_creating_results():
    passed = finding("passed", "pass", evidence={"trap_requests": [],
        "model_egress_notes": ["model provider requests through the relay: observed"]})
    skipped = finding("skipped", "skipped", evidence={"trap_requests": [],
        "trace_egress_notes": ["OTLP trace export: not observable"]})
    output = sarif(run(passed, skipped, finding("failed")))
    assert [r["ruleId"] for r in output["results"]] == ["failed"]
    assert output["properties"]["evidence_notes"] == [
        {"probe_id": "passed", "verdict": "pass", "notes": passed["evidence"]["model_egress_notes"]},
        {"probe_id": "skipped", "verdict": "skipped", "notes": skipped["evidence"]["trace_egress_notes"]}]
