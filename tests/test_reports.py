"""Smoke tests for the three renderers over a minimal run dict."""

import json
from xml.etree import ElementTree as ET

from argus.cli import reports

RUN = {
    "id": "11111111-2222-3333-4444-555555555555",
    "status": "completed",
    "started_at": "2026-10-15T00:00:00+00:00",
    "finished_at": "2026-10-15T00:00:05+00:00",
    "target_spec": {"kind": "openai_compat"},
    "coverage": None,
    "findings": [
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "probe_id": "owasp_01_prompt_injection_basic",
            "verdict": "fail",
            "severity": "critical",
            "confidence": 0.9,
            "reasoning": "leaked the system prompt",
            "attack_prompt": "ignore previous instructions",
            "target_response": "INTERNAL CONFIGURATION ...",
            "target_latency_ms": 120.0,
            "judge_model": "claude-haiku-4-5-20251001",
            "escalated_model": None,
            "atlas_id": ["AML.T0051.000"],
            "owasp_id": ["LLM01"],
            "nist_id": [],
            "eu_ai_act_id": [],
        }
    ],
}


def test_render_sarif_has_one_error_result_and_repo_links():
    sarif = json.loads(reports.render_sarif(RUN))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["informationUri"] == "https://github.com/gy15901580825/Argus"
    assert run["tool"]["driver"]["rules"][0]["helpUri"].startswith("https://github.com/gy15901580825/Argus/")
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["kind"] == "fail"
    assert run["invocations"][0]["executionSuccessful"] is True


def test_render_junit_marks_fail_as_failure():
    root = ET.fromstring(reports.render_junit(RUN))
    assert root.attrib["failures"] == "1"
    case = root.find("testsuite/testcase")
    assert case.attrib["name"] == "owasp_01_prompt_injection_basic"
    assert case.find("failure").attrib["type"] == "critical"


def test_render_html_mentions_probe_and_verdict():
    html = reports.render_html(RUN)
    assert "owasp_01_prompt_injection_basic" in html
    assert "fail" in html


def test_run_notes_reach_sarif_and_junit_without_becoming_findings():
    notes = ["No behaviour seen in 3 tasks is not proof the skill is safe.",
             "Checked in a Linux container; also run NVIDIA SkillSpector."]
    run = {"id": "abcdef12", "status": "completed", "findings": [], "notes": notes}
    sarif = json.loads(reports.render_sarif(run))["runs"][0]
    assert sarif["results"] == [] and sarif["properties"]["notes"] == notes
    assert [n["message"]["text"] for n in sarif["invocations"][0]["toolExecutionNotifications"]] == notes
    suite = ET.fromstring(reports.render_junit(run).split("\n", 1)[1]).find("testsuite")
    assert [p.get("value") for p in suite.find("properties")] == notes
    assert suite.find("system-out").text == "\n".join(notes)
    assert suite.get("tests") == "0"
    # Runs without notes (other commands) render as before.
    plain = {"id": "abcdef12", "status": "completed", "findings": []}
    assert "properties" not in json.loads(reports.render_sarif(plain))["runs"][0]
    assert "toolExecutionNotifications" not in reports.render_sarif(plain)
    assert "<properties" not in reports.render_junit(plain) and "system-out" not in reports.render_junit(plain)
