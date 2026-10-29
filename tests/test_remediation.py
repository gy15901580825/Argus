"""Remediation text per attack_class, and where every report format shows it."""
import json
from xml.etree import ElementTree as ET

import pytest

from argus import remediation
from argus.api import PROBES_DIR
from argus.cli import reports, run_json
from argus.probe import VALID_ATTACK_CLASSES, load_probe_library

TEXT = remediation.table()


def test_every_attack_class_has_remediation():
    assert set(TEXT) == set(VALID_ATTACK_CLASSES)


def test_every_attack_class_in_the_library_has_remediation():
    used = {c for p in load_probe_library(PROBES_DIR) for c in p.attack_class}
    assert used, "no probes loaded"
    missing = sorted(c for c in used if not TEXT.get(c, "").strip())
    assert not missing, f"attack_class without remediation in argus/data/remediation.yaml: {missing}"


@pytest.mark.parametrize("cls", sorted(VALID_ATTACK_CLASSES))
def test_remediation_text_is_short_plain_and_has_no_dashes(cls):
    text = TEXT[cls]
    assert 40 <= len(text) <= 400, (cls, len(text))
    assert "—" not in text and "–" not in text, cls


def test_for_classes_keeps_probe_order_and_drops_repeats():
    assert remediation.for_classes(["mcp-abuse", "data-exfil", "mcp-abuse"]) == (
        TEXT["mcp-abuse"].strip() + "\n" + TEXT["data-exfil"].strip())
    assert remediation.for_classes([]) == ""


def _run(**finding):
    base = {"id": "f1", "probe_id": "mcp_poison_description_exfil", "verdict": "fail", "severity": "high",
            "confidence": 1.0, "reasoning": "called exfil_notes", "attack_prompt": "p", "target_response": "r",
            "target_latency_ms": 1.0, "judge_model": "", "escalated_model": None, "atlas_id": [],
            "owasp_id": [], "nist_id": [], "eu_ai_act_id": [], "evidence": None,
            "remediation": "Connect only to approved MCP servers."}
    return {"id": "11111111-2222", "status": "completed", "target_spec": {"kind": "mcp_agent"},
            "coverage": None, "findings": [{**base, **finding}]}


def test_html_shows_remediation_for_a_failure():
    html = reports.render_html(_run())
    assert "How to fix" in html and "Connect only to approved MCP servers." in html


def test_html_leaves_remediation_out_of_a_pass():
    assert "How to fix" not in reports.render_html(_run(verdict="pass"))


def test_sarif_rule_help_is_the_remediation():
    rule = json.loads(reports.render_sarif(_run()))["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["help"] == {"text": "Connect only to approved MCP servers."}


def test_sarif_rule_has_no_help_without_remediation():
    rule = json.loads(reports.render_sarif(_run(remediation="")))["runs"][0]["tool"]["driver"]["rules"][0]
    assert "help" not in rule


def test_junit_failure_carries_remediation():
    failure = ET.fromstring(reports.render_junit(_run()).split("\n", 1)[1]).find("testsuite/testcase/failure")
    assert failure.text.endswith("remediation: Connect only to approved MCP servers.")


def test_run_json_keeps_remediation_unmasked():
    # A short substituted env value ("MCP") must not mangle engine-written text.
    out = json.loads(run_json.render_json(_run(), secret_values=["MCP"]))
    assert out["findings"][0]["remediation"] == "Connect only to approved MCP servers."


def test_mcp_scan_and_mcp_trap_findings_carry_remediation():
    from argus.mcp_scan.findings import finding as scan_finding
    from argus.mcp_trap.driver import RoundOutcome, load_trap_probes, scenario_finding

    scan_probe = next(p for p in load_probe_library(PROBES_DIR) if p.id == "mcp_scan_command_execution")
    f = scan_finding(scan_probe, verdict="pass", severity="info", reasoning="r", evidence={})
    assert f["remediation"] == remediation.for_classes(scan_probe.attack_class) != ""

    trap_probe = load_trap_probes(["rug_pull"])[0]
    t = scenario_finding(trap_probe, [RoundOutcome(1, "failed", "sent", "p", "r", {"interaction_count": 1})], 1)
    assert t["remediation"] == remediation.for_classes(trap_probe.attack_class) != ""
