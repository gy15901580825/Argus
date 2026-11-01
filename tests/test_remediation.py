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


SERVER_CLASSES = {"a2a_server", "mcp_scan", "mcp_server", "vllm_server"}


def test_server_facing_probes_have_their_own_remediation():
    # Class text is written for someone who runs an agent; these findings go to a server owner.
    probes = [p for p in load_probe_library(PROBES_DIR) if SERVER_CLASSES & set(p.target_class)]
    assert len(probes) == 22
    missing = [p.id for p in probes if not p.remediation.strip()]
    assert not missing, missing
    for p in probes:
        assert remediation.for_probe(p) == p.remediation.strip()
        assert "\u2014" not in p.remediation and "\u2013" not in p.remediation, p.id


def test_for_probe_falls_back_to_the_class_text():
    p = next(p for p in load_probe_library(PROBES_DIR) if p.id == "mcp_poison_description_exfil")
    assert p.remediation == ""
    assert remediation.for_probe(p) == remediation.for_classes(p.attack_class) != ""


def test_load_probe_reads_remediation(tmp_path):
    from argus.probe import load_probe

    path = tmp_path / "p.yaml"
    path.write_text("id: p\nname: p\ntarget_class: [http-chat]\nattack_class: [jailbreak]\nseverity: low\n"
                    "prompts: [x]\nremediation: >-\n  Patch the thing.\n")
    assert load_probe(path).remediation == "Patch the thing."


def test_every_library_probe_gets_remediation():
    empty = [p.id for p in load_probe_library(PROBES_DIR) if not remediation.for_probe(p)]
    assert not empty, f"probes whose findings would carry no remediation: {empty}"


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


def test_html_shows_remediation_for_a_warn():
    assert "Connect only to approved MCP servers." in reports.render_html(_run(verdict="warn"))


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
    assert f["remediation"] == remediation.for_probe(scan_probe) == scan_probe.remediation.strip() != ""

    trap_probe = load_trap_probes(["rug_pull"])[0]
    t = scenario_finding(trap_probe, [RoundOutcome(1, "failed", "sent", "p", "r", {"interaction_count": 1})], 1)
    assert t["remediation"] == remediation.for_probe(trap_probe) != ""


def test_scan_skill_findings_carry_an_empty_remediation():
    # docs/run-json.md promises the key on every finding; scan-skill rules are not library probes.
    from argus.skillscan.scan import _normalise

    assert _normalise({"probe_id": "skill_exfiltration"}, "t")["remediation"] == ""
    assert _normalise({"probe_id": "x", "remediation": "keep"}, "t")["remediation"] == "keep"


def test_deep_mode_wrapper_keeps_the_probe_remediation():
    from argus.persona_loader import default_personas, default_strategies
    from argus.persona_strategy import build_deep_probes

    base = next(p for p in load_probe_library(PROBES_DIR) if p.id == "mcp_server_no_auth")
    from dataclasses import replace

    base = replace(base, remediation_actions=({"tier": "fix", "text": "Scope MCP tools.", "atlas_mitigation": None},))
    wrapped = build_deep_probes(base, default_personas(), default_strategies(), deep_pairs=2)
    assert wrapped
    assert all(remediation.for_probe(w) == remediation.for_probe(base) == base.remediation.strip() for w in wrapped)
    assert all(remediation.actions_for_probe(w) == remediation.actions_for_probe(base) for w in wrapped)
