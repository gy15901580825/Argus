"""Reviewed tool-poisoning probes appear under their ATLAS coverage labels."""
from pathlib import Path

import pytest

from argus.coverage import build_coverage
from argus.probe import load_all_probes


@pytest.mark.parametrize("technique_id,expected_probe_ids", [
    ("AML.T0110.000", {
        "mcp_credential_lure_api_key",
        "mcp_credential_lure_compliance_framing",
        "mcp_cross_server_mail_redirect",
        "mcp_poison_description_exfil",
        "mcp_poison_description_multi_turn",
        "mcp_poison_non_english",
        "mcp_rugpull_after_relist",
        "mcp_rugpull_overcollect",
        "mcp_rugpull_silent_escalation",
        "mcp_scan_description_instructions",
        "mcp_scan_hidden_characters",
        "mcp_scan_schema_instructions",
        "mcp_scan_tool_list_changed",
        "mcp_shadow_claims_newer_version",
        "mcp_shadow_near_name",
        "mcp_trap_credential_lure",
        "mcp_trap_rug_pull",
        "mcp_trap_shadowing",
        "mcp_trap_tool_poisoning",
    }),
    ("AML.T0110.002", {
        "approval_forged_narration",
        "approval_skipped",
        "approval_substitution",
        "mcp_confused_deputy_chained_forward",
        "mcp_confused_deputy_result_injection",
        "mcp_forged_reasoning_result_injection",
        "mcp_forged_reasoning_result_injection_control",
        "mcp_os_cmd_result_injection",
        "mcp_resource_embedded_injection",
        "mcp_scan_input_reflection",
        "mcp_scan_result_injection",
        "mcp_trap_confused_deputy",
        "memory_instruction_persistence",
        "memory_poison_delayed_trigger",
        "memory_poison_tool_result",
        "rogue_protected_resource",
        "rogue_test_tamper",
    }),
])
def test_reviewed_tool_poisoning_probes_are_discoverable_in_atlas_coverage(technique_id, expected_probe_ids):
    probes = list(load_all_probes(Path(__file__).resolve().parents[1] / "argus/probes"))
    assert {probe.id for probe in probes if technique_id in probe.mappings.atlas} == expected_probe_ids
    cells = build_coverage(probes)["standards"]["mitre-atlas"]["cells"]
    cell = next(cell for cell in cells if cell["id"] == technique_id)
    assert cell["probes_in_library"] == len(expected_probe_ids)
