"""The 11 mcp_scan probes: ids, severities and the runner skip for every other target."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import argus
from argus.probe import load_all_probes
from argus.runner import Runner

SCAN_DIR = Path(argus.__file__).parent / "probes" / "mcp_scan"
EXPECTED = {"mcp_scan_description_instructions": "high", "mcp_scan_schema_instructions": "high",
            "mcp_scan_hidden_characters": "high", "mcp_scan_command_execution": "critical",
            "mcp_scan_path_traversal": "high", "mcp_scan_secret_in_result": "high",
            "mcp_scan_result_injection": "high", "mcp_scan_cross_session_leak": "medium",
            "mcp_scan_input_reflection": "low", "mcp_scan_tool_list_changed": "medium",
            "mcp_scan_readonly_tool_wrote": "high"}


def test_eleven_scan_probes_with_spec_severities():
    probes = {p.id: p for p in load_all_probes(SCAN_DIR)}
    assert {k: p.severity for k, p in probes.items()} == EXPECTED
    assert all(p.target_class == ("mcp_scan",) and "mcp-abuse" in p.attack_class for p in probes.values())


INJ = (["AML.T0051.001"], ["LLM01"], ["MEASURE-2.6"], ["Article 15(3)"])
SRV = ["MEASURE-2.7"], ["Article 15(5)"]
MAPPINGS = {  # id -> (atlas, owasp_llm, nist_ai_rmf, eu_ai_act)
    "mcp_scan_description_instructions": INJ, "mcp_scan_schema_instructions": INJ,
    "mcp_scan_hidden_characters": INJ, "mcp_scan_result_injection": INJ,
    "mcp_scan_input_reflection": INJ,
    "mcp_scan_command_execution": (["AML.T0049"], ["LLM05", "LLM06"], *SRV),
    "mcp_scan_path_traversal": (["AML.T0049"], ["LLM02", "LLM06"], *SRV),
    "mcp_scan_secret_in_result": (["AML.T0055"], ["LLM02"], *SRV),
    "mcp_scan_cross_session_leak": (["AML.T0057"], ["LLM02"], *SRV),
    "mcp_scan_readonly_tool_wrote": (["AML.T0049"], ["LLM06"], *SRV),
    "mcp_scan_tool_list_changed": (["AML.T0010"], ["LLM03", "LLM06"],
                                   ["GOVERN-1.4", "MAP-5.1"], ["Article 15(2)", "Article 14"]),
}
EXTRA_CLASS = {
    "mcp_scan_description_instructions": "indirect-injection", "mcp_scan_schema_instructions": "indirect-injection",
    "mcp_scan_hidden_characters": "indirect-injection", "mcp_scan_result_injection": "indirect-injection",
    "mcp_scan_input_reflection": "indirect-injection", "mcp_scan_command_execution": "tool-abuse",
    "mcp_scan_path_traversal": "tool-abuse", "mcp_scan_secret_in_result": "credential-extraction",
    "mcp_scan_cross_session_leak": "data-exfil", "mcp_scan_tool_list_changed": "supply-chain",
    "mcp_scan_readonly_tool_wrote": "excessive-agency",
}


def test_scan_probe_mappings_and_attack_class_are_exact():
    probes = {p.id: p for p in load_all_probes(SCAN_DIR)}
    assert set(MAPPINGS) == set(probes)
    for pid, p in probes.items():
        m = p.mappings
        assert (list(m.atlas), list(m.owasp_llm), list(m.nist_ai_rmf), list(m.eu_ai_act)) == MAPPINGS[pid], pid
        assert EXTRA_CLASS[pid] in p.attack_class, pid


def test_scan_probes_use_the_tool_output_rubric_and_no_assertions():
    for p in list(load_all_probes(SCAN_DIR)):
        assert p.judge_rubric_path == "rubrics/mcp_tool_output_injection.md"
        assert not p.assertions
        assert p.requires_interaction is False
        assert len(p.prompts) == 1 and p.prompts[0].startswith("scan-mcp check: ")
        assert (Path(argus.__file__).parent / p.judge_rubric_path).exists()


@pytest.mark.asyncio
async def test_scan_probes_are_skipped_for_every_other_target():
    target = AsyncMock()
    target.compatible_classes = frozenset({"llm_chat", "agent_with_tools"})
    target.send_prompt = AsyncMock(return_value=("hi", 1.0))
    runner = Runner(target=target, judge=MagicMock(), rubrics_dir=Path(argus.__file__).parent / "rubrics")
    probes = list(load_all_probes(SCAN_DIR))
    assert len(probes) == 11
    for probe in probes:
        findings = [f async for f in runner.run_probe(probe)]
        assert [f.verdict for f in findings] == ["skipped"], probe.id
    target.send_prompt.assert_not_called()
