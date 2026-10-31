import importlib.util
from pathlib import Path
from argus import api
from argus.demo import servers
from argus.probe import load_probe_library

EXPECTED = {
    "memory_poison_tool_result": ["ASI06"],
    "memory_poison_delayed_trigger": ["ASI06"],
    "memory_instruction_persistence": ["ASI06"],
    "approval_forged_narration": ["ASI09"],
    "approval_substitution": ["ASI09"],
    "approval_denied_then_executed": ["ASI02"],
    "approval_skipped": ["ASI02"],
    "rogue_protected_resource": ["ASI10"],
    "rogue_monitor_tamper": ["ASI10"],
    "rogue_concealment_report": ["ASI10"],
    "rogue_test_tamper": ["ASI10"],
}


def library():
    return [p for p in load_probe_library(api.PROBES_DIR) if p.id in EXPECTED]


def mapper():
    spec = importlib.util.spec_from_file_location(
        "world_mapping",
        Path(__file__).parents[1] / "scripts/annotate_agentic_probes.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mcp_world_library_has_the_eleven_probes_with_design_mappings():
    probes = library()
    assert len(probes) == 11
    assert {p.id: list(p.mappings.owasp_agentic) for p in probes} == EXPECTED


def test_no_asi08_in_mcp_world():
    assert all("ASI08" not in p.mappings.owasp_agentic for p in library())


def test_every_session_first_prompt_names_mcp_url():
    assert library()
    assert all(
        session[0].startswith("Connect to the MCP server at {mcp_url}.")
        for p in library()
        for session in p.session_prompts
    )


def test_every_world_probe_is_phased_assertion_backed_unjudged():
    assert library() and all(
        p.is_phased and p.assertions and not p.needs_judge for p in library()
    )


def test_asi02_reasons_cite_precedent():
    approved = mapper().APPROVED
    for pid in ["approval_skipped", "approval_denied_then_executed"]:
        assert (
            "pay_approval_forged" in approved[pid]["reason"]
            and "bypassing a gate" in approved[pid]["reason"]
        )


def test_scope_notes():
    for p in library():
        if "ASI06" in p.mappings.owasp_agentic:
            assert "Argus-hosted memory" in p.scope_note
        if "ASI09" in p.mappings.owasp_agentic:
            assert (
                "approval content integrity" in p.scope_note
                and "free-text" in p.scope_note
            )
        if "ASI10" in p.mappings.owasp_agentic:
            assert not any(
                word in p.scope_note.lower() for word in ["malicious", "rogue"]
            )


def test_mcp_probe_ids_unchanged():
    assert len(servers.PROBE_IDS) == 12 and not set(servers.PROBE_IDS) & set(EXPECTED)
