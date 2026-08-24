"""MCP 探针族的结构约束。"""
from pathlib import Path

from orchestrator.redteam.probe import load_all_probes

MCP_DIR = Path(__file__).resolve().parent.parent / "orchestrator" / "redteam" / "probes" / "mcp"
SCENARIOS = {"tool_poisoning", "rug_pull", "shadowing", "confused_deputy", "credential_lure"}
MCP_ASSERTIONS = {"no_call_to_tool", "no_secret_in_tool_args",
                  "no_call_after_description_change", "max_tool_calls"}


def _mcp():
    return [p for p in load_all_probes(MCP_DIR)]


def test_twelve_probes_load():
    assert len(_mcp()) == 12


def test_every_probe_targets_only_the_instrumented_server():
    for p in _mcp():
        assert p.target_class == ("mcp_agent",), p.id


def test_every_probe_carries_assertions_so_no_judge_is_needed():
    for p in _mcp():
        assert p.assertions, p.id
        for entry in p.assertions:
            assert set(entry) <= MCP_ASSERTIONS, p.id


def test_every_probe_requires_interaction():
    """没跑到就是 error,不是 pass。缺这个标志就会假绿。"""
    for p in _mcp():
        assert p.requires_interaction is True, p.id


def test_every_prompt_carries_the_mcp_url_placeholder():
    for p in _mcp():
        assert any("{mcp_url}" in s for s in p.prompts), p.id


def test_scenario_kinds_are_all_implemented():
    for p in _mcp():
        assert p.scenario_kind in SCENARIOS, f"{p.id}: {p.scenario_kind}"


def test_mappings_are_not_all_the_same_cell():
    """全填 LLM01 会把覆盖率清单变成噪音。"""
    cells = {c for p in _mcp() for c in p.mappings.owasp_llm}
    assert len(cells) >= 3, cells


def test_mcp_suite_is_derived():
    from orchestrator.redteam.suites import derive_suites
    suites = derive_suites(_mcp())
    assert len(suites["mcp"]) == 12
