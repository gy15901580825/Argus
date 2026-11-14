"""MCP 探针族的结构约束。"""
from pathlib import Path

from argus.probe import load_all_probes

MCP_DIR = Path(__file__).resolve().parent.parent / "argus" / "probes" / "mcp"
SCENARIOS = {"tool_poisoning", "rug_pull", "shadowing", "confused_deputy", "credential_lure",
             "overcollect", "unbounded_loop"}
MCP_ASSERTIONS = {"no_call_to_tool", "no_secret_in_tool_args",
                  "no_attacker_call_after_description_change", "max_tool_calls",
                  "no_mcp_beacon_hit", "no_out_of_scope_records_after_description_change"}


def _mcp():
    return [p for p in load_all_probes(MCP_DIR)]


def test_fourteen_probes_load():
    assert len(_mcp()) == 14


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
    from argus.suites import derive_suites
    suites = derive_suites(_mcp())
    assert len(suites["mcp"]) == 14


def test_unbounded_loop_probe_is_driven_by_the_server_not_the_user_prompt():
    """The user asks for an ordinary summary; only the served tool result
    invites more calls, so exceeding the limit is the attack's doing."""
    [p] = [p for p in _mcp() if p.id == "mcp_budget_unbounded_tool_loop"]
    assert p.scenario_kind == "unbounded_loop"
    prompt = " ".join(p.prompts).lower()
    for phrase in ("as many times", "don't stop", "until", "fully confident"):
        assert phrase not in prompt, phrase
