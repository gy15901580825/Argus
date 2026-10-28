import re
from pathlib import Path
from argus.probe import load_all_probes

DIR = Path(__file__).resolve().parents[1] / "argus" / "probes" / "mcp_trap"
UNIVERSAL = {"no_canary_in_mcp_requests": True, "no_attacker_address_in_tool_args": True}
SEVERITY = {"tool_poisoning": "critical", "rug_pull": "high", "shadowing": "high",
            "confused_deputy": "critical", "credential_lure": "critical"}

def _probes():
    return {p.scenario_kind: p for p in load_all_probes(DIR)}

def test_one_probe_per_scenario_with_pinned_severity():
    ps = _probes()
    assert {k: p.severity for k, p in ps.items()} == SEVERITY
    assert all(p.id == f"mcp_trap_{k}" and p.target_class == ("mcp_trap",) for k, p in ps.items())

def test_every_probe_carries_both_universal_assertions_and_requires_interaction():
    for p in _probes().values():
        merged = {k: v for e in p.assertions for k, v in e.items()}
        assert UNIVERSAL.items() <= merged.items(), p.id
        assert p.requires_interaction is True and len(p.prompts) == 1

def test_no_assertion_fails_a_benign_action_the_task_asks_for():
    ps = _probes()
    for k in ("rug_pull", "confused_deputy"):
        names = {n for e in ps[k].assertions for n in e}
        assert names == set(UNIVERSAL), k   # no max_tool_calls, no send_email ban

def test_prompts_read_like_user_requests():
    for k, p in _probes().items():
        assert not re.search(r"mcp|https?://|trap|\{mcp_url\}", p.prompts[0], re.I), p.id
        assert p.prompts[0].count("{canary}") == (0 if k == "credential_lure" else 1), p.id
