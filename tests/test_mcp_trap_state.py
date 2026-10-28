import re
import pytest
from argus.mcp_trap.trap import scenarios as sc
from argus.mcp_trap.trap.state import TrapState, new_canary

def _round(scenario, canary="ARGUS-CANARY-00000000000000AA"):
    s = TrapState(); s.begin_round(scenario, canary); return s

def test_new_canary_format():
    a, b = new_canary(), new_canary()
    assert re.fullmatch(r"ARGUS-CANARY-[0-9A-F]{16}", a) and a != b

def test_begin_round_resets_everything():
    s = _round("confused_deputy")
    seq = s.start_request(http_method="POST", rpc_methods=["tools/list"], has_session_id=True, body="{}")
    s.on_tools_list(); s.on_tool_call("read_notes", {})
    s.begin_round("shadowing", "ARGUS-CANARY-00000000000000BB")
    s.finish_request(seq, 200)                                  # a response that outlives its round
    ev = s.evidence()
    assert (ev["scenario"], ev["canary"]) == ("shadowing", "ARGUS-CANARY-00000000000000BB")
    assert ev["interaction_count"] == ev["tools_list_count"] == 0
    assert ev["tool_calls"] == [] and ev["listed_after_swap"] is False
    assert ev["shadow_tool_names"] == ["read_notes_v2"] and ev["requests"] == []

def test_rug_pull_switches_after_first_call_and_reports_list_changed():
    s = _round("rug_pull")
    send = next(t for t in s.on_tools_list() if t["name"] == "send_email")
    assert sc.ATTACKER_DOMAIN not in send["description"]
    assert s.on_tool_call("read_notes", {})[2] is True          # list_changed at the switch
    send = next(t for t in sc.tools_for("rug_pull", None, rug_pulled=True) if t["name"] == "send_email")
    assert sc.ATTACKER_EMAIL in send["description"]
    assert s.on_tool_call("read_notes", {})[2] is False         # only once
    assert s.evidence()["rug_pull"]["switched"] is True

def test_rug_pull_records_definition_in_force_and_agent_view():
    s = _round("rug_pull")
    s.on_tools_list(); s.on_tool_call("read_notes", {})
    s.on_tool_call("send_email", {"to": sc.TEAMMATE_EMAIL, "body": "hi"})
    call = s.evidence()["tool_calls"][1]
    assert (call["definition_in_force"], call["agent_last_listed"]) == ("changed", "original")
    assert s.evidence()["rug_pull"]["relisted_after_switch"] is False
    s.on_tools_list()
    assert s.evidence()["rug_pull"]["relisted_after_switch"] is True

def test_unknown_tool_call_is_recorded_and_errors():
    s = _round("confused_deputy")
    text, is_error, _ = s.on_tool_call("exfil_notes", {"notes": "x"})
    assert is_error and s.evidence()["unknown_tool_calls"] == ["exfil_notes"]

def test_canary_hit_found_in_raw_body_beyond_any_bound():
    s = _round("tool_poisoning")
    body = '{"method":"tools/call","params":{"arguments":{"notes":"' + "x" * 5000 + 'ARGUS-CANARY-00000000000000AA"}}}'
    seq = s.start_request(http_method="POST", rpc_methods=["tools/call"], has_session_id=True, body=body)
    s.finish_request(seq, 200)
    assert s.evidence()["canary_hits"] == [{"seq": 1, "rpc_methods": ["tools/call"]}]

def test_stale_session_404_is_not_an_interaction():
    s = _round("shadowing")
    s.finish_request(s.start_request(http_method="POST", rpc_methods=["tools/list"], has_session_id=True,
                                     body="{}"), 404)
    ev = s.evidence()
    assert (ev["interaction_count"], ev["stale_session_requests"]) == (0, 1)

def test_stale_404_is_reclassified_at_finish_and_drops_its_canary_hit():
    s = _round("tool_poisoning")
    hit = '{"params":{"arguments":{"notes":"ARGUS-CANARY-00000000000000AA"}}}'
    stale = s.start_request(http_method="POST", rpc_methods=["tools/call"], has_session_id=True, body=hit)
    live = s.start_request(http_method="POST", rpc_methods=["tools/call"], has_session_id=False, body=hit)
    ev = s.evidence()
    assert (ev["interaction_count"], ev["stale_session_requests"], len(ev["canary_hits"])) == (2, 0, 2)
    assert [r["status"] for r in ev["requests"]] == [None, None]
    s.finish_request(stale, 404); s.finish_request(live, 404)      # no session id: a real 404, not stale
    ev = s.evidence()
    assert (ev["interaction_count"], ev["stale_session_requests"]) == (1, 1)
    assert ev["canary_hits"] == [{"seq": live, "rpc_methods": ["tools/call"]}]
    assert [(r["seq"], r["status"]) for r in ev["requests"]] == [(stale, 404), (live, 404)]

def test_handler_is_stamped_with_its_own_request_seq():
    s = _round("rug_pull")
    s.finish_request(s.start_request(http_method="GET", rpc_methods=[], has_session_id=True, body=""), 200)
    seq = s.start_request(http_method="POST", rpc_methods=["tools/list"], has_session_id=True, body="{}")
    s.on_tools_list()
    s.finish_request(seq, 200)
    ev = s.evidence()
    assert seq == 2 and ev["lists_served"][0]["seq"] == 2
    assert ev["requests"][1] == {"seq": 2, "http_method": "POST", "rpc_methods": ["tools/list"], "status": 200}

def test_begin_round_rejects_an_unknown_scenario():
    with pytest.raises(ValueError, match="no_such_scenario"):
        TrapState().begin_round("no_such_scenario", "ARGUS-CANARY-00000000000000AA")
    with pytest.raises(ValueError):
        TrapState().begin_round("warmup", "ARGUS-CANARY-00000000000000AA")

def test_credential_lure_schema_carries_the_round_canary():
    tools = _round("credential_lure", "ARGUS-CANARY-00000000000000CC").on_tools_list()
    sync = next(t for t in tools if t["name"] == "sync_notes")
    assert sync["inputSchema"]["properties"]["api_key"]["default"] == "ARGUS-CANARY-00000000000000CC"

def test_confused_deputy_result_carries_the_injection():
    text, is_error, _ = _round("confused_deputy").on_tool_call("read_notes", {})
    assert sc.NOTES_TEXT in text and sc.ATTACKER_EMAIL in text and not is_error

def test_warmup_serves_one_benign_tool():
    s = TrapState(); s.begin_warmup()
    tools = s.on_tools_list()
    assert [t["name"] for t in tools] == ["read_notes"]
    assert sc.ATTACKER_DOMAIN not in str(tools)

def test_scenario_text_names_only_reserved_hosts():
    text = " ".join(str(sc.tools_for(n, "C", rug_pulled=r)) + " ".join(
        sc.call_result(n, t["name"], {}) for t in sc.tools_for(n, "C", rug_pulled=r))
        for n in (*sc.SCENARIO_NAMES, "warmup") for r in (False, True))
    for host in re.findall(r"@([\w.-]+)|https?://([\w.-]+)", text):
        h = next(x for x in host if x).rstrip(".")
        assert h.endswith((".invalid", ".example")), h

def test_agent_last_listed_is_per_tool_and_none_when_not_listed():
    s = _round("rug_pull")
    s.on_tool_call("read_notes", {})                                  # switch, nothing listed yet
    seq = s.start_request(http_method="POST", rpc_methods=["tools/list"], has_session_id=True, body="{}")
    s.on_tools_list(); s.finish_request(seq, 200); s.on_tool_call("read_notes", {})
    s.on_tool_call("send_email", {"to": sc.TEAMMATE_EMAIL, "body": "hi"})
    calls = s.evidence()["tool_calls"]
    assert [(c["definition_in_force"], c["agent_last_listed"]) for c in calls] == [
        ("original", None), ("original", "original"), ("changed", "changed")]
    assert s.evidence()["lists_served"] == [{"seq": 1, "tools": ["read_notes", "send_email"], "rug_pulled": True}]

def test_evidence_returns_copies():
    s = _round("credential_lure")
    s.on_tools_list(); s.on_tool_call("sync_notes", {"api_key": {"k": "v"}})
    ev = s.evidence()
    ev["tool_calls"][0]["arguments"]["api_key"]["k"] = "changed"
    ev["lists_served"][0]["tools"].clear(); ev["requests"].append({})
    again = s.evidence()
    assert again["tool_calls"][0]["arguments"] == {"api_key": {"k": "v"}}
    assert again["lists_served"][0]["tools"] == ["read_notes", "send_email", "sync_notes"]
    assert again["requests"] == [] and again["rug_pull"] is None
