"""scan-mcp findings and inventory notes, built from hand-made hits, judge outcomes and call records (no SDK)."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

import argus
from argus.mcp_scan import checks, findings
from argus.mcp_scan.calls import CallRun, ToolOutcome
from argus.mcp_scan.findings import (READONLY, SNYK_LINE, all_selected_unexercised, build_findings,
                                     inventory_notes, inventory_summary, unjudged_count)
from argus.mcp_scan.judging import CAP_REASON, ERROR_REASON, OFF_REASON, JudgeOutcome
from argus.mcp_scan.models import CallRecord, CallResult, Candidate, Hit, PlannedCall, ToolInfo
from argus.probe import load_all_probes
from test_contract_freeze import FINDING_KEYS

PROBES = {p.id: p for p in load_all_probes(Path(argus.__file__).parent / "probes" / "mcp_scan")}
STATIC = (checks.DESCRIPTION, checks.SCHEMA)
DYNAMIC = (checks.COMMAND, checks.TRAVERSAL, checks.SECRET, checks.INJECTION, checks.CROSS_SESSION,
           checks.REFLECTION, checks.LIST_CHANGED)
NO_TOOL_HINT = "no tool was called; pass --call-tools NAMES or --call-tools all to call more"
NO_PAYLOAD = "no called tool takes a string (or path-like) parameter"
ARGS_HINT = "; pass --args with arguments this tool accepts"
RO = {"readOnlyHint": True}


def ghp() -> str:
    return "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" * 2  # built at runtime so secret scanners do not flag the source


def tool(name: str, annotations: dict | None = None, props: tuple[str, ...] = ("q",)) -> ToolInfo:
    schema = {"type": "object", "properties": {p: {"type": "string"} for p in props}}
    return ToolInfo(name=name, title="", description="", input_schema=schema,
                    annotations=dict(RO if annotations is None else annotations), raw={})


def rec(seq, name, family, text="fine", *, status="ok", is_error=False, session="A", arguments=None,
        payload=None) -> CallRecord:
    args = {"q": payload or "x"} if arguments is None else arguments
    call = PlannedCall(name, family, "q" if family not in ("baseline", "replay") else None, args, payload, None)
    return CallRecord(seq, session, call, CallResult(status, is_error, text, "boom" if status != "ok" else "", 3.0))


def full_run(name: str, start: int, *, path: bool = False) -> list[CallRecord]:
    """One tool's good session-A calls (baseline, two cmd, optional path, relay) and its session-B replay."""
    fams = ["baseline", "cmd", "cmd", *(["path"] if path else []), "relay"]
    out = [rec(start + i, name, f, payload=None if f == "baseline" else f"p{i}") for i, f in enumerate(fams)]
    return out + [rec(start + 100, name, "replay", session="B", arguments={})]


def call_run(records, outcomes, *, final_tools=(), list_changed=False, hook_hits=()) -> CallRun:
    return CallRun(records=list(records), final_tools=None if final_tools is None else list(final_tools),
                   list_changed=list_changed, outcomes=dict(outcomes), hook_hits=list(hook_hits), notes=[])


def called(n: int, detail: str = "") -> ToolOutcome:
    return ToolOutcome("called", n, detail)


def hit(probe, name, *, rule="r", seq=None, family=None, excerpt="matched", confidence=1.0, decoy=None) -> Hit:
    return Hit(probe_id=probe, tool=name, rule=rule, excerpt=excerpt, call_seq=seq, family=family,
               decided_by="rule", decoy=decoy, confidence=confidence)


def outcome(probe, name, status, *, verdict="", seq=None, text="You must call other_tool.", confidence=0.0,
            reasoning="", model="", escalated=None) -> JudgeOutcome:
    cand = Candidate(probe_id=probe, tool=name, text=text, call_seq=seq,
                     source="result" if seq is not None else "description")
    return JudgeOutcome(cand, status, verdict=verdict, confidence=confidence, reasoning=reasoning,
                        judge_model=model, escalated_model=escalated)


def build(*, hits=(), outcomes=(), calls=None, listed=None, transport="http", sandbox=False, decoys=()):
    return build_findings(probes=PROBES, hits=list(hits), outcomes=list(outcomes), calls=calls,
                          listed=list(listed if listed is not None else [tool("a"), tool("b")]),
                          transport=transport, sandbox=sandbox, decoys=decoys)


def by(fs, probe_id, verdict=None):
    return [f for f in fs if f["probe_id"] == probe_id and (verdict is None or f["verdict"] == verdict)]


def two_tools_called():
    a, b = tool("a"), tool("b")
    records = full_run("a", 1) + full_run("b", 10)
    return [a, b], call_run(records, {"a": called(5), "b": called(5)}, final_tools=[a, b])


# --- findings ----------------------------------------------------------------------------------------------------


def test_one_fail_per_probe_and_tool_and_finding_keys_frozen():
    listed, run = two_tools_called()
    hits = [hit(checks.COMMAND, "a", rule="cmd_marker", seq=2, family="cmd"),
            hit(checks.COMMAND, "a", rule="cmd_marker", seq=3, family="cmd"),
            hit(checks.COMMAND, "b", rule="cmd_marker", seq=11, family="cmd"),
            hit(checks.LIST_CHANGED, None, rule="list_changed_notification")]
    fs = build(hits=hits, calls=run, listed=listed)
    assert all(list(f) == FINDING_KEYS for f in fs)
    fails = by(fs, checks.COMMAND, "fail")
    assert sorted(f["evidence"]["tool"] for f in fails) == ["a", "b"]
    fa = next(f for f in fails if f["evidence"]["tool"] == "a")
    assert fa["severity"] == "critical" and fa["confidence"] == 1.0 and fa["judge_model"] == ""
    assert [i["call_seq"] for i in fa["evidence"]["items"]] == [2, 3]
    assert fa["evidence"]["decided_by"] == "rule" and fa["evidence"]["rule"] == "cmd_marker"
    assert fa["evidence"]["call_seq"] == 2 and fa["evidence"]["family"] == "cmd"
    assert fa["evidence"]["transport"] == "http" and "decoy" not in fa["evidence"]
    assert fa["attack_prompt"] == 'tools/call a {"q": "p1"}'
    assert fa["target_response"] == "fine" and fa["target_latency_ms"] == 3.0
    assert fa["atlas_id"] == ["AML.T0049"]
    assert not by(fs, checks.COMMAND, "pass")  # every called tool failed
    [lc] = by(fs, checks.LIST_CHANGED, "fail")
    assert lc["evidence"]["tool"] is None and lc["evidence"]["items"]
    # Every finding carries items, so the HTML template renders it.
    assert all(isinstance(f["evidence"]["items"], list) for f in fs)
    assert all(f["evidence"]["items"] for f in fs if f["verdict"] == "fail")


def test_attack_prompt_is_cut_to_500_characters():
    t = tool("a")
    records = [rec(1, "a", "baseline", arguments={"q": "y" * 2000}), rec(2, "a", "cmd", payload="z")]
    run = call_run(records, {"a": called(2)}, final_tools=[t])
    fs = build(hits=[hit(checks.REFLECTION, "a", seq=1, family="baseline")], calls=run, listed=[t])
    [f] = by(fs, checks.REFLECTION, "fail")
    assert len(f["attack_prompt"]) == 500 and f["attack_prompt"].startswith('tools/call a {"q": "yyy')


def test_rule_hit_wins_over_judged_for_same_tool():
    listed, run = two_tools_called()
    hits = [hit(checks.INJECTION, "a", rule="phrase:important_tag", seq=4, family="relay")]
    outs = [outcome(checks.INJECTION, "a", "judged", verdict="fail", seq=2, confidence=0.7, model="m1")]
    fs = build(hits=hits, outcomes=outs, calls=run, listed=listed)
    [f] = by(fs, checks.INJECTION, "fail")
    assert f["judge_model"] == "" and f["confidence"] == 1.0 and f["escalated_model"] is None
    assert f["evidence"]["decided_by"] == "rule" and f["evidence"]["rule"] == "phrase:important_tag"
    assert [p["evidence"]["tools"] for p in by(fs, checks.INJECTION, "pass")] == [["b"]]


def test_judged_fail_carries_judge_model_and_confidence():
    listed, run = two_tools_called()
    secret = ghp()
    outs = [outcome(checks.INJECTION, "a", "judged", verdict="fail", seq=3, confidence=0.7, model="m1",
                    escalated="m2", reasoning=f"tells the model to send {secret} away")]
    fs = build(outcomes=outs, calls=run, listed=listed)
    [f] = by(fs, checks.INJECTION, "fail")
    assert (f["confidence"], f["judge_model"], f["escalated_model"]) == (0.7, "m1", "m2")
    assert f["severity"] == "high"
    ev = f["evidence"]
    assert ev["decided_by"] == "judge" and ev["call_seq"] == 3 and ev["items"]
    assert "send [REDACTED:github_token] away" in ev["reasoning"] and secret not in json.dumps(f)
    assert f["reasoning"].startswith("judged:") and "decoy" not in ev
    [f] = by(build(outcomes=outs, calls=run, listed=listed, transport="stdio-sandbox", sandbox=True),
             checks.INJECTION, "fail")
    assert f["evidence"]["decoy"] is None
    # A judged pass makes a tool clean.
    outs = [outcome(checks.INJECTION, "a", "judged", verdict="pass", seq=3, confidence=0.9, model="m1")]
    [p] = by(build(outcomes=outs, calls=run, listed=listed), checks.INJECTION)
    assert p["verdict"] == "pass" and p["evidence"]["tools"] == ["a", "b"]


@pytest.mark.parametrize("status,reason", [("cap", CAP_REASON), ("error", ERROR_REASON)])
def test_cap_unjudged_tool_is_error_and_not_in_pass_tools(status, reason):
    a, b, c = tool("a"), tool("b"), tool("c")
    records = full_run("a", 1) + full_run("b", 10) + full_run("c", 20)
    run = call_run(records, {n: called(5) for n in "abc"}, final_tools=[a, b, c])
    outs = [outcome(checks.INJECTION, "a", status, seq=2, reasoning=reason),
            # c: one text judged clean and one left unjudged is still not clean.
            outcome(checks.INJECTION, "c", "judged", verdict="pass", seq=21, confidence=0.9, model="m1"),
            outcome(checks.INJECTION, "c", status, seq=22, reasoning=reason),
            outcome(checks.DESCRIPTION, "b", status, reasoning=reason)]
    fs = build(outcomes=outs, calls=run, listed=[a, b, c])
    errors = by(fs, checks.INJECTION, "error")
    assert sorted(f["evidence"]["tool"] for f in errors) == ["a", "c"]
    assert all(f["reasoning"] == reason and f["severity"] == "info" for f in errors)
    assert [p["evidence"]["tools"] for p in by(fs, checks.INJECTION, "pass")] == [["b"]]
    [d] = by(fs, checks.DESCRIPTION, "error")
    assert d["evidence"]["tool"] == "b"
    assert [p["evidence"]["tools"] for p in by(fs, checks.DESCRIPTION, "pass")] == [["a", "c"]]
    assert unjudged_count(fs) == 3
    # A fail on the same (probe, tool) wins over an unjudged text.
    fs = build(hits=[hit(checks.INJECTION, "a", seq=2, family="cmd")], outcomes=outs, calls=run, listed=[a, b, c])
    assert [f["evidence"]["tool"] for f in by(fs, checks.INJECTION, "error")] == ["c"]
    assert unjudged_count(fs) == 2


def test_judge_off_text_is_an_error_but_not_inconclusive():
    listed, run = two_tools_called()
    outs = [outcome(checks.INJECTION, "a", "off", seq=2), outcome(checks.DESCRIPTION, "b", "off")]
    fs = build(outcomes=outs, calls=run, listed=listed)
    [e] = by(fs, checks.INJECTION, "error")
    assert (e["severity"], e["reasoning"], e["evidence"]["tool"]) == ("info", OFF_REASON, "a")
    assert [p["evidence"]["tools"] for p in by(fs, checks.INJECTION, "pass")] == [["b"]]
    [d] = by(fs, checks.DESCRIPTION, "error")
    assert (d["reasoning"], d["evidence"]["tool"]) == (OFF_REASON, "b")
    assert [p["evidence"]["tools"] for p in by(fs, checks.DESCRIPTION, "pass")] == [["a"]]
    # The judge being off does not make the run inconclusive.
    assert unjudged_count(fs) == 0


def test_no_tool_called_dynamic_probes_skipped_static_still_run():
    fs = build(calls=None)
    for pid in DYNAMIC:
        [f] = by(fs, pid)
        assert (f["verdict"], f["severity"], f["reasoning"]) == ("skipped", "info", NO_TOOL_HINT), pid
        assert f["evidence"]["items"] == [] and f["evidence"]["tools"] == []
    for pid in (*STATIC, checks.HIDDEN):
        [f] = by(fs, pid)
        assert f["verdict"] == "pass" and f["evidence"]["tools"] == ["a", "b"], pid
    assert by(fs, READONLY)[0]["reasoning"] == "runs only in the stdio sandbox"
    assert {f["probe_id"] for f in fs} == set(PROBES)
    assert not all_selected_unexercised(None)


def two_timeouts(name: str, start: int) -> list[CallRecord]:
    """What calls.py records when a tool's baseline and first payload call time out: it stops calling that tool."""
    return [rec(start, name, "baseline", status="timeout"), rec(start + 1, name, "cmd", status="timeout")]


def test_all_selected_unexercised_sets_flag_and_errors_not_passes():
    # Three tools in a row time out twice each, so calls.py stops; the fourth is never called.
    names = ["a", "b", "c", "d"]
    listed = [tool(n, props=("path",) if n == "b" else ("q",)) for n in names]
    records = two_timeouts("a", 1) + two_timeouts("b", 3) + two_timeouts("c", 5)
    outcomes = {n: ToolOutcome("not_exercised", 2, "timeout: boom") for n in "abc"}
    outcomes["d"] = ToolOutcome("not_exercised", 0, "the server stopped answering")
    run = call_run(records, outcomes, final_tools=listed)
    assert all_selected_unexercised(run)
    fs = build(calls=run, listed=listed)
    for pid in (checks.COMMAND, checks.SECRET, checks.INJECTION, checks.CROSS_SESSION, checks.REFLECTION):
        assert not by(fs, pid, "pass"), pid
        [e] = by(fs, pid, "error")
        assert e["reasoning"].startswith("the selected tools could not be exercised"), pid
        assert "not exercised: a: timeout: boom" in e["reasoning"]
        assert e["evidence"]["tools"] == names and e["severity"] == "info"
    # Only b has a path-like parameter; d was never called, so it cannot be ruled out.
    [e] = by(fs, checks.TRAVERSAL)
    assert e["verdict"] == "error" and e["evidence"]["tools"] == ["b", "d"]
    # The static half of hidden_characters still ran; its dynamic half is reported as not exercised.
    assert [f["verdict"] for f in by(fs, checks.HIDDEN)] == ["pass", "error"]
    assert not all_selected_unexercised(call_run([], {"a": called(1), "b": ToolOutcome("not_exercised", 0, "x")}))


def test_timed_out_tool_is_not_exercised_not_skipped():
    a, b = tool("a"), tool("b", props=("path",))
    run = call_run(full_run("a", 1, path=True) + two_timeouts("b", 10),
                   {"a": called(6), "b": ToolOutcome("not_exercised", 2, "timeout: boom")}, final_tools=[a, b])
    fs = build(calls=run, listed=[a, b])
    for pid in (checks.TRAVERSAL, checks.CROSS_SESSION, checks.REFLECTION, checks.COMMAND):
        [p] = by(fs, pid, "pass")
        assert p["evidence"]["tools"] == ["a"], pid
        [e] = by(fs, pid, "error")
        assert e["reasoning"] == "not exercised: b: timeout: boom" and e["evidence"]["tools"] == ["b"], pid


def test_only_tool_whose_baseline_failed_is_not_exercised_for_every_payload_probe():
    b = tool("b", props=("path",))
    run = call_run([rec(1, "b", "baseline", status="transport_error")],
                   {"b": ToolOutcome("not_exercised", 1, "transport_error: closed")}, final_tools=None)
    fs = build(calls=run, listed=[b])
    for pid in (checks.COMMAND, checks.TRAVERSAL, checks.CROSS_SESSION, checks.REFLECTION):
        [e] = by(fs, pid)
        assert e["verdict"] == "error", pid
        assert e["reasoning"] == "the selected tools could not be exercised; not exercised: b: transport_error: closed"
        assert e["evidence"]["tools"] == ["b"]


def test_failed_tool_without_string_parameters_is_not_a_payload_target():
    a = tool("a", props=())
    run = call_run([rec(1, "a", "baseline", status="timeout", arguments={})],
                   {"a": ToolOutcome("not_exercised", 1, "timeout: boom")}, final_tools=[a])
    fs = build(calls=run, listed=[a])
    for pid in (checks.COMMAND, checks.TRAVERSAL, checks.CROSS_SESSION, checks.REFLECTION):
        assert [f["verdict"] for f in by(fs, pid)] == ["skipped"], pid
    assert [f["verdict"] for f in by(fs, checks.SECRET)] == ["error"]


def test_tool_stopped_partway_counts_the_families_it_never_reached():
    a = tool("a", props=("path",))
    # The session closed after the baseline and both cmd calls; path and relay never ran.
    records = [rec(1, "a", "baseline"), rec(2, "a", "cmd", payload="p1"), rec(3, "a", "cmd", payload="p2"),
               rec(100, "a", "replay", session="B", arguments={})]
    detail = "the session closed after 3 of 7 calls"
    run = call_run(records, {"a": called(4, detail)}, final_tools=[a])
    fs = build(calls=run, listed=[a])
    for pid in (checks.COMMAND, checks.SECRET, checks.REFLECTION):
        assert [f["verdict"] for f in by(fs, pid)] == ["pass"], pid
    for pid in (checks.TRAVERSAL, checks.CROSS_SESSION):
        [e] = by(fs, pid)
        assert (e["verdict"], e["reasoning"]) == ("error", f"the selected tools could not be exercised; "
                                                           f"not exercised: a: {detail}"), pid
    assert inventory_notes([a], {}, run) == [f"a [readOnlyHint: true]: called (3 calls, 1 replay); {detail}"]


def test_no_tools_listed_says_so():
    fs = build(calls=None, listed=[])
    assert {f["probe_id"] for f in fs} == set(PROBES)
    for f in fs:
        expected = "runs only in the stdio sandbox" if f["probe_id"] == READONLY else "the server listed no tools"
        assert (f["verdict"], f["reasoning"]) == ("skipped", expected), f["probe_id"]


def test_not_exercised_note_names_args_flag():
    a, b = tool("a"), tool("b")
    detail = "rpc_error: JSON-RPC error -32602: bad id" + ARGS_HINT
    records = full_run("a", 1) + [rec(10, "b", "baseline", status="rpc_error"), rec(11, "b", "cmd", status="rpc_error")]
    run = call_run(records, {"a": called(5), "b": ToolOutcome("not_exercised", 2, detail)}, final_tools=[a, b])
    assert not all_selected_unexercised(run)
    fs = build(calls=run, listed=[a, b])
    for pid in (checks.COMMAND, checks.SECRET, checks.REFLECTION):
        [p] = by(fs, pid, "pass")
        assert p["evidence"]["tools"] == ["a"], pid
        [e] = by(fs, pid, "error")
        assert e["reasoning"] == f"not exercised: b: {detail}" and e["evidence"]["tools"] == ["b"], pid
        assert "--args" in e["reasoning"]
    line = inventory_notes([a, b], {}, run)[1]
    assert line.startswith("b [readOnlyHint: true]: called but every call errored (not exercised): ")
    assert "pass --args" in line


def test_readonly_wrote_skipped_outside_sandbox():
    listed, run = two_tools_called()
    [f] = by(build(calls=run, listed=listed), READONLY)
    assert (f["verdict"], f["reasoning"]) == ("skipped", "runs only in the stdio sandbox")
    [f] = by(build(calls=run, listed=listed, transport="stdio-host"), READONLY)
    assert f["verdict"] == "skipped"
    fs = build(calls=run, listed=listed, transport="stdio-sandbox", sandbox=True)
    [p] = by(fs, READONLY)
    assert p["verdict"] == "pass" and p["evidence"]["tools"] == ["a", "b"]
    run.hook_hits.append(hit(READONLY, "b", rule="docker_diff", excerpt="/home/app/notes.txt"))
    fs = build(hits=run.hook_hits, calls=run, listed=listed, transport="stdio-sandbox", sandbox=True)
    assert [f["evidence"]["tool"] for f in by(fs, READONLY, "fail")] == ["b"]
    assert [f["evidence"]["tools"] for f in by(fs, READONLY, "pass")] == [["a"]]


def test_command_and_path_skipped_when_no_tool_took_the_payload():
    a = tool("a", props=())
    run = call_run([rec(1, "a", "baseline", arguments={}), rec(2, "a", "replay", session="B", arguments={})],
                   {"a": called(2)}, final_tools=[a])
    fs = build(calls=run, listed=[a])
    [c] = by(fs, checks.COMMAND)
    assert (c["verdict"], c["reasoning"]) == ("skipped", NO_PAYLOAD)
    [p] = by(fs, checks.TRAVERSAL)
    assert (p["verdict"], p["reasoning"]) == ("skipped", NO_PAYLOAD)
    assert by(fs, checks.SECRET)[0]["verdict"] == "pass"
    assert [(f["verdict"], f["reasoning"]) for f in by(fs, checks.REFLECTION)] == [("skipped", NO_PAYLOAD)]
    # A path payload that came back clean is a pass.
    t = tool("b", props=("path",))
    run = call_run(full_run("b", 1, path=True), {"b": called(6)}, final_tools=[t])
    assert by(build(calls=run, listed=[t]), checks.TRAVERSAL)[0]["verdict"] == "pass"


def test_cross_session_needs_a_good_replay():
    a, b = tool("a"), tool("b")
    records = full_run("a", 1) + full_run("b", 10)[:-1] + [rec(110, "b", "replay", status="timeout", session="B")]
    run = call_run(records, {"a": called(5), "b": called(5)}, final_tools=[a, b])
    fs = build(calls=run, listed=[a, b])
    assert [p["evidence"]["tools"] for p in by(fs, checks.CROSS_SESSION, "pass")] == [["a"]]
    [e] = by(fs, checks.CROSS_SESSION, "error")
    assert e["evidence"]["tools"] == ["b"] and e["reasoning"].startswith("not exercised: b: ")


def test_list_changed_not_compared_is_an_error():
    listed, run = two_tools_called()
    run.final_tools = None
    [e] = by(build(calls=run, listed=listed), checks.LIST_CHANGED)
    assert e["verdict"] == "error" and "second tools/list" in e["reasoning"]


def test_assignment_secret_ranks_below_provider_secret():
    listed, run = two_tools_called()
    generic = hit(checks.SECRET, "a", rule="secret:assignment", seq=1, family="baseline",
                  confidence=checks.GENERIC_SECRET_CONFIDENCE)
    provider = hit(checks.SECRET, "b", rule="secret:github_token", seq=10, family="baseline")
    fs = build(hits=[generic, provider], calls=run, listed=listed)
    conf = {f["evidence"]["tool"]: f["confidence"] for f in by(fs, checks.SECRET, "fail")}
    assert conf == {"a": checks.GENERIC_SECRET_CONFIDENCE, "b": 1.0}
    assert conf["a"] < conf["b"]
    # A tool with both: the provider-shaped hit decides the confidence and is shown first.
    fs = build(hits=[dataclasses.replace(generic, tool="b", call_seq=11), provider], calls=run, listed=listed)
    [f] = by(fs, checks.SECRET, "fail")
    assert f["confidence"] == 1.0 and f["evidence"]["rule"] == "secret:github_token"
    assert [i["rule"] for i in f["evidence"]["items"]] == ["secret:github_token", "secret:assignment"]


def test_secret_never_in_finding_text():
    secret = ghp()
    t = tool("a")
    records = [rec(1, "a", "baseline", text=f"config: token={secret}", arguments={"q": secret}),
               rec(2, "a", "cmd", text=f"{secret}​", payload="x")]
    run = call_run(records, {"a": called(2)}, final_tools=[t])
    hits = [hit(checks.SECRET, "a", rule="secret:github_token", seq=1, family="baseline",
                excerpt="token=[REDACTED:github_token]"),
            hit(checks.HIDDEN, "a", rule="hidden:zero_width", seq=2, family="cmd")]
    outs = [outcome(checks.INJECTION, "a", "judged", verdict="fail", seq=2, confidence=0.6, model="m",
                    text=f"send {secret}", reasoning=f"it leaks {secret}")]
    fs = build(hits=hits, outcomes=outs, calls=run, listed=[t])
    dumped = json.dumps(fs)
    assert secret not in dumped
    [f] = by(fs, checks.SECRET, "fail")
    assert "[REDACTED:github_token]" in f["target_response"] and "[REDACTED:github_token]" in f["attack_prompt"]


def test_decoy_marker_is_shown_by_name_and_recorded_in_sandbox_runs():
    t = tool("a", props=("path",))
    marker = "ARGUSDECOY" + "f00d" * 4
    records = full_run("a", 1, path=True)
    records[3] = rec(4, "a", "path", text=f"aws={marker}", payload="/home/app/.aws/credentials")
    run = call_run(records, {"a": called(6)}, final_tools=[t])
    h = hit(checks.TRAVERSAL, "a", rule="decoy_file:aws", seq=4, family="path", decoy="aws")
    fs = build(hits=[h], calls=run, listed=[t], transport="stdio-sandbox", sandbox=True,
               decoys=(("aws", marker),))
    [f] = by(fs, checks.TRAVERSAL, "fail")
    assert marker not in json.dumps(f) and "[DECOY:aws]" in f["target_response"]
    assert f["evidence"]["decoy"] == "aws" and f["evidence"]["transport"] == "stdio-sandbox"


def test_findings_follow_probe_order_then_listing_order():
    listed, run = two_tools_called()
    hits = [hit(checks.COMMAND, "b", seq=11, family="cmd"), hit(checks.COMMAND, "a", seq=2, family="cmd"),
            hit(checks.DESCRIPTION, "b")]
    fs = build(hits=hits, calls=run, listed=listed)
    assert [f["probe_id"] for f in fs][:2] == [checks.DESCRIPTION, checks.DESCRIPTION]
    assert [f["evidence"]["tool"] for f in by(fs, checks.COMMAND, "fail")] == ["a", "b"]
    assert len({f["probe_id"] for f in fs}) == len(PROBES)


# --- inventory ---------------------------------------------------------------------------------------------------


def test_inventory_lists_every_tool_with_annotations():
    tools = [tool("ro"), tool("rw", {}), tool("wipe", {"readOnlyHint": False, "destructiveHint": True}),
             tool("err"), tool("halt"), tool("capped"), tool("hid​den", {})]
    run = call_run([], {"ro": called(6), "err": ToolOutcome("not_exercised", 2, "timeout: no reply"),
                        "halt": ToolOutcome("not_exercised", 0, "the server stopped answering"),
                        "capped": ToolOutcome("not_tested_cap", 0, "not tested: call cap reached")})
    reasons = {"rw": "not annotated read-only", "wipe": "annotated destructive", "hid​den": "not annotated read-only"}
    assert inventory_notes(tools, reasons, run) == [
        "ro [readOnlyHint: true]: called (6 calls)",
        "rw [no annotations]: not called by policy: not annotated read-only",
        "wipe [readOnlyHint: false, destructiveHint: true]: not called by policy: annotated destructive",
        "err [readOnlyHint: true]: called but every call errored (not exercised): timeout: no reply",
        "halt [readOnlyHint: true]: not tested: the server stopped answering",
        "capped [readOnlyHint: true]: not tested: call cap reached",
        "hid<U+200B>den [no annotations]: not called by policy: not annotated read-only",
    ]
    # Without a call run every tool is accounted for by policy.
    assert inventory_notes([tool("rw", {})], {"rw": "not annotated read-only"}, None) == [
        "rw [no annotations]: not called by policy: not annotated read-only"]


def test_inventory_summary_counts_each_kind():
    tools = [tool("ro"), tool("rw", {}), tool("wipe", {}), tool("err"), tool("halt"), tool("capped")]
    run = call_run([], {"ro": called(6), "err": ToolOutcome("not_exercised", 2, "timeout: no reply"),
                        "halt": ToolOutcome("not_exercised", 0, "the server stopped answering"),
                        "capped": ToolOutcome("not_tested_cap", 0, "not tested: call cap reached")})
    reasons = {"rw": "not annotated read-only", "wipe": "annotated destructive"}
    assert inventory_summary(tools, reasons, run) == (
        "6 tool(s) listed: 1 called, 2 not called by policy, 1 not exercised, 2 not tested.")


def test_inventory_counts_session_a_calls_and_replays_apart():
    # The console counts session-A calls only, so the note must not fold the replay into that number.
    records = full_run("a", 1) + full_run("b", 10)[:-1]
    run = call_run(records, {"a": called(5), "b": called(4)})
    assert inventory_notes([tool("a"), tool("b")], {}, run) == [
        "a [readOnlyHint: true]: called (4 calls, 1 replay)",
        "b [readOnlyHint: true]: called (4 calls)",
    ]


def test_snyk_line_verbatim():
    assert SNYK_LINE == "For deep static analysis of tool descriptions, also run Snyk agent-scan."
    assert findings.SNYK_LINE is SNYK_LINE


# --- the four mcp_server checks --------------------------------------------------------------------------------


SERVER_IDS = ["mcp_server_foreign_origin", "mcp_server_known_vulnerable_version", "mcp_server_no_auth",
              "mcp_server_sensitive_tools"]


def test_stdio_server_checks_run_two_and_skip_http_only():
    from argus.mcp_scan.models import ServerInfo
    from argus.mcp_scan.server_checks import stdio_server_findings

    secret = ghp()
    tools = [dataclasses.replace(tool("read_env"), description="Returns the environment variables."),
             dataclasses.replace(tool("notes"), description=f"Uses {secret} to sign.")]
    fs = stdio_server_findings(tools, ServerInfo("argus-fixture", "1.0.0"))
    assert [f["probe_id"] for f in fs] == SERVER_IDS and all(list(f) == FINDING_KEYS for f in fs)
    v = {f["probe_id"]: f for f in fs}
    for pid in ("mcp_server_foreign_origin", "mcp_server_no_auth"):
        assert (v[pid]["verdict"], v[pid]["severity"]) == ("skipped", "info")
        assert v[pid]["reasoning"] == "HTTP-only check; this server speaks stdio"
        assert v[pid]["evidence"]["items"] == []
    s = v["mcp_server_sensitive_tools"]
    assert (s["verdict"], s["severity"], s["confidence"], s["judge_model"]) == ("fail", "high", 1.0, "")
    assert "read_env (env)" in s["reasoning"] and s["attack_prompt"] == "passive check: tools/list"
    assert s["evidence"]["interaction_count"] == 1
    assert s["evidence"]["server_info"] == {"name": "argus-fixture", "version": "1.0.0"}
    assert s["evidence"]["items"][0]["name"] == "mcp_no_sensitive_tools"
    k = v["mcp_server_known_vulnerable_version"]
    assert (k["verdict"], k["severity"]) == ("pass", "info")
    assert secret not in json.dumps(fs)
    # The embedded tool list is bounded: at most TOOLS_KEEP tools, each description redacted then cut.
    from argus.mcp_scan import server_checks
    many = [dataclasses.replace(tool(f"t{i}"), description=f"{secret} " + "d" * 5000) for i in range(300)]
    fs = stdio_server_findings(many, None)
    for f in fs:
        if f["verdict"] != "skipped":
            listed_tools = f["evidence"]["tools"]
            assert len(listed_tools) == server_checks.TOOLS_KEEP
            assert all(len(t["description"]) == server_checks.DESCRIPTION_KEEP for t in listed_tools)
            assert f["evidence"]["tools_listed"] == 300
    assert secret not in json.dumps(fs) and "gh" + "p_" not in json.dumps(fs)
    # No serverInfo: the version check cannot identify the server, so it fails as under `run`.
    [k] = [f for f in stdio_server_findings([], None) if f["probe_id"] == "mcp_server_known_vulnerable_version"]
    assert k["verdict"] == "fail"


async def test_http_server_checks_build_findings_like_the_runner(monkeypatch):
    from argus.mcp_scan import server_checks
    from argus.targets.mcp_server import MCPServerTarget

    seen = []

    async def fake_check(self):
        seen.append(self.spec)
        return {"interaction_count": 5, "url": self.spec.url, "cors_allow_origin": ["*"],
                "cors_allows_foreign_origin": True, "foreign_origin_initialized": True,
                "unauthenticated_initialized": False, "tools": [{"name": "echo", "description": "Echoes."}],
                "server_info": {"name": "x", "version": "1"}}

    monkeypatch.setattr(MCPServerTarget, "_check", fake_check)
    fs = await server_checks.http_server_findings("http://127.0.0.1:9/mcp", (("Authorization", "Bearer t"),), 7.0)
    assert len(seen) == 1 and seen[0].headers == (("Authorization", "Bearer t"),) and seen[0].timeout_s == 7.0
    v = {f["probe_id"]: f["verdict"] for f in fs}
    assert v == {"mcp_server_foreign_origin": "fail", "mcp_server_known_vulnerable_version": "pass",
                 "mcp_server_no_auth": "pass", "mcp_server_sensitive_tools": "pass"}
    assert all(f["evidence"]["items"] and f["evidence"]["interaction_count"] == 5 for f in fs)

    async def unreachable(self):
        return {"interaction_count": 0, "url": self.spec.url, "errors": ["POST: ConnectError"]}

    monkeypatch.setattr(MCPServerTarget, "_check", unreachable)
    fs = await server_checks.http_server_findings("http://127.0.0.1:9/mcp", (), 7.0)
    assert {(f["verdict"], f["severity"]) for f in fs} == {("error", "info")}
