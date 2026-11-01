import json
from dataclasses import asdict
from a2a_evidence import action, event, linked_chain, make_evidence
from event_graph import components
from argus.a2a.events import events_from_trials
from argus.events import validate_events

def dicts(events): return [asdict(e) for e in events]

def test_linked_cascade_is_one_connected_graph():
    got = dicts(events_from_trials([(1, linked_chain())]))
    assert [(e["event_id"], e["operation"], e["actor"], e["basis"], e["parent_event_ids"]) for e in got] == [
        ("t1:E1", "invoke_agent", "planner", "observed", []),
        ("t1:E2", "deliver_message", "worker:invoice-records", "observed", ["t1:E1"]),
        ("t1:E3", "invoke_agent", "planner", "reported", ["t1:E2"]),
        ("t1:E4", "invoke_agent", "reviewer", "reported", ["t1:E3"]),
        ("t1:E5", "execute_tool", "executor", "observed", ["t1:E4"]),
    ]
    assert got[1]["object_ref"] == "a2a.task:T2" and got[2]["object_ref"] == "a2a.message:M3"
    assert got[4]["tool_name"] == "pay_invoice" and got[4]["object_ref"] is None
    assert all(e["ts"] is None and e["source"] == "a2a_world" and e["atlas_technique"] is None for e in got)
    assert [e["seq"] for e in got] == [1, 2, 3, 4, 5]
    assert validate_events(got) is None and components(got) == 1

def test_existing_parent_event_ids_are_preserved_exactly():
    got = {e["event_id"]: e for e in dicts(events_from_trials([(1, linked_chain())]))}
    assert got["t1:E2"]["parent_event_ids"] == ["t1:E1"]

def test_value_correlation_alone_creates_no_parent():
    from a2a_evidence import chain
    got = dicts(events_from_trials([(1, chain())]))
    assert all(e["parent_event_ids"] == [] for e in got)

def test_unresolved_and_forward_parents_are_dropped():
    ev = make_evidence(events=[event(1, "planner", "reviewer", parent=("M9", "M2")),
                               event(2, "reviewer", "executor", parent=("M1",))])
    got = dicts(events_from_trials([(1, ev)]))
    assert got[0]["parent_event_ids"] == [] and got[1]["parent_event_ids"] == ["t1:E1"]
    assert validate_events(got) is None

def test_untrusted_peer_send_is_send_external_and_discovery_reads_are_skipped():
    ev = make_evidence(events=[
        {**event(1, "planner", "worker:x", kind="card_read", assurance="testbed_observed")},
        {**event(2, "planner", "worker:x", kind="peer_message", assurance="testbed_observed"), "peer_trusted": False},
        {**event(3, "planner", "worker:x", kind="task_poll", assurance="testbed_observed")},
    ])
    got = dicts(events_from_trials([(1, ev)]))
    assert [(e["event_id"], e["operation"]) for e in got] == [("t1:E2", "send_external")]

def test_trials_get_distinct_ids_and_invalid_evidence_is_skipped():
    got = dicts(events_from_trials([(1, linked_chain()), (2, linked_chain()), (3, {"schema_version": "x"})]))
    assert len(got) == 10 and len({e["event_id"] for e in got}) == 10
    assert {e["event_id"].split(":")[0] for e in got} == {"t1", "t2"}

def test_canary_in_fields_and_digest_never_reaches_events():
    canary = "CANARY-A2A-7f3e"
    ev = linked_chain()
    ev["events"][2]["fields"] = {"memo": canary}
    ev["events"][2]["digest"] = canary
    ev["actions"][0]["fields"] = {"amountMinor": 100000, "note": canary}
    assert canary not in json.dumps(dicts(events_from_trials([(1, ev)])))

def test_repeated_message_or_task_ids_link_all_earlier_emitted_matches():
    rows = [event(1, "planner", "reviewer"), event(2, "reviewer", "executor"),
            event(3, "planner", "executor", parent=("shared", "shared", "M1"))]
    rows[0]["task_id"] = "shared"
    rows[1]["message_id"] = "shared"
    rows[2]["task_id"] = "shared"
    got = dicts(events_from_trials([(1, make_evidence(events=rows))]))
    assert got[2]["parent_event_ids"] == ["t1:E1", "t1:E2"]
    assert validate_events(got) is None


def test_skipped_and_forward_event_parents_are_dropped():
    rows = [event(1, "planner", "worker:x", kind="card_read"),
            event(2, "planner", "reviewer", parent_events=("E1", "E2", "E3", "missing")),
            event(3, "reviewer", "executor", parent_events=("E2",))]
    got = dicts(events_from_trials([(1, make_evidence(events=rows))]))
    assert [e["parent_event_ids"] for e in got] == [[], ["t1:E2"]]
    assert validate_events(got) is None


def test_clean_phase_emits_no_events():
    assert events_from_trials([(1, linked_chain(phase="clean"))]) == []


def test_invalid_raw_seq_and_duplicate_ids_skip_entire_trial():
    invalid = []
    for seq in (-1, True):
        evidence = linked_chain()
        evidence["events"][0]["seq"] = seq
        invalid.append(evidence)
    duplicate_seq = linked_chain()
    duplicate_seq["events"][1]["seq"] = 1
    invalid.append(duplicate_seq)
    duplicate_id = linked_chain()
    duplicate_id["actions"][0]["event_id"] = "E1"
    invalid.append(duplicate_id)
    for evidence in invalid:
        got = dicts(events_from_trials([(1, linked_chain()), (2, evidence)]))
        assert [e["event_id"] for e in got] == ["t1:E1", "t1:E2", "t1:E3", "t1:E4", "t1:E5"]


def test_trial_seq_uses_input_positions_including_invalid_slots():
    got = dicts(events_from_trials([(7, linked_chain()), (8, {}), (9, linked_chain())]))
    assert [(e["event_id"], e["seq"]) for e in got] == [
        ("t7:E1", 1), ("t7:E2", 2), ("t7:E3", 3), ("t7:E4", 4), ("t7:E5", 5),
        ("t9:E1", 2000001), ("t9:E2", 2000002), ("t9:E3", 2000003), ("t9:E4", 2000004), ("t9:E5", 2000005),
    ]
    assert validate_events(got) is None


def test_action_collection_defines_action_even_with_extra_kind():
    evidence = linked_chain()
    evidence["actions"][0]["kind"] = "agent_message"
    got = dicts(events_from_trials([(1, evidence)]))
    assert got[-1]["operation"] == "execute_tool"
    assert got[-1]["actor"] == "executor"


def test_invalid_optional_action_identifiers_skip_trial():
    from argus.a2a.world import validate

    for name, value in (("parent_event_ids", None), ("parent_event_ids", [{}]),
                        ("message_id", {}), ("task_id", [])):
        evidence = linked_chain()
        evidence["actions"][0][name] = value
        assert validate(evidence) is None
        got = dicts(events_from_trials([(1, evidence), (2, linked_chain())]))
        assert [e["event_id"] for e in got] == ["t2:E1", "t2:E2", "t2:E3", "t2:E4", "t2:E5"]
        assert [e["seq"] for e in got] == [1000001, 1000002, 1000003, 1000004, 1000005]
