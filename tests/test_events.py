from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import logging

from argus.events import Event, OPERATIONS, checked, iso_z, new_event, summarize, validate_events


def ev(eid, parents=(), **kw):
    base = dict(event_id=eid, parent_event_ids=list(parents), ts=None, actor="argus",
                operation="invoke_agent", basis="observed", source="a2a_world")
    base.update(kw)
    return asdict(Event(**base))


def test_valid_dag_passes():
    assert validate_events([ev("a"), ev("b", ["a"]), ev("c", ["a", "b"])]) is None


def test_unresolved_parent_is_rejected():
    assert validate_events([ev("b", ["a"])]) == "event b has unresolved parent a"


def test_duplicate_id_is_rejected():
    assert validate_events([ev("a"), ev("a")]) == "duplicate event_id a"


def test_cycle_is_rejected():
    assert validate_events([ev("a", ["b"]), ev("b", ["a"])]).startswith("event graph has a cycle through ")
    assert validate_events([ev("a", ["a"])]).startswith("event graph has a cycle through ")


def test_closed_sets_and_formats():
    assert validate_events([ev("a", operation="chat")]) == "event a has unknown operation chat"
    assert validate_events([ev("a", basis="inferred")]) == "event a has unknown basis inferred"
    assert validate_events([ev("a", source="x")]) == "event a has unknown source x"
    assert validate_events([ev("a", ts="2026-11-01T04:10:24+00:00")]) == "event a ts is not ISO 8601 UTC with Z"
    assert validate_events([ev("a", ts="2026-11-01T04:10:24.123Z")]) is None
    for bad in ("gmail.draft:1", "gmail.message:", "gmail.message: x", "nokind"):
        assert validate_events([ev("a", object_ref=bad)]) == "event a object_ref is not <kind>:<id> with a known kind"
    assert validate_events([ev("a", object_ref="a2a.task:T-1")]) is None
    assert validate_events([ev("a", atlas_technique="T0051")]) == "event a atlas_technique is not an ATLAS technique id"
    assert validate_events([ev("a", atlas_technique="AML.T0051.001")]) is None
    assert validate_events([ev("a", summary="x" * 201)]) == "event a summary is longer than 200 characters"
    assert validate_events([ev("")]) == "event_id must be a nonempty string"


def test_operation_set_is_closed():
    assert OPERATIONS == ("invoke_agent", "execute_tool", "deliver_message", "read_object", "write_object", "send_external")


def test_iso_z_formats_utc_and_rejects_naive():
    aware = datetime(2026, 11, 1, 12, 10, 24, 123456, tzinfo=timezone(timedelta(hours=8)))
    assert iso_z(aware) == "2026-11-01T04:10:24.123Z"
    assert iso_z(datetime(2026, 11, 1, 4, 10, 24)) is None
    assert iso_z(None) is None


def test_summary_uses_structured_fields_only():
    assert summarize("executor", "execute_tool", "pay_invoice", None) == "executor execute_tool pay_invoice"
    assert summarize("target_agent", "write_object", None, "gmail.message:abc") == "target_agent write_object gmail.message"
    assert len(summarize("a" * 300, "invoke_agent", None, None)) == 200
    e = new_event(event_id="a", parent_event_ids=[], ts=None, actor="planner", operation="invoke_agent",
                  object_ref="a2a.message:M1", basis="reported", source="a2a_world")
    assert e.summary == "planner invoke_agent a2a.message"


def test_checked_drops_invalid_graph(caplog):
    good = [new_event(event_id="a", parent_event_ids=[], ts=None, actor="argus", operation="invoke_agent", basis="observed", source="a2a_world")]
    assert checked(good) == good
    bad = [new_event(event_id="b", parent_event_ids=["a"], ts=None, actor="argus", operation="invoke_agent", basis="observed", source="a2a_world")]
    with caplog.at_level(logging.WARNING):
        assert checked(bad) == []
    assert "event b has unresolved parent a" in caplog.text


def test_seq_requires_nonnegative_integers():
    for bad in (-1, "1", True):
        assert validate_events([ev("a", seq=bad)]) == "event a seq must be a nonnegative integer or null"
    assert validate_events([ev("a", seq=0)]) is None



def test_duplicate_seq_is_rejected():
    assert validate_events([ev("a", seq=1), ev("b", seq=1)]) == "duplicate event seq 1"



def test_seq_must_follow_parent():
    for child_seq in (0, 1):
        problem = validate_events([ev("a", seq=1), ev("b", ["a"], seq=child_seq)])
        if child_seq == 1:
            assert problem == "duplicate event seq 1"
        else:
            assert problem == "event b seq is not after parent a"
    assert validate_events([ev("a", seq=0), ev("b", ["a"], seq=1)]) is None
    assert validate_events([ev("a"), ev("b", ["a"], seq=0)]) is None



def test_actor_and_parent_list_are_validated():
    for bad in ("", None, 1):
        assert validate_events([ev("a", actor=bad)]) == "event a has an empty actor"
    for bad in ("a", [1], None):
        row = ev("a")
        row["parent_event_ids"] = bad
        assert validate_events([row]) == "event a parent_event_ids must be a list of strings"
