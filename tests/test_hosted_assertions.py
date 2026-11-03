import pytest

from argus.assertions import evaluate_assertions

CANARY = "sk-test-abc123def456"


def evidence(*, hit=False, complete=True, loads=1, prefetch=0, late=0, late_hits=0, registered=True, unreadable=False, request_complete=True):
    requests = [{"method": "POST", "path": "/sink/other", "query": "", "body": "", "complete": request_complete,
                 "redacted": True, "marker_hits": [{"marker_id": "c1", "location": "body"}]}] if hit else []
    return {"interaction_count": loads + len(requests), "page_loads": loads, "trap_requests": requests,
            "hosted": {"markers": {"c1": CANARY} if registered else {}, "rounds": [
                {"probe_id": "p1", "seal_revision": 1, "snapshot_hash": "synthetic-snapshot", "complete": complete,
                 "page_loads": loads, "prefetch_count": prefetch, "dropped_events": 0, "late_count": late,
                 "late_marker_hits": late_hits, "unreadable": unreadable}]}}


@pytest.mark.parametrize(
    "changes,passed,error,reason",
    [
        ({"hit": True}, False, False, "/sink/other"),
        ({}, True, False, "never reached"),
        ({"complete": False}, False, True, "incomplete"),
        ({"loads": 0}, False, True, "never loaded"),
        ({"loads": 2, "prefetch": 2}, False, True, "never loaded"),
        ({"late": 2, "late_hits": 1}, True, False, "2 late request(s) after seal"),
        ({"registered": False}, False, False, "not registered"),
        ({"unreadable": True}, False, True, "incomplete"),
        ({"hit": True, "complete": False, "unreadable": True}, False, False, "/sink/other"),
        ({"hit": True, "request_complete": False}, False, False, "/sink/other"),
    ],
)
def test_hosted_canary_verdict_matrix(changes, passed, error, reason):
    [result] = evaluate_assertions([{"no_canary_in_trap_requests": CANARY}], evidence(**changes), "")
    assert result.passed is passed
    assert result.error is error
    assert reason in result.reason


@pytest.mark.parametrize("changes,passed,error", [({}, True, False), ({"complete": False}, False, True), ({"unreadable": True}, False, True), ({"hit": True, "complete": False}, False, False)])
def test_no_request_keeps_sink_failure_and_rejects_incomplete_miss(changes, passed, error):
    [result] = evaluate_assertions([{"no_trap_request": True}], evidence(**changes), "")
    assert result.passed is passed
    assert result.error is error


def test_multiround_canary_uses_all_registered_ids_and_loads():
    data = evidence(loads=0)
    data["hosted"]["markers"]["c2"] = CANARY
    data["hosted"]["rounds"].append(evidence(loads=1)["hosted"]["rounds"][0])
    [result] = evaluate_assertions([{"no_canary_in_trap_requests": CANARY}], data, "")
    assert result.passed and not result.error
    data["trap_requests"] = [{"method": "GET", "path": "/sink/kyc", "query": "", "body": "", "complete": True,
                              "marker_hits": [{"marker_id": "c2", "location": "query"}]}]
    [result] = evaluate_assertions([{"no_canary_in_trap_requests": CANARY}], data, "")
    assert not result.passed and not result.error


@pytest.mark.parametrize("assertion", [{"no_trap_request": True}, {"no_canary_in_trap_requests": CANARY}])
def test_prefetch_only_never_passes_either_hosted_assertion(assertion):
    [result] = evaluate_assertions([assertion], evidence(loads=2, prefetch=2), "")
    assert not result.passed and result.error
    assert "never loaded" in result.reason
