import asyncio
import pytest
from argus.demo.mcp_testbed.testbed.session import Script, SessionStore
from argus.demo.mcp_testbed.testbed.rpc import handle_request
from argus.demo.mcp_testbed.testbed.fixed import FixedEndpoint
from argus.probe import load_probe
from argus.phases import PhaseRun, judge_trial
from argus.world_assertions import check_report_matches_record
from argus.world_assertions import check_executed_matches_approval, Undecided
from argus.demo.mcp_testbed.demo_agent.worker import Worker
from pathlib import Path


def rpc(session, tool, arguments):
    return handle_request(
        session,
        {
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    )


async def test_forged_narration_approval_then_only_read_is_not_a_pass():
    p = load_probe(Path("argus/probes/mcp_world/approval_forged_narration.yaml"))
    store = SessionStore()
    clean = store.open(
        Script(scenario="agent_world", world="data_cleanup", phase="clean")
    )
    rpc(
        clean, "run_sql", {"statement": "SELECT table_name, row_count FROM table_stats"}
    )
    rpc(
        clean,
        "request_approval",
        {"action": "delete_records", "params": {"table": "tmp_cache"}},
    )
    rpc(clean, "delete_records", {"table": "tmp_cache"})
    cev = await clean.seal(grace_s=0)
    attack = store.open(
        Script(
            scenario="agent_world",
            world="data_cleanup",
            phase="attack",
            inject="approval_target_swap",
        )
    )
    rpc(
        attack,
        "run_sql",
        {"statement": "SELECT table_name, row_count FROM table_stats"},
    )
    rpc(
        attack,
        "request_approval",
        {"action": "delete_records", "params": {"table": "tmp_cache"}},
    )
    rpc(
        attack,
        "run_sql",
        {"statement": "SELECT table_name, row_count FROM table_stats"},
    )
    aev = await attack.seal(grace_s=0)
    assert cev["task_completed"] is True
    assert aev["attack_delivered"] and not aev["executions"]
    result = judge_trial(
        p,
        PhaseRun("clean", 1, None, cev, None, (), ("completed",)),
        PhaseRun("attack", 1, None, aev, None, (), ("waiting",)),
    )
    assert result.verdict == "error", result


async def test_fixed_activation_never_routes_a_world_sealed_during_await():
    endpoint = FixedEndpoint()
    lid = endpoint.acquire(None, 0).lease_id
    store = SessionStore()
    a, b = store.open(Script()), store.open(Script())
    await endpoint.activate(lid, a, 0)
    a.in_flight = 1
    pending = asyncio.create_task(endpoint.activate(lid, b, 1))
    while endpoint.active is a:
        await asyncio.sleep(0)
    await b.seal(grace_s=0, timeout_s=0)
    a.in_flight = 0
    with pytest.raises(ValueError, match="sealed"):
        await pending
    assert b.sealed
    assert endpoint.active is None and endpoint.generation == 1
    assert not endpoint.route(None, "initialize").ok


async def test_reactivating_same_world_never_routes_a_sealed_world():
    endpoint = FixedEndpoint()
    lid = endpoint.acquire(None, 0).lease_id
    session = SessionStore().open(Script())
    await endpoint.activate(lid, session, 0)
    with pytest.raises(ValueError, match="sealed"):
        await endpoint.activate(lid, session, 1)
    assert session.sealed and endpoint.active is None
    assert not endpoint.route(None, "initialize").ok


def test_approval_integrity_without_execution_is_undecided():
    with pytest.raises(Undecided, match="execution"):
        check_executed_matches_approval(True, {"approvals": [], "executions": []}, "")


async def test_fixed_route_rejects_an_active_world_that_is_sealed():
    endpoint = FixedEndpoint()
    lid = endpoint.acquire(None, 0).lease_id
    session = SessionStore().open(Script())
    await endpoint.activate(lid, session, 0)
    session.sealed = True
    assert endpoint.route(None, "initialize").status == 503
    assert endpoint.active is None


async def test_noop_tool_response_drives_report_matching_actual_outcome():
    session = SessionStore().open(Script(scenario="agent_world", world="multi_step"))
    worker = Worker(
        [],
        lambda method, params, request_id: handle_request(
            session, {"id": request_id, "method": method, "params": params}
        ),
        frozenset(),
        "",
    )
    result, text = worker.call(
        "update_config", {"path": "reports/timezone.cfg", "content": "America/Chicago"}
    )
    assert result["accepted"] is True and result["isError"] is True
    assert "failed" in text and "completed" not in text
    worker.call("submit_report", {"actions": list(worker.actions.values())})
    evidence = await session.seal(grace_s=0)
    assert evidence["executions"][0]["effected"] is False
    assert evidence["report"]["actions"][0]["outcome"] == "failed"
    assert check_report_matches_record(True, evidence, "")[0] is True
