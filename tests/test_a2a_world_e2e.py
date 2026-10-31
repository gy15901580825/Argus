import dataclasses
import json
from types import SimpleNamespace

import pytest

from argus import api
from argus.a2a.lineage import Claim, agent_edges, carries
from argus.demo import servers
from argus.local import run_local
from argus.probe import load_probe_library
from argus.runner import Runner
from argus.targets import build_target
from a2a_world_harness import DEMO_CAPABILITIES, serve_a2a_demo

P = "a2a_"
CELLS = []


def add(name, rows):
    for cell, weakness, caps, payload, expected, extra in rows:
        CELLS.append((P + name, cell, weakness, caps, payload, expected, extra))


add(
    "peer_impersonation",
    [
        ("naive", "naive", (), {}, "fail", "invoice-worker-2"),
        ("safe", "safe", (), {}, "pass", None),
        (
            "no_peer_capability",
            "naive",
            ("peer_http_json_1_0",),
            {},
            "skipped",
            "no_sessions",
        ),
    ],
)
add(
    "business_approval_replay",
    [
        ("naive", "naive", (), {}, "fail", "2 request(s)"),
        ("safe", "safe", (), {}, "pass", None),
        (
            "naive_new_message_id",
            "naive",
            (),
            {"deliveries": "replay_new_id"},
            "fail",
            None,
        ),
        (
            "safe_new_message_id",
            "safe",
            (),
            {"deliveries": "replay_new_id"},
            "pass",
            None,
        ),
        ("dedup_same_message", "dedup_message_id", (), {}, "pass", None),
        (
            "dedup_new_message_id",
            "dedup_message_id",
            (),
            {"deliveries": "replay_new_id"},
            "fail",
            None,
        ),
        ("no_receiver", "naive", ("target_receiver",), {}, "skipped", None),
    ],
)
add(
    "peer_result_injection",
    [
        ("naive", "naive", (), {}, "fail", None),
        ("safe", "safe", (), {}, "pass", "quoted"),
        (
            "naive_input_required",
            "naive",
            (),
            {"inject": "input_required"},
            "fail",
            None,
        ),
        ("safe_input_required", "safe", (), {"inject": "input_required"}, "pass", None),
    ],
)
add(
    "card_instruction_injection",
    [
        ("naive", "naive", (), {}, "fail", None),
        ("safe", "safe", (), {}, "pass", None),
        (
            "card_unread",
            "naive,skip_cards",
            (),
            {},
            "error",
            "code:attack_not_delivered",
        ),
    ],
)
add(
    "sensitive_peer_egress",
    [
        ("naive", "naive", (), {}, "fail", "TLS subcase not run"),
        ("safe", "safe", (), {}, "pass", "TLS subcase not run"),
        (
            "tls_declared_local",
            "safe",
            ("+production_tls_policy",),
            {},
            "error",
            "code:clean_control_failed|production_tls_policy",
        ),
    ],
)
add(
    "upstream_error_propagation",
    [
        ("naive", "naive", (), {}, "fail", "100000|truth 1000|cascaded across agents"),
        ("safe", "safe", (), {}, "pass", "seed_edge"),
        (
            "direct_large_payments",
            "naive,direct_large_payments",
            (),
            {},
            "warn",
            "not a cascade",
        ),
        (
            "lineage_gap",
            "naive,drop_reviewer_sent",
            (),
            {},
            "error",
            "code:lineage_incomplete",
        ),
        (
            "no_lineage_capability",
            "naive",
            ("observable_agent_lineage", "three_hop_chain"),
            {},
            "skipped",
            None,
        ),
        (
            "observers_off",
            "safe,observers_off",
            (),
            {},
            "error",
            "code:clean_control_failed|observable_agent_lineage",
        ),
        (
            "worker_action_excluded",
            "safe",
            (),
            {"noise": "worker_action"},
            "pass",
            "worker_action",
        ),
    ],
)
add(
    "retry_fanout_storm",
    [
        ("naive", "naive", (), {}, "fail", "reviewer"),
        ("safe", "safe", (), {}, "pass", "four_attempts"),
        ("retry_alone", "naive,retry_alone", (), {}, "warn", "budget symptom"),
        (
            "runaway_alone",
            "naive,retry_alone,runaway",
            (),
            {},
            "error",
            "code:observation_truncated",
        ),
        ("runaway_cascade", "naive,runaway", (), {}, "fail", "exhausted"),
    ],
)
add(
    "approval_trust_chain",
    [
        ("naive", "naive", (), {}, "fail", None),
        ("safe", "safe", (), {}, "pass", "seed_edge"),
    ],
)
add(
    "three_hop_error_amplification",
    [
        ("naive", "naive", (), {}, "fail", "depth 3|10 effect(s) vs limit 1"),
        ("safe", "safe", (), {}, "pass", None),
        ("no_three_hop_capability", "naive", ("three_hop_chain",), {}, "skipped", None),
        (
            "two_hop_only",
            "naive,two_hop_only",
            (),
            {},
            "error",
            "code:clean_control_failed|three_hop_chain",
        ),
    ],
)


def selected(probe_id):
    return next(p for p in load_probe_library(api.PROBES_DIR) if p.id == probe_id)


async def findings(spec, ids):
    events = [event async for event in run_local(spec, ids, env={})]
    return [event for event in events if "verdict" in event], events


async def one(spec, probe):
    target = build_target(spec)
    try:
        results = [
            dataclasses.asdict(f)
            async for f in Runner(target, SimpleNamespace(), api.RUBRICS_DIR).run_probe(
                probe
            )
        ]
        assert len(results) == 1
        return results[0]
    finally:
        await target.aclose()


@pytest.mark.parametrize(
    "probe_id,cell,weaknesses,caps,payload,expected,extra",
    CELLS,
    ids=[f"{c[0]}-{c[1]}" for c in CELLS],
)
async def test_a2a_world_cell(
    probe_id, cell, weaknesses, caps, payload, expected, extra
):
    capabilities = tuple(c for c in DEMO_CAPABILITIES if c not in caps) + tuple(
        c[1:] for c in caps if c.startswith("+")
    )
    probe = selected(probe_id)
    if payload:
        original = json.loads(probe.scenario_payload)
        probe = dataclasses.replace(
            probe, scenario_payload=json.dumps({**original, **payload})
        )
    with serve_a2a_demo(weaknesses, capabilities) as spec:
        finding = await one(spec, probe)
        session_count = len(spec.testbed.store.sessions)
    assert finding["verdict"] == expected, finding["reasoning"]
    if extra == "no_sessions":
        assert session_count == 0
        return
    if expected == "skipped":
        return
    trial = finding["evidence"]["trials"][0]
    attack = trial["attack"]
    if extra == "quoted":
        assert "share_document" in finding["target_response"]
    elif extra == "seed_edge":
        seed = Claim(**next(row for row in attack["claims"] if row["kind"] == "seed"))
        assert any(
            edge.sender == "planner"
            and edge.receiver == "reviewer"
            and carries(
                next(
                    row for row in attack["events"] if row["event_id"] == edge.event_id
                ),
                seed,
            )
            for edge in agent_edges(attack)
        )
    elif extra == "worker_action":
        assert any(
            row["caller"] == "worker:invoice-records" for row in attack["actions"]
        )
    elif extra == "four_attempts":
        case = attack["canaries"]["case_key"]
        attempts = [
            row
            for row in attack["events"]
            if row["kind"] == "peer_message"
            and row["sender"] in ("planner", "reviewer", "executor")
            and (case in row["refs"] or row["fields"].get("requestRef") == case)
        ]
        assert len(attempts) == 4 and len({row["message_id"] for row in attempts}) == 1
    elif extra == "exhausted":
        assert attack["budget"]["exhausted"] is True
    elif extra:
        for part in extra.split("|"):
            if part.startswith("code:"):
                assert trial["reason_code"] == part[5:]
            else:
                assert part in finding["reasoning"]


def test_matrix_has_every_designed_cell():
    assert len(CELLS) == 38 and len({(row[0], row[1]) for row in CELLS}) == 38
    expected = {
        "peer_impersonation": 3,
        "business_approval_replay": 7,
        "peer_result_injection": 4,
        "card_instruction_injection": 3,
        "sensitive_peer_egress": 3,
        "upstream_error_propagation": 7,
        "retry_fanout_storm": 5,
        "approval_trust_chain": 2,
        "three_hop_error_amplification": 4,
    }
    assert {
        name: sum(row[0] == P + name for row in CELLS) for name in expected
    } == expected
    assert all(
        {row[1] for row in CELLS if row[0] == P + name} >= {"naive", "safe"}
        for name in expected
    )


async def test_trials_two_run_four_fresh_worlds():
    probe = dataclasses.replace(selected("a2a_upstream_error_propagation"), trials=2)
    with serve_a2a_demo("safe") as spec:
        result = await one(spec, probe)
    trials = result["evidence"]["trials"]
    worlds = [trial[phase] for trial in trials for phase in ("clean", "attack")]
    assert len(trials) == 2 and len({w["session_id"] for w in worlds}) == 4
    assert len({w["canaries"]["case_key"] for w in worlds}) == 4
    assert len({row["ref"] for w in worlds for row in w["claims"]}) == 4
    assert result["verdict"] == "pass"


async def test_generic_testbed_agent_a2a_matches_a2a_agent():
    outcomes = []
    for generic in (False, True):
        with serve_a2a_demo("naive") as spec:
            if generic:
                spec.update(kind="testbed_agent", environment="a2a")
            result, _ = await findings(spec, ["a2a_peer_impersonation"])
            outcomes.append(result[0]["verdict"])
    assert outcomes == ["fail", "fail"]


async def test_a2a_world_run_needs_no_key():
    ids = sorted({row[0] for row in CELLS})
    with serve_a2a_demo("safe") as spec:
        result, events = await findings(spec, ids)
    assert len(result) == 9 and all(row["verdict"] == "pass" for row in result)
    assert not any(
        event.get("type") == "judge" or event.get("event") == "judge"
        for event in events
    )


async def test_local_testbed_url_runs_end_to_end():
    from argus.demo.a2a_testbed.demo_agent import app as demo

    with serve_a2a_demo("safe") as spec:
        spec["testbed_url"] = "local"
        with servers.local_testbed(spec) as resolved:
            demo.configure(
                peer_base_url=resolved["peer_url"],
                credentials=spec["agent_credentials"],
                driver_credential=spec["receiver"]["headers"][0][1],
                weaknesses="safe",
            )
            result, _ = await findings(resolved, ["a2a_peer_impersonation"])
    assert result[0]["verdict"] == "pass", result[0]["reasoning"]
