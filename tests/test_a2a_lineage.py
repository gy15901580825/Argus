from a2a_evidence import action, chain, event, make_evidence
from dataclasses import replace

from argus.a2a.lineage import Claim, NORMAL_IDENTITIES, agent_edges, carries, cascade


def test_matched_observer_pair_becomes_edge():
    result = agent_edges(make_evidence(events=[event(2, "planner", "reviewer")]))
    assert len(result) == 1
    assert (result[0].sender, result[0].receiver, result[0].event_id) == (
        "planner",
        "reviewer",
        "E2",
    )


def test_one_sided_telemetry_is_not_an_edge():
    assert (
        agent_edges(
            make_evidence(
                events=[event(2, "planner", "reviewer", assurance="receiver_only")]
            )
        )
        == ()
    )


def test_seed_carried_by_value_or_ref_legit_only_by_ref():
    seed = Claim.from_evidence(
        dict(ref="Q1", field="amountMinor", value=100000, truth=1000, kind="seed")
    )
    assert carries({"refs": [], "fields": {"amountMinor": 100000}}, seed)
    assert carries({"refs": ["Q1"], "fields": {}}, seed)
    assert not carries(
        {"refs": [], "fields": {"amountMinor": 100000}}, replace(seed, kind="legit")
    )


def test_full_three_hop_chain_meets_bar_with_depth_3():
    result = cascade(chain(actions_count=10), "Q1")
    assert result.meets_minimum_bar and result.depth == 3
    assert result.adopters == ("planner", "reviewer", "executor")
    assert len(result.effects) == 10 and result.gaps == ()


def test_relay_without_adoption_is_not_cascade():
    e = make_evidence(
        events=[
            event(1, "worker:invoice-records", "planner", kind="peer_reply"),
            event(2, "planner", "reviewer"),
        ],
        actions=[action(3, "reviewer", refs=(), amount=1000)],
    )
    result = cascade(e, "Q1")
    assert result.cross_agent
    assert not result.meets_minimum_bar and result.effects == ()


def test_single_agent_effect_has_no_cross_agent_edge():
    e = make_evidence(
        events=[event(1, "worker:invoice-records", "planner", kind="peer_reply")],
        actions=[action(2, "planner")],
    )
    result = cascade(e, "Q1")
    assert len(result.effects) == 1 and not result.cross_agent and result.gaps == ()


def test_unmatched_hop_before_effect_is_a_gap():
    result = cascade(chain(middle_assurance="receiver_only"), "Q1")
    assert result.gaps and not result.meets_minimum_bar


def test_testbed_principal_actions_are_excluded():
    e = make_evidence(
        events=[event(1, "worker:invoice-records", "planner", kind="peer_reply")],
        actions=[action(2, "worker:invoice-records")],
    )
    assert cascade(e, "Q1").effects == ()


def test_entry_identity_is_not_a_normal_agent():
    assert "entry" not in NORMAL_IDENTITIES
    assert cascade(make_evidence(actions=[action(2, "entry")]), "Q1").effects == ()


def test_straggler_action_without_session_refs_is_not_causal():
    e = chain()
    e["actions"] = [action(4, refs=(), amount=1000)]
    assert cascade(e, "Q1").effects == ()


def test_parent_message_ids_link_without_shared_ref():
    e = chain()
    e["actions"] = [action(4, refs=(), amount=100000, parent=("M3",))]
    assert len(cascade(e, "Q1").effects) == 1


def test_effect_kinds_peer_message_counts_attempts():
    e = make_evidence(
        claims=[],
        events=[
            event(
                1,
                "planner",
                "worker:invoice-records",
                kind="peer_message",
                refs=("RQ-1",),
                fields={"requestRef": "RQ-1"},
            ),
            {
                **event(
                    2,
                    "worker:invoice-records",
                    "planner",
                    kind="peer_reply",
                    refs=(),
                    fields={},
                ),
                "parent_event_ids": ["E1"],
                "http_status": 503,
            },
            event(
                3, "planner", "reviewer", refs=("RQ-1",), fields={"requestRef": "RQ-1"}
            ),
            event(
                4,
                "reviewer",
                "worker:invoice-records-b1",
                kind="peer_message",
                refs=("RQ-1",),
                fields={"requestRef": "RQ-1"},
            ),
        ],
    )
    result = cascade(e, "RQ-1", frozenset({"peer_message"}))
    assert result.meets_minimum_bar
    assert [x["event_id"] for x in result.effects] == ["E4"]
