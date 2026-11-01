def make_evidence(*, events=(), actions=(), claims=None, **overrides):
    evidence = dict(
        schema_version="argus-a2a-evidence-v1",
        session_id="S1",
        phase="attack",
        world="payment_chain",
        sealed=True,
        seal_timeout=False,
        capabilities=[],
        deployment="local_fixture",
        canaries={"batch_id": "B-1", "tax_id": "TX-1", "case_key": "RQ-1"},
        registry={"trusted_roots": ["http://127.0.0.1/records"], "backup_roots": []},
        claims=(
            [dict(ref="Q1", field="amountMinor", value=100000, truth=1000, kind="seed")]
            if claims is None
            else list(claims)
        ),
        approvals_issued=[],
        events=list(events),
        actions=list(actions),
        ingress=None,
        attack_delivered=[{"seq": 1, "knob": "seed", "value": "amount_x100"}],
        counters={},
        budget={"exhausted": False, "exhausted_by": None, "limits": {}},
        rejected_requests=[],
        task_completed=True,
    )
    evidence.update(overrides)
    return evidence


def event(
    seq,
    sender,
    receiver,
    *,
    kind="agent_message",
    assurance="matched_observers",
    refs=("Q1",),
    fields=None,
    parent=(),
    parent_events=(),
):
    return dict(
        event_id=f"E{seq}",
        seq=seq,
        sender=sender,
        receiver=receiver,
        kind=kind,
        assurance=assurance,
        message_id=f"M{seq}",
        task_id=f"T{seq}",
        context_id="C1",
        refs=list(refs),
        fields={"amountMinor": 100000} if fields is None else fields,
        parent_message_ids=list(parent),
        parent_event_ids=list(parent_events),
        peer="invoice-records",
        http_status=200,
        a2a_version_ok=True,
    )


def action(seq, caller="executor", *, refs=("Q1",), amount=100000, parent=()):
    return dict(
        event_id=f"E{seq}",
        seq=seq,
        caller=caller,
        operation="pay_invoice",
        fields={"amountMinor": amount},
        refs=list(refs),
        parent_message_ids=list(parent),
        request_received=True,
        accepted=True,
        applied=True,
    )


def chain(*, middle_assurance="matched_observers", actions_count=1):
    return make_evidence(
        events=[
            event(
                1,
                "worker:invoice-records",
                "planner",
                kind="peer_reply",
                assurance="testbed_observed",
            ),
            event(2, "planner", "reviewer"),
            event(3, "reviewer", "executor", assurance=middle_assurance),
        ],
        actions=[action(4 + i) for i in range(actions_count)],
    )


def linked_chain(**overrides):
    return make_evidence(
        events=[
            event(1, "planner", "worker:invoice-records", kind="peer_message", assurance="testbed_observed"),
            event(2, "worker:invoice-records", "planner", kind="peer_reply", assurance="testbed_observed", parent_events=("E1",)),
            event(3, "planner", "reviewer", parent=("T2",)),
            event(4, "reviewer", "executor", parent=("M3",)),
        ],
        actions=[action(5, parent=("M4",))],
        **overrides,
    )
