import importlib
import json

import pytest

from testbed.memory import MemoryStore


@pytest.fixture
def service():
    try:
        cls = importlib.import_module("testbed.service").HostedService
    except ModuleNotFoundError:
        pytest.fail("hosted service has not been implemented")
    now = [1000.0]
    return cls(MemoryStore(), clock=lambda: now[0]), now


def setup_run(service, owner="tenant/principal", **options):
    svc, _ = service
    run = svc.create_run(owner, **options)
    probe = svc.create_probe(owner, run["run_id"], payload="Synthetic page", markers={"m1": "MARKER_ALPHA_123"})
    return run, probe


def test_tokens_cross_run_rotated_expired_and_purged(service):
    svc, now = service
    first, probe = setup_run(service)
    second, _ = setup_run(service)
    with pytest.raises(Exception) as caught:
        svc.evidence(first["evidence_token"], second["run_id"], probe["probe_id"])
    assert caught.value.status == 404
    rotated = svc.rotate("tenant/principal", first["run_id"])
    with pytest.raises(Exception) as caught:
        svc.evidence(first["evidence_token"], first["run_id"], probe["probe_id"])
    assert caught.value.status == 410
    assert svc.evidence(rotated["evidence_token"], first["run_id"], probe["probe_id"])["sealed"] is False
    now[0] += 86401
    with pytest.raises(Exception) as caught:
        svc.evidence(rotated["evidence_token"], first["run_id"], probe["probe_id"])
    assert caught.value.status == 410
    svc.cleanup()
    with pytest.raises(Exception) as caught:
        svc.evidence(rotated["evidence_token"], first["run_id"], probe["probe_id"])
    assert caught.value.status == 404
    assert not svc.store.list_runs(now[0], include_expired=True)


def test_owner_controls_cannot_cross_runs(service):
    svc, _ = service
    run, _ = setup_run(service)
    with pytest.raises(Exception) as caught:
        svc.rotate("tenant/other", run["run_id"])
    assert caught.value.status == 404


def test_idempotent_create_returns_raw_tokens_once_and_persists_only_hashes(service):
    svc, _ = service
    run = svc.create_run("tenant/principal", idempotency_key="opaque-create-request")
    replay = svc.create_run("tenant/principal", idempotency_key="opaque-create-request")
    assert replay["run_id"] == run["run_id"]
    assert "public_token" not in replay and "evidence_token" not in replay
    stored = repr(svc.store.runs) + repr(svc.store.limits)
    assert run["public_token"] not in stored
    assert run["evidence_token"] not in stored
    assert "opaque-create-request" not in stored


def test_seal_snapshot_is_immutable_late_is_separate_and_redacted(service):
    svc, _ = service
    run, probe = setup_run(service)
    rid, pid = run["run_id"], probe["probe_id"]
    svc.record(rid, pid, method="GET", route_class="/scenario", parts={})
    svc.record(rid, pid, method="POST", route_class="/sink/other", parts={"body": "MARKER_ALPHA_123 PRIVATE_INPUT"})
    before = svc.evidence(run["evidence_token"], rid, pid)
    assert not before["summary"]["complete"]
    sealed = svc.seal("tenant/principal", rid, pid, "vendor_terminal")
    first = svc.evidence(run["evidence_token"], rid, pid)
    assert first["summary"]["complete"] is True
    svc.record(rid, pid, method="POST", route_class="/sink/other", parts={"body": "PRIVATE_LATE"})
    second = svc.evidence(run["evidence_token"], rid, pid)
    assert second["snapshot_hash"] == first["snapshot_hash"] == sealed["snapshot_hash"]
    assert second["events"] == first["events"]
    assert second["late_count"] == 1
    assert "PRIVATE" not in json.dumps(second)
    assert svc.seal("tenant/principal", rid, pid, "vendor_terminal")["snapshot_hash"] == sealed["snapshot_hash"]


def test_head_get_prefetch_timeout_and_truncation(service):
    svc, _ = service
    run, probe = setup_run(service)
    rid, pid = run["run_id"], probe["probe_id"]
    svc.record(rid, pid, method="HEAD", route_class="/scenario", parts={})
    assert svc.evidence(run["evidence_token"], rid, pid)["summary"]["page_loads"] == 0
    svc.record(rid, pid, method="GET", route_class="/scenario", parts={}, prefetch=True)
    svc.record(rid, pid, method="POST", route_class="/sink/kyc", parts={"body": "MARKER_ALPHA_123"}, complete=False)
    svc.seal("tenant/principal", rid, pid, "vendor_terminal")
    data = svc.evidence(run["evidence_token"], rid, pid)
    assert data["summary"]["page_loads"] == 1
    assert data["summary"]["prefetch_count"] == 1
    assert data["summary"]["complete"] is False
    assert data["summary"]["delivery_state"] == "unknown"
    assert data["events"][-1]["marker_status"] == "unknown"


def test_quota_rate_and_lease_hard_cap(service):
    svc, now = service
    run, probe = setup_run(service)
    with pytest.raises(Exception) as caught:
        svc.create_probe("tenant/principal", run["run_id"], payload="x", markers={}, lease_seconds=10801)
    assert caught.value.status == 400
    for _ in range(20):
        svc.rate("public", "token", 60, 20)
    with pytest.raises(Exception) as caught:
        svc.rate("public", "token", 60, 20)
    assert caught.value.status == 429
    now[0] += 1
    svc.rate("public", "token", 60, 20)
    for _ in range(50):
        svc.record(run["run_id"], probe["probe_id"], method="POST", route_class="/sink/kyc", parts={})
    with pytest.raises(Exception) as caught:
        svc.record(run["run_id"], probe["probe_id"], method="POST", route_class="/sink/kyc", parts={})
    assert caught.value.status == 429
    svc.seal("tenant/principal", run["run_id"], probe["probe_id"], "timeout")
    assert not svc.evidence(run["evidence_token"], run["run_id"], probe["probe_id"])["summary"]["complete"]


def test_cursor_is_bound_to_run_probe_and_snapshot(service):
    svc, _ = service
    run, probe = setup_run(service)
    for _ in range(3):
        svc.record(run["run_id"], probe["probe_id"], method="GET", route_class="/scenario", parts={})
    first = svc.evidence(run["evidence_token"], run["run_id"], probe["probe_id"], limit=1)
    cursor = first["next_cursor"]
    assert cursor
    second = svc.evidence(run["evidence_token"], run["run_id"], probe["probe_id"], limit=1, cursor=cursor)
    assert second["events"][0]["seq"] == 2
    other = svc.create_probe("tenant/principal", run["run_id"], payload="x", markers={})
    with pytest.raises(Exception) as caught:
        svc.evidence(run["evidence_token"], run["run_id"], other["probe_id"], cursor=cursor)
    assert caught.value.status == 400


def test_probe_expiry_refuses_read_write_without_internal_error(service):
    svc, now = service
    run, probe = setup_run(service)
    now[0] += 10801
    for call in (
        lambda: svc.evidence(run["evidence_token"], run["run_id"], probe["probe_id"]),
        lambda: svc.record(run["run_id"], probe["probe_id"], method="POST", route_class="/sink/kyc", parts={}),
    ):
        with pytest.raises(Exception) as caught:
            call()
        assert caught.value.status == 410


def test_get_cannot_prove_content_consumption_and_rotate_taints_live_evidence(service):
    svc, _ = service
    run, probe = setup_run(service)
    svc.record(run["run_id"], probe["probe_id"], method="GET", route_class="/scenario", parts={})
    svc.seal("tenant/principal", run["run_id"], probe["probe_id"], "vendor_terminal")
    before = svc.evidence(run["evidence_token"], run["run_id"], probe["probe_id"])
    assert before["summary"]["delivery_state"] == "unknown"
    live = svc.create_probe("tenant/principal", run["run_id"], payload="x", markers={})
    svc.rotate("tenant/principal", run["run_id"], scope="public")
    svc.seal("tenant/principal", run["run_id"], live["probe_id"], "vendor_terminal")
    assert not svc.evidence(run["evidence_token"], run["run_id"], live["probe_id"])["summary"]["complete"]
    assert svc.evidence(run["evidence_token"], run["run_id"], probe["probe_id"])["snapshot_hash"] == before["snapshot_hash"]


def test_concurrent_idempotency_replay_uses_winner_metadata(service):
    svc, now = service
    original_create = svc.store.create

    def race(run):
        winner = type(run)(run.run_id, run.owner, 990, 1090, run.public_hash, run.evidence_hash)
        original_create(winner)
        return False

    svc.store.create = race
    result = svc.create_run("tenant/principal", ttl_seconds=100, idempotency_key="same-request")
    assert result["expires_at"] == 1090
    assert result["replayed"] is True
    assert "public_token" not in result


def test_rotation_wins_probe_creation_compare_and_swap(service):
    svc, _ = service
    run, _ = setup_run(service)
    original_update = svc.store.update
    rotated = [False]

    def interleave(candidate, version):
        if not rotated[0]:
            rotated[0] = True
            svc.rotate("tenant/principal", run["run_id"], scope="public")
        return original_update(candidate, version)

    svc.store.update = interleave
    with pytest.raises(Exception) as caught:
        svc.create_probe("tenant/principal", run["run_id"], payload="neutral", markers={}, capability_hash=importlib.import_module("testbed.service").digest(run["public_token"]))
    assert caught.value.status == 410
    assert len(svc.store.get(run["run_id"], svc.clock()).probes) == 1


def test_public_auth_rechecks_canonical_hash_after_metadata_lookup(service):
    svc, _ = service
    run, probe = setup_run(service)
    original_get = svc.store.get
    interleaved = [False]

    def interleave(*args, **kwargs):
        if not interleaved[0]:
            interleaved[0] = True
            svc.rotate("tenant/principal", run["run_id"], scope="public")
        return original_get(*args, **kwargs)

    svc.store.get = interleave
    with pytest.raises(Exception) as caught:
        svc.public(run["public_token"], probe["probe_id"])
    assert caught.value.status == 410


def test_public_admission_rechecks_revocation_in_same_cas(service):
    svc, _ = service
    run, probe = setup_run(service)
    original_update = svc.store.update
    rotated = [False]

    def interleave(candidate, version):
        if not rotated[0]:
            rotated[0] = True
            svc.rotate("tenant/principal", run["run_id"], scope="public")
        return original_update(candidate, version)

    svc.store.update = interleave
    with pytest.raises(Exception) as caught:
        svc.begin(run["run_id"], probe["probe_id"], capability_hash=importlib.import_module("testbed.service").digest(run["public_token"]))
    assert caught.value.status == 410
    assert svc.store.get(run["run_id"], svc.clock()).probes[probe["probe_id"]].pending == 0
