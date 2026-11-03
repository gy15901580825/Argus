import copy
import json
from datetime import datetime, timezone

from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from testbed.models import Event, Probe, Run


class Entity(dict):
    def __init__(self, data, version):
        super().__init__(copy.deepcopy(data))
        self.metadata = {"etag": str(version), "timestamp": datetime.now(timezone.utc)}


class Table:
    def __init__(self):
        self.rows = {}
        self.version = 0
        self.before_update = None
        self.before_delete = None

    def create_entity(self, entity):
        if (entity["PartitionKey"], entity["RowKey"]) in self.rows:
            raise ResourceExistsError("duplicate", status_code=409)
        self._save(entity)

    def _save(self, entity):
        for name in ("PartitionKey", "RowKey"):
            assert not any(c in entity[name] for c in "/\\#?")
            assert len(entity[name].encode("utf-16-le")) <= 1024
        assert all(len(v.encode("utf-16-le")) <= 65536 for v in entity.values() if isinstance(v, str))
        assert len(json.dumps(entity).encode()) < 1048576
        self.version += 1
        self.rows[(entity["PartitionKey"], entity["RowKey"])] = Entity(entity, self.version)

    def get_entity(self, partition_key, row_key):
        try:
            return copy.deepcopy(self.rows[(partition_key, row_key)])
        except KeyError:
            raise ResourceNotFoundError("missing", status_code=404)

    def update_entity(self, entity, *, mode, etag, match_condition):
        if self.before_update:
            hook, self.before_update = self.before_update, None
            hook()
        old = self.get_entity(entity["PartitionKey"], entity["RowKey"])
        assert match_condition == MatchConditions.IfNotModified
        if etag != old.metadata["etag"]:
            raise ResourceModifiedError("stale", status_code=412)
        self._save(entity)

    def query_entities(self, query_filter, *, parameters=None):
        parameters = parameters or {}
        rows = list(self.rows.values())
        if "partition" in parameters:
            rows = [r for r in rows if r["PartitionKey"] == parameters["partition"]]
        if "head" in parameters:
            rows = [r for r in rows if r["RowKey"] == parameters["head"]]
        if "now" in parameters:
            rows = [r for r in rows if r.get("expires_at", float("inf")) <= parameters["now"]]
        return copy.deepcopy(rows)

    def list_entities(self):
        return copy.deepcopy(list(self.rows.values()))

    def delete_entity(self, partition_key, row_key, **kwargs):
        if self.before_delete:
            hook, self.before_delete = self.before_delete, None
            hook()
        old = self.get_entity(partition_key, row_key)
        assert kwargs["match_condition"] == MatchConditions.IfNotModified
        if kwargs["etag"] != old.metadata["etag"]:
            raise ResourceModifiedError("stale", status_code=412)
        try:
            del self.rows[(partition_key, row_key)]
        except KeyError:
            raise ResourceNotFoundError("missing", status_code=404)


class Service:
    def __init__(self):
        self.tables = {}

    def create_table_if_not_exists(self, table_name):
        return self.get_table_client(table_name)

    def get_table_client(self, table_name):
        return self.tables.setdefault(table_name, Table())


def make_run(expires=200):
    event = Event("event1", 1, "sink", "/sink/other", "POST", True, "hit", [{"marker_id": "m1", "location": "body"}])
    probe = Probe("probe1", "epoch1", expires, "Synthetic page", {"m1": "SYNTHETIC"}, events=[event], sealed=True, snapshot={"events": [{"seq": 1}], "summary": {"complete": True}}, snapshot_hash="abc")
    return Run("run1", "owner1", 0, expires, "publichash", "evidencehash", probes={"probe1": probe}, event_count=1)


def backend(service=None, now=None):
    from testbed.tables import TablesStore
    return TablesStore("https://example.invalid", "hosted", client=service or Service(), clock=lambda: (now or [100])[0])


def test_sealed_evidence_survives_a_new_store_client():
    service = Service()
    store = backend(service)
    assert store.create(make_run())
    recovered = backend(service).get("run1", 100)
    assert recovered.probes["probe1"].snapshot_hash == "abc"
    assert recovered.probes["probe1"].snapshot["summary"]["complete"] is True
    assert recovered.probes["probe1"].events[0].canary_hits == [{"marker_id": "m1", "location": "body"}]


def test_page_format_persists_in_tables():
    service = Service()
    store = backend(service)
    run = make_run()
    run.probes["probe1"].page_format = "html"
    assert store.create(run)
    recovered = backend(service).get("run1", 100)
    assert recovered.probes["probe1"].page_format == "html"


def test_old_table_probe_defaults_to_text():
    service = Service()
    store = backend(service)
    run = make_run()
    original_blob = store._blob

    def legacy_blob(partition, value, expires_at):
        value = copy.deepcopy(value)
        if isinstance(value, dict) and "probes" in value:
            for probe in value["probes"].values():
                probe.pop("page_format", None)
        return original_blob(partition, value, expires_at)

    store._blob = legacy_blob
    assert store.create(run)
    recovered = backend(service).get("run1", 100)
    assert recovered.probes["probe1"].page_format == "text"
    assert set(service.tables) == {"hostedruns", "hostedevents", "hostedlimits"}


def test_stale_update_does_not_publish_candidate_evidence():
    service = Service()
    a, b = backend(service), backend(service)
    assert a.create(make_run())
    first, stale = a.get("run1", 100), b.get("run1", 100)
    first.sink_count = 5
    assert a.update(first, 0)
    stale.sink_count = 9
    assert not b.update(stale, 0)
    assert b.get("run1", 100).sink_count == 5
    assert b.get("run1", 100).version == 1


def test_expired_reads_writes_and_physical_purge():
    service, clock = Service(), [100]
    store = backend(service, clock)
    assert store.create(make_run(101))
    run = store.get("run1", 100)
    clock[0] = 101
    assert store.get("run1", 101) is None
    assert store.get("run1", 101, include_expired=True).run_id == "run1"
    assert store.list_runs(101) == []
    assert not store.update(run, 0)
    assert not store.create(make_run(100))
    assert store.purge(101) == 1
    assert store.get("run1", 101, include_expired=True) is None
    assert not service.tables["hostedruns"].rows
    assert not service.tables["hostedevents"].rows


def test_atomic_quota_retries_etag_conflict_without_losing_increment():
    service = Service()
    a, b = backend(service), backend(service)
    def increment(state):
        count = state.get("count", 0) + 1
        return {"count": count, "expires_at": 300}, count
    assert a.atomic_limit("quota/token?opaque", increment) == 1
    service.tables["hostedlimits"].before_update = lambda: b.atomic_limit("quota/token?opaque", increment)
    assert a.atomic_limit("quota/token?opaque", increment) == 3
    assert backend(service).atomic_limit("quota/token?opaque", increment) == 4


def test_large_evidence_fits_table_property_and_entity_bounds():
    service = Service()
    store = backend(service)
    run = make_run()
    probe = run.probes["probe1"]
    probe.events = [Event(str(i), i, "sink", "/sink/other", "POST", True, "miss", [], epoch="epoch1") for i in range(1000)]
    probe.snapshot = {"events": [vars(event) for event in probe.events], "summary": {"complete": True}}
    probe.payload = "S" * 100000
    assert store.create(run)
    recovered = backend(service).get("run1", 100)
    assert len(recovered.probes["probe1"].events) == 1000
    assert len(recovered.probes["probe1"].snapshot["events"]) == 1000
    assert recovered.probes["probe1"].payload == "S" * 100000


def test_expired_quota_starts_from_empty_state():
    now, service = [100], Service()
    store = backend(service, now)
    def increment(state):
        count = state.get("count", 0) + 1
        return {"count": count, "expires_at": now[0] + 1}, count
    assert store.atomic_limit("quota", increment) == 1
    now[0] = 101
    assert store.atomic_limit("quota", increment) == 1


def test_inflight_etag_conflict_keeps_published_evidence():
    service = Service()
    a, b = backend(service), backend(service)
    assert a.create(make_run())
    losing = a.get("run1", 100)
    losing.sink_count = 9
    def win():
        run = b.get("run1", 100)
        run.sink_count = 5
        assert b.update(run, 0)
    service.tables["hostedruns"].before_update = win
    assert not a.update(losing, 0)
    assert backend(service).get("run1", 100).sink_count == 5
    assert a.purge(100) == 0
    assert backend(service).get("run1", 100).sink_count == 5
    assert a.purge(200) == 1
    assert not service.tables["hostedevents"].rows


def test_unicode_fixture_obeys_property_bounds():
    service = Service()
    store = backend(service)
    run = make_run()
    run.probes["probe1"].payload = "\U0001f7e2" * 1310720
    assert store.create(run)
    assert backend(service).get("run1", 100).probes["probe1"].payload == "\U0001f7e2" * 1310720


def test_purge_does_not_delete_concurrently_renewed_quota():
    service, now = Service(), [100]
    a, b = backend(service, now), backend(service, now)
    assert a.atomic_limit("quota", lambda state: ({"expires_at": 101, "count": 1}, 1)) == 1
    now[0] = 101
    service.tables["hostedlimits"].before_delete = lambda: b.atomic_limit("quota", lambda state: ({"expires_at": 300, "count": 5}, 5))
    assert a.purge(101) == 0
    assert a.atomic_limit("quota", lambda state: ({"expires_at": 300, "count": state["count"]}, state["count"])) == 5


def test_auth_reads_work_without_accessing_missing_event_rows():
    service = Service()
    store = backend(service)
    run = make_run()
    run.retired_evidence = ["oldhash"]
    assert store.create(run)
    table = service.tables["hostedevents"]
    for key, entity in list(table.rows.items()):
        if '"event_id":"event1"' in entity["data"]:
            del table.rows[key]
    auth = store.get_auth("run1", 100)
    assert auth.owner == "owner1"
    assert auth.evidence_hash == "evidencehash"
    assert auth.retired_evidence == ["oldhash"]
    assert auth.probes == {}
    assert store.list_auth(100)[0].public_hash == "publichash"
    assert store.get_auth("run1", 200) is None
    assert store.get_auth("run1", 200, include_expired=True).evidence_hash == "evidencehash"


def test_partial_auth_metadata_is_an_error_not_missing_authorization():
    service = Service()
    store = backend(service)
    assert store.create(make_run())
    service.tables["hostedevents"].rows.clear()
    import pytest
    with pytest.raises(RuntimeError, match="Published evidence is missing"):
        store.get_auth("run1", 100)


def test_partial_auth_header_is_an_explicit_storage_error():
    service = Service()
    store = backend(service)
    assert store.create(make_run())
    for row in service.tables["hostedruns"].rows.values():
        if row["RowKey"] == "head":
            del row["auth_ref"]
    import pytest
    with pytest.raises(RuntimeError, match="Published evidence is missing"):
        store.get_auth("run1", 100)
