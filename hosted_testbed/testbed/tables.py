import hashlib
import json
import re
import time
from dataclasses import asdict
from uuid import uuid4

from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.data.tables import TableServiceClient, UpdateMode
from azure.identity import DefaultAzureCredential

from .models import Event, Probe, Run


class TablesStore:
    def __init__(self, endpoint, prefix, *, client=None, clock=time.time):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,56}", prefix):
            raise ValueError("Invalid table prefix")
        self.clock = clock
        self.client = client if client is not None else TableServiceClient(endpoint, credential=DefaultAzureCredential())
        self.runs = self.client.create_table_if_not_exists(prefix + "runs")
        self.events = self.client.create_table_if_not_exists(prefix + "events")
        self.limits = self.client.create_table_if_not_exists(prefix + "limits")

    @staticmethod
    def _partition(run_id):
        return hashlib.sha256(run_id.encode()).hexdigest()

    @staticmethod
    def _json(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @staticmethod
    def _get(table, partition, row):
        try:
            return table.get_entity(partition_key=partition, row_key=row)
        except ResourceNotFoundError:
            return None

    @staticmethod
    def _cas(table, entity, previous):
        try:
            if previous is None:
                table.create_entity(entity)
            else:
                table.update_entity(entity, mode=UpdateMode.REPLACE, etag=previous.metadata["etag"], match_condition=MatchConditions.IfNotModified)
            return True
        except (ResourceExistsError, ResourceModifiedError, ResourceNotFoundError):
            return False

    def _blob(self, partition, value, expires_at):
        data = self._json(value)
        digest = hashlib.sha256(data.encode()).hexdigest()
        keys = []
        for index, offset in enumerate(range(0, len(data), 16000)):
            key = f"data-{digest}-{index:06d}"
            entity = {"PartitionKey": partition, "RowKey": key, "expires_at": expires_at, "data": data[offset:offset + 16000]}
            try:
                self.events.create_entity(entity)
            except ResourceExistsError:
                pass
            keys.append(key)
        return {"digest": digest, "count": len(keys)}

    def _candidate(self, run, version):
        partition = self._partition(run.run_id)
        metadata = {name: value for name, value in vars(run).items() if name != "probes"}
        metadata["version"] = version
        metadata["probes"] = {}
        for probe_id, probe in run.probes.items():
            data = asdict(probe)
            for field in ("events", "late_events"):
                data[field] = [self._blob(partition, asdict(event), run.expires_at) for event in getattr(probe, field)]
            data["snapshot"] = None if probe.snapshot is None else self._blob(partition, probe.snapshot, run.expires_at)
            metadata["probes"][probe_id] = data
        revision = uuid4().hex
        keys = self._blob(partition, metadata, run.expires_at)
        manifest = {"PartitionKey": partition, "RowKey": "revision-" + revision, "expires_at": run.expires_at, "keys": self._json(keys)}
        self.runs.create_entity(manifest)
        auth = {name: value for name, value in metadata.items() if name != "probes"}
        return revision, self._blob(partition, auth, run.expires_at)

    def create(self, run):
        if run.deleted or run.expires_at <= self.clock():
            return False
        partition = self._partition(run.run_id)
        if self._get(self.runs, partition, "head") is not None:
            return False
        revision, auth_ref = self._candidate(run, 0)
        if run.expires_at <= self.clock():
            return False
        return self._cas(self.runs, {"PartitionKey": partition, "RowKey": "head", "run_id": run.run_id, "expires_at": run.expires_at, "revision": revision, "version": 0, "deleted": False, "auth_ref": self._json(auth_ref)}, None)

    def get(self, run_id, now, *, include_expired=False):
        partition = self._partition(run_id)
        head = self._get(self.runs, partition, "head")
        if head is None or (not include_expired and (head["expires_at"] <= now or head["deleted"])):
            return None
        manifest = self._get(self.runs, partition, "revision-" + head["revision"])
        if manifest is None:
            raise RuntimeError("Published evidence is missing")
        data = self._read_blob(partition, json.loads(manifest["keys"]))
        for probe_id, probe in data["probes"].items():
            for field in ("events", "late_events"):
                probe[field] = [Event(**self._read_blob(partition, keys)) for keys in probe[field]]
            if probe["snapshot"] is not None:
                probe["snapshot"] = self._read_blob(partition, probe["snapshot"])
            data["probes"][probe_id] = Probe(**probe)
        return Run(**data)

    def _read_blob(self, partition, reference):
        keys = [f"data-{reference['digest']}-{index:06d}" for index in range(reference["count"])]
        fragments = [self._get(self.events, partition, key) for key in keys]
        if any(fragment is None for fragment in fragments):
            raise RuntimeError("Published evidence is missing")
        return json.loads("".join(fragment["data"] for fragment in fragments))

    def get_auth(self, run_id, now, *, include_expired=False):
        partition = self._partition(run_id)
        head = self._get(self.runs, partition, "head")
        if head is None or (not include_expired and (head["expires_at"] <= now or head["deleted"])):
            return None
        if "auth_ref" not in head:
            raise RuntimeError("Published evidence is missing")
        data = self._read_blob(partition, json.loads(head["auth_ref"]))
        return Run(**data)

    def list_auth(self, now, *, include_expired=False):
        result = []
        for row in self.runs.query_entities("RowKey eq @head", parameters={"head": "head"}):
            if row["RowKey"] == "head":
                run = self.get_auth(row["run_id"], now, include_expired=include_expired)
                if run is not None:
                    result.append(run)
        return result

    def update(self, run, expected_version):
        partition = self._partition(run.run_id)
        head = self._get(self.runs, partition, "head")
        if head is None or head["version"] != expected_version or head["expires_at"] <= self.clock() or head["deleted"]:
            return False
        if run.expires_at != head["expires_at"]:
            raise ValueError("Run expiry is immutable")
        revision, auth_ref = self._candidate(run, expected_version + 1)
        if head["expires_at"] <= self.clock():
            return False
        entity = dict(head)
        entity.update(revision=revision, version=expected_version + 1, deleted=run.deleted, auth_ref=self._json(auth_ref))
        return self._cas(self.runs, entity, head)

    def list_runs(self, now, *, include_expired=False):
        result = []
        for row in self.runs.query_entities("RowKey eq @head", parameters={"head": "head"}):
            if row["RowKey"] == "head":
                run = self.get(row["run_id"], now, include_expired=include_expired)
                if run is not None:
                    result.append(run)
        return result

    def purge(self, now):
        removed = 0
        for table in (self.runs, self.events, self.limits):
            for row in table.query_entities("expires_at le @now", parameters={"now": now}):
                try:
                    table.delete_entity(partition_key=row["PartitionKey"], row_key=row["RowKey"], etag=row.metadata["etag"], match_condition=MatchConditions.IfNotModified)
                    removed += table is self.runs and row["RowKey"] == "head"
                except (ResourceNotFoundError, ResourceModifiedError):
                    pass
        return removed

    def atomic_limit(self, key, change):
        row_key = hashlib.sha256(key.encode()).hexdigest()
        for _ in range(32):
            previous = self._get(self.limits, "quota", row_key)
            state = {} if previous is None or previous["expires_at"] <= self.clock() else json.loads(previous["data"])
            replacement, result = change(state)
            encoded = self._json(replacement)
            if len(encoded.encode("utf-16-le")) > 65536:
                raise ValueError("Quota state exceeds table property limit")
            entity = {"PartitionKey": "quota", "RowKey": row_key, "data": encoded, "expires_at": replacement["expires_at"]}
            if self._cas(self.limits, entity, previous):
                return result
        raise RuntimeError("Quota update contention exceeded retry limit")
