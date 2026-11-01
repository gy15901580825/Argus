"""Build scenario events from recorded planted-object identifiers and observed evidence."""
from __future__ import annotations

from argus.events import Event, checked, iso_z, new_event
from argus.scenarios.models import Provenance, ScenarioResult

KIND = {"gdrive": "gdrive.file", "gmail": "gmail.message", "acs_email": "acs.email", "hosted_acs": "acs.email"}
READ_OPERATIONS = {"read", "retrieve", "search", "get", "fetch"}


def scenario_events(result: ScenarioResult) -> list[Event]:
    planted = {}
    for index, obj in enumerate(result.objects):
        if obj.logical_key != "folder" and obj.external_id != "pending-send":
            planted.setdefault(obj.marker, (index, obj))
    by_external_id = {}
    for marker, (_, obj) in planted.items():
        by_external_id.setdefault(obj.external_id, marker)

    def markers(row):
        if row.operation == "response" and row.provenance == Provenance.TARGET_SELF_REPORT:
            values = row.details.get("markers")
            return [value for value in values if isinstance(value, str)] if isinstance(values, list) else []
        if row.provenance == Provenance.TARGET_RUN_LOG:
            record = row.details.get("record")
            if not isinstance(record, dict):
                return []
            marker, object_id = record.get("marker"), record.get("object_id")
            if isinstance(marker, str) and marker in planted:
                return [marker]
            if isinstance(object_id, str) and object_id in by_external_id:
                return [by_external_id[object_id]]
            return []
        marker = row.details.get("marker")
        return [marker] if isinstance(marker, str) else []

    rows = [(index, row) for index, row in enumerate(result.evidence) if row.group == "test"]
    referenced = {marker for _, row in rows for marker in markers(row)}
    events: list[Event] = []
    objects = {}
    for marker, (index, obj) in planted.items():
        if marker not in referenced:
            continue
        kind = KIND.get(obj.provider)
        event = new_event(event_id=f"o:{obj.group}:{obj.logical_key}", parent_event_ids=[], ts=None, actor="argus",
                          operation="deliver_message" if obj.provider in {"acs_email", "hosted_acs", "gmail"} else "write_object",
                          object_ref=f"{kind}:{obj.external_id}" if kind else None, basis="observed",
                          source="integration_scenario", seq=index)
        objects[marker] = event
        events.append(event)
    responses = set()
    drafts = set()
    for index, row in rows:
        parents = [objects[marker].event_id for marker in markers(row) if marker in objects]
        object_ref = None
        if row.operation == "response" and row.provenance == Provenance.TARGET_SELF_REPORT:
            operation, actor, basis, ts = "invoke_agent", "argus", "observed", iso_z(row.observed_at)
        elif row.provenance == Provenance.TARGET_RUN_LOG:
            record = row.details.get("record")
            if (not isinstance(record, dict) or row.details.get("is_dry_run")
                    or str(record.get("operation", "")).lower() not in READ_OPERATIONS
                    or row.result not in {"success", "succeeded", "executed", "ok"}):
                continue
            operation, actor, basis, ts = "read_object", "target_agent", "reported", iso_z(row.occurred_at)
            response_id = row.details.get("response_event_id")
            if isinstance(response_id, str) and response_id in responses:
                parents.insert(0, response_id)
            obj = next((objects[marker] for marker in markers(row) if marker in objects), None)
            object_ref = obj.object_ref if obj else None
        elif row.provenance == Provenance.THIRD_PARTY_API and row.operation in {"draft_created", "draft_changed"}:
            key = (row.operation, row.object_id)
            if key in drafts:
                continue
            drafts.add(key)
            operation, actor, basis, ts = "write_object", "target_agent", "observed", iso_z(row.occurred_at)
            if row.source_system == "gmail" and row.object_id:
                object_ref = "gmail.message:" + row.object_id
        else:
            continue
        event = new_event(event_id=row.event_id, parent_event_ids=list(dict.fromkeys(parents)), ts=ts, actor=actor,
                          operation=operation, object_ref=object_ref, basis=basis,
                          source="integration_scenario", seq=len(result.objects) + index)
        events.append(event)
        if row.operation == "response" and row.provenance == Provenance.TARGET_SELF_REPORT:
            responses.add(event.event_id)
    return checked(events)
