"""Use only testbed parent events and target-reported parent message identifiers."""
from __future__ import annotations

from argus.a2a.world import validate
from argus.events import Event, checked, new_event

# Keep each trial's recorded order separate within one finding.
TRIAL_SEQ_STRIDE = 1_000_000


def events_from_trials(trials: list[tuple[int, dict]]) -> list[Event]:
    events: list[Event] = []
    for trial_index, (trial, evidence) in enumerate(trials):
        if validate(evidence) is not None or evidence["phase"] != "attack":
            continue
        if any(
            ("parent_event_ids" in row and (not isinstance(row["parent_event_ids"], list)
                                          or any(not isinstance(parent, str) for parent in row["parent_event_ids"])))
            or any(row.get(name) is not None and not isinstance(row[name], str) for name in ("message_id", "task_id"))
            for row in evidence["actions"]
        ):
            continue
        rows = evidence["events"] + evidence["actions"]
        raw_seqs = [row["seq"] for row in rows]
        raw_ids = [row["event_id"] for row in rows]
        if any(seq < 0 for seq in raw_seqs) or len(set(raw_seqs)) != len(rows) or len(set(raw_ids)) != len(rows):
            continue
        action_ids = {row["event_id"] for row in evidence["actions"]}
        offset = trial_index * TRIAL_SEQ_STRIDE if len(trials) > 1 else 0
        emitted: dict[str, Event] = {}
        messages: dict[str, list[Event]] = {}
        for row in sorted(rows, key=lambda row: row["seq"]):
            kind = None if row["event_id"] in action_ids else row["kind"]
            tool_name = None
            object_ref = None
            if kind in {"bootstrap_read", "card_read", "task_poll"}:
                continue
            if kind is None:
                actor, operation, tool_name, basis = row["caller"], "execute_tool", row["operation"], "observed"
            else:
                actor = row["sender"]
                basis = "reported" if kind == "agent_message" else "observed"
                if kind == "peer_reply":
                    operation = "deliver_message"
                    if row.get("task_id"):
                        object_ref = "a2a.task:" + row["task_id"]
                else:
                    operation = "send_external" if kind == "peer_message" and row.get("peer_trusted") is False else "invoke_agent"
                if object_ref is None and row.get("message_id"):
                    object_ref = "a2a.message:" + row["message_id"]
            parents: list[str] = []
            for parent_id in row.get("parent_event_ids", []):
                if parent_id in emitted:
                    parents.append(emitted[parent_id].event_id)
            for message_id in row["parent_message_ids"]:
                parents.extend(parent.event_id for parent in messages.get(message_id, []))
            event = new_event(event_id=f"t{trial}:{row['event_id']}", parent_event_ids=list(dict.fromkeys(parents)),
                              ts=None, actor=actor, operation=operation, tool_name=tool_name, object_ref=object_ref,
                              basis=basis, source="a2a_world", seq=offset + row["seq"])
            events.append(event)
            emitted[row["event_id"]] = event
            for message_id in dict.fromkeys(row.get(name) for name in ("message_id", "task_id")):
                if message_id:
                    messages.setdefault(message_id, []).append(event)
    return checked(events)
