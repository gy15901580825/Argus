"""Evidence-backed finding events and graph rules are documented in docs/run-json.md."""
from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence

OPERATIONS = ("invoke_agent", "execute_tool", "deliver_message", "read_object", "write_object", "send_external")
BASES = ("observed", "reported")
SOURCES = ("a2a_world", "integration_scenario")
OBJECT_KINDS = ("a2a.message", "a2a.task", "acs.email", "gdrive.file", "gmail.message")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
_OBJECT_REF = re.compile(r"(?:" + "|".join(re.escape(kind) for kind in OBJECT_KINDS) + r"):\S+")
_ATLAS = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")
logger = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class Event:
    event_id: str
    parent_event_ids: list[str]
    ts: str | None
    actor: str
    operation: str
    tool_name: str | None = None
    tool_call_id: str | None = None
    object_ref: str | None = None
    basis: str
    atlas_technique: str | None = None
    source: str
    summary: str | None = None
    seq: int | None = None


def iso_z(value: datetime | None) -> str | None:
    if value is None or value.tzinfo is None or value.utcoffset() is None:
        return None
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{utc.microsecond // 1000:03d}Z"


def summarize(actor: str, operation: str, tool_name: str | None, object_ref: str | None) -> str:
    kind = object_ref.split(":", 1)[0] if object_ref else None
    return " ".join(part for part in (actor, operation, tool_name, kind) if part)[:200]


def new_event(**fields) -> Event:
    fields["summary"] = summarize(fields["actor"], fields["operation"], fields.get("tool_name"), fields.get("object_ref"))
    return Event(**fields)


def validate_events(events: Sequence[Mapping]) -> str | None:
    by_id: dict[str, Mapping] = {}
    seqs: set[int] = set()
    for event in events:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            return "event_id must be a nonempty string"
        if event_id in by_id:
            return f"duplicate event_id {event_id}"
        by_id[event_id] = event
        for name, allowed in (("operation", OPERATIONS), ("basis", BASES), ("source", SOURCES)):
            if event.get(name) not in allowed:
                return f"event {event_id} has unknown {name} {event.get(name)}"
        for name, pattern, reason in (
            ("ts", _TS, "is not ISO 8601 UTC with Z"),
            ("object_ref", _OBJECT_REF, "is not <kind>:<id> with a known kind"),
            ("atlas_technique", _ATLAS, "is not an ATLAS technique id"),
        ):
            value = event.get(name)
            if value is not None and (not isinstance(value, str) or pattern.fullmatch(value) is None):
                return f"event {event_id} {name} {reason}"
        summary = event.get("summary")
        if summary is not None and (not isinstance(summary, str) or len(summary) > 200):
            return f"event {event_id} summary is longer than 200 characters"
        if not isinstance(event.get("actor"), str) or not event["actor"]:
            return f"event {event_id} has an empty actor"
        parents = event.get("parent_event_ids")
        if not isinstance(parents, list) or any(not isinstance(parent, str) for parent in parents):
            return f"event {event_id} parent_event_ids must be a list of strings"
        seq = event.get("seq")
        if seq is not None:
            if type(seq) is not int or seq < 0:
                return f"event {event_id} seq must be a nonnegative integer or null"
            if seq in seqs:
                return f"duplicate event seq {seq}"
            seqs.add(seq)
    for event_id, event in by_id.items():
        for parent_id in event["parent_event_ids"]:
            if parent_id not in by_id:
                return f"event {event_id} has unresolved parent {parent_id}"
            parent_seq, seq = by_id[parent_id].get("seq"), event.get("seq")
            if parent_seq is not None and seq is not None and parent_seq >= seq:
                return f"event {event_id} seq is not after parent {parent_id}"
    colors: dict[str, int] = {}

    def visit(event_id: str) -> str | None:
        if colors.get(event_id) == 1:
            return f"event graph has a cycle through {event_id}"
        if colors.get(event_id) == 2:
            return None
        colors[event_id] = 1
        for parent_id in by_id[event_id]["parent_event_ids"]:
            if problem := visit(parent_id):
                return problem
        colors[event_id] = 2
        return None

    for event_id in by_id:
        if problem := visit(event_id):
            return problem
    return None


def checked(events: list[Event]) -> list[Event]:
    problem = validate_events([asdict(event) for event in events])
    if problem:
        logger.warning("dropping %d events: %s", len(events), problem)
        return []
    return events
