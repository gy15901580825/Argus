from typing import Mapping, Sequence


def components(events: Sequence[Mapping]) -> int:
    roots = {event["event_id"]: event["event_id"] for event in events}

    def root(event_id):
        while roots[event_id] != event_id:
            event_id = roots[event_id]
        return event_id

    for event in events:
        for parent_id in event["parent_event_ids"]:
            roots[root(event["event_id"])] = root(parent_id)
    return len({root(event_id) for event_id in roots})


def ancestors(events: Sequence[Mapping], event_id: str) -> set[str]:
    by_id = {event["event_id"]: event for event in events}
    found: set[str] = set()
    pending = list(by_id[event_id]["parent_event_ids"])
    while pending:
        parent_id = pending.pop()
        if parent_id not in found:
            found.add(parent_id)
            pending.extend(by_id[parent_id]["parent_event_ids"])
    return found
