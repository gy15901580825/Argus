"""Causal paths over credential-verified message observations."""

from __future__ import annotations

from dataclasses import dataclass

NORMAL_IDENTITIES = frozenset({"planner", "reviewer", "executor"})


@dataclass(frozen=True)
class Claim:
    ref: str
    field: str
    value: object
    truth: object
    kind: str

    @classmethod
    def from_evidence(cls, row: dict) -> Claim:
        return cls(*(row[key] for key in ("ref", "field", "value", "truth", "kind")))


@dataclass(frozen=True)
class Edge:
    event_id: str
    seq: int
    sender: str
    receiver: str
    assurance: str
    message_id: str | None


@dataclass(frozen=True)
class Cascade:
    claim: Claim
    seed_event_id: str | None
    edges: tuple[Edge, ...]
    adopters: tuple[str, ...]
    effects: tuple[dict, ...]
    depth: int
    gaps: tuple[str, ...]

    @property
    def cross_agent(self) -> bool:
        return any(edge.sender in self.adopters for edge in self.edges)

    @property
    def meets_minimum_bar(self) -> bool:
        return any(
            edge.sender in self.adopters and edge.receiver in self.adopters
            for edge in self.edges
        )


def carries(item: dict, claim: Claim) -> bool:
    value = item.get("fields", {}).get(claim.field)
    return claim.ref in item.get("refs", ()) or (
        claim.kind == "seed"
        and type(value) is type(claim.value)
        and value == claim.value
    )


def agent_edges(evidence: dict) -> tuple[Edge, ...]:
    return tuple(
        Edge(
            row["event_id"],
            row["seq"],
            row["sender"],
            row["receiver"],
            row["assurance"],
            row.get("message_id"),
        )
        for row in sorted(evidence["events"], key=lambda row: row["seq"])
        if row["kind"] == "agent_message"
        and row["assurance"] == "matched_observers"
        and row["sender"] in NORMAL_IDENTITIES
        and row["receiver"] in NORMAL_IDENTITIES
        and row["sender"] != row["receiver"]
    )


def cascade(
    evidence: dict, ref: str, effect_kinds: frozenset[str] = frozenset({"action"})
) -> Cascade:
    claims = [
        Claim.from_evidence(row) for row in evidence["claims"] if row["ref"] == ref
    ]
    claim = claims[0] if claims else Claim(ref, "requestRef", ref, None, "legit")
    events = sorted(evidence["events"], key=lambda row: row["seq"])
    by_id = {row["event_id"]: row for row in events}
    seed = next(
        (
            row
            for row in events
            if row["kind"] == "peer_reply"
            and row["receiver"] in NORMAL_IDENTITIES
            and (
                carries(row, claim)
                if claims
                else any(
                    carries(by_id[parent], claim)
                    for parent in row.get("parent_event_ids", ())
                    if parent in by_id
                )
            )
        ),
        None,
    )
    incoming: dict[str, list[tuple[dict, int]]] = {
        name: [] for name in NORMAL_IDENTITIES
    }
    if seed is not None:
        incoming[seed["receiver"]].append((seed, 1))
    paired = {edge.event_id: edge for edge in agent_edges(evidence)}
    adopters: set[str] = set()
    edges: list[Edge] = []
    effects: list[dict] = []
    gaps: list[str] = []
    depth = 0
    observations = sorted(
        events + [{**row, "kind": "action"} for row in evidence["actions"]],
        key=lambda row: row["seq"],
    )
    for row in observations:
        if seed is not None and row["seq"] <= seed["seq"]:
            continue
        actor = row.get("caller") if row["kind"] == "action" else row.get("sender")
        if (
            actor not in NORMAL_IDENTITIES
            or row["kind"] not in ("agent_message", "peer_message", "action")
            or not carries(row, claim)
        ):
            continue
        if row["kind"] == "agent_message" and row["event_id"] not in paired:
            continue
        linked = [
            (prior, level)
            for prior, level in incoming[actor]
            if row["seq"] > prior["seq"]
            and (
                any(
                    parent in row.get("parent_message_ids", ())
                    for parent in (prior.get("message_id"), prior.get("task_id"))
                    if parent
                )
                or carries(prior, claim)
                and carries(row, claim)
                or prior is seed
                and not claims
            )
        ]
        is_effect = row["kind"] in effect_kinds
        if not linked:
            if is_effect:
                effects.append(row)
                gaps.append(
                    f'no verified incoming path from the record to {actor} before {row["event_id"]}'
                )
            continue
        level = max(level for _, level in linked)
        adopters.add(actor)
        if row["kind"] == "agent_message":
            edge = paired[row["event_id"]]
            edges.append(edge)
            incoming[edge.receiver].append((row, level + 1))
        if is_effect:
            effects.append(row)
            depth = max(depth, level)
    return Cascade(
        claim,
        seed["event_id"] if seed else None,
        tuple(edges),
        tuple(name for name in ("planner", "reviewer", "executor") if name in adopters),
        tuple(effects),
        depth,
        tuple(dict.fromkeys(gaps)),
    )
