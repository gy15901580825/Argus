from dataclasses import dataclass, field
from typing import Callable, Literal, Protocol, TypeVar


@dataclass
class Event:
    event_id: str
    seq: int
    kind: str
    route_class: str
    method: str
    complete: bool
    marker_status: str
    canary_hits: list[dict[str, str]]
    body_bytes: int = 0
    prefetch: bool = False
    epoch: str = ""
    timestamp: float = 0.0


@dataclass
class Probe:
    probe_id: str
    epoch: str
    expires_at: float
    payload: str
    markers: dict[str, str]
    combination: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    late_events: list[Event] = field(default_factory=list)
    dropped_events: int = 0
    page_loads: int = 0
    prefetch_count: int = 0
    pending: int = 0
    sealing: bool = False
    sealed: bool = False
    seal_reason: str = ""
    seal_revision: int = 0
    snapshot: dict | None = None
    snapshot_hash: str | None = None
    page_format: Literal["text", "html"] = "text"


@dataclass
class Run:
    run_id: str
    owner: str
    created_at: float
    expires_at: float
    public_hash: str
    evidence_hash: str
    version: int = 0
    retired_public: list[str] = field(default_factory=list)
    retired_evidence: list[str] = field(default_factory=list)
    probes: dict[str, Probe] = field(default_factory=dict)
    sink_count: int = 0
    event_count: int = 0
    deleted: bool = False


T = TypeVar("T")


class Store(Protocol):
    def create(self, run: Run) -> bool: ...
    def get(self, run_id: str, now: float, *, include_expired: bool = False) -> Run | None: ...
    def get_auth(self, run_id: str, now: float, *, include_expired: bool = False) -> Run | None: ...
    def list_auth(self, now: float, *, include_expired: bool = False) -> list[Run]: ...
    def update(self, run: Run, expected_version: int) -> bool: ...
    def list_runs(self, now: float, *, include_expired: bool = False) -> list[Run]: ...
    def purge(self, now: float) -> int: ...
    def atomic_limit(self, key: str, change: Callable[[dict], tuple[dict, T]]) -> T: ...
