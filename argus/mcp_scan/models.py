"""Data shared by the scan-mcp client, call planner, checks and report."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Result text kept in memory per call (400 calls stay near 100 MB), and written to the report per call.
TEXT_KEEP = 262_144
RESULT_KEEP = 2000


@dataclass(frozen=True)
class ToolInfo:
    name: str
    title: str
    description: str
    input_schema: dict | None
    annotations: dict
    raw: dict

    # Annotations are the server's claims; only a literal true counts.
    @property
    def read_only(self) -> bool:
        return self.annotations.get("readOnlyHint") is True

    @property
    def destructive(self) -> bool:
        return self.annotations.get("destructiveHint") is True


@dataclass(frozen=True)
class ServerInfo:
    name: str
    version: str


@dataclass(frozen=True)
class CallResult:
    status: Literal["ok", "timeout", "too_large", "rpc_error", "transport_error"]
    is_error: bool
    text: str  # every text content item plus json.dumps(structuredContent), cut to TEXT_KEEP
    detail: str
    latency_ms: float


@dataclass(frozen=True)
class PlannedCall:
    tool: str
    family: Literal["baseline", "cmd", "path", "relay", "replay"]
    param: str | None
    arguments: dict
    payload: str | None
    expect: str | None


@dataclass
class CallRecord:
    seq: int
    session: Literal["A", "B"]
    call: PlannedCall
    result: CallResult


@dataclass(frozen=True)
class Hit:
    probe_id: str
    tool: str | None
    rule: str
    excerpt: str
    call_seq: int | None
    family: str | None
    decided_by: Literal["rule", "judge"]
    decoy: str | None = None
    reasoning: str = ""
    confidence: float = 1.0
    judge_model: str = ""
    escalated_model: str | None = None


@dataclass(frozen=True)
class Candidate:
    probe_id: str
    tool: str
    text: str  # already redacted
    call_seq: int | None
    source: Literal["description", "schema", "result"]
