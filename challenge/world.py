from dataclasses import dataclass, field
from typing import Any


@dataclass
class World:
    customers: dict[str, dict[str, Any]] = field(default_factory=dict)
    inbox_emails: list[dict[str, Any]] = field(default_factory=list)
    refunds: list[dict[str, Any]] = field(default_factory=list)
    outbound_emails: list[dict[str, Any]] = field(default_factory=list)
    vendors: list[dict[str, Any]] = field(default_factory=list)
    payments: list[dict[str, Any]] = field(default_factory=list)
    approvals: list[dict[str, Any]] = field(default_factory=list)
    internal_api_key: str = ""
    tool_descriptions: dict[str, str] = field(default_factory=dict)
    tool_exports: list[dict[str, Any]] = field(default_factory=list)
    invoice_documents: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TraceEntry:
    tool: str
    arguments: dict[str, Any]
    result: Any = None
    blocked_reason: str | None = None
