from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Protocol

from argus.scenarios.credentials import ConnRef, CredentialProvider
from argus.scenarios.models import BudgetSpec, CleanupResult, ConnCheck, Evidence, ObjectRecord, ObjectSpec, ObserveSpec, object_marker


class BudgetExceeded(RuntimeError):
    pass


class NotReady(RuntimeError):
    pass


class Budget:
    def __init__(self, spec: BudgetSpec, clock=time.monotonic):
        self.spec, self.clock = spec, clock
        self.started = clock()
        self.counts = {"target_calls": 0, "third_party_calls": 0, "judge_usd": 0.0, "cleanup_calls": 0}

    def charge(self, kind: str, amount: int | float = 1, *, cleanup: bool = False):
        if cleanup:
            # Cleanup has its own bounded reserve so exhausted test budgets cannot strand objects.
            if self.counts["cleanup_calls"] + amount > 100:
                raise BudgetExceeded("cleanup call budget exhausted")
            self.counts["cleanup_calls"] += amount
            return
        self.check_wall()
        if amount < 0 or self.counts[kind] + amount > getattr(self.spec, kind):
            raise BudgetExceeded(f"{kind} budget exhausted")
        self.counts[kind] += amount

    def check_wall(self):
        if self.clock() - self.started >= self.spec.wall_s:
            raise BudgetExceeded("wall_s budget exhausted")

    def summary(self):
        return {**self.counts, "wall_s": max(0, self.clock() - self.started)}


@dataclass
class RunContext:
    run_id: str
    organization_id: str
    scenario_id: str
    connections: dict[str, str]
    target_identity: str
    allowed_ops: frozenset[str]
    budget: Budget
    registry: "ObjectRegistry"
    group: str = "baseline"
    control_name: str | None = None
    objects: dict[str, ObjectRecord] = field(default_factory=dict)
    cleanup_mode: bool = False
    secrets: set[str] = field(default_factory=set, repr=False)

    def connection(self, role: str) -> ConnRef:
        connection_id = self.connections.get(role)
        if not connection_id:
            raise NotReady(f"missing {role} connection")
        return ConnRef(connection_id=connection_id, role=role)

    def marker(self, key: str) -> str:
        return object_marker(self.run_id, self.group, key, self.control_name)

    def authorize(self, operation: str):
        if self.cleanup_mode and not (operation.endswith(".read") or operation.endswith(".delete_own")):
            raise NotReady("cleanup cannot create, send or mutate unrelated objects")
        if operation not in self.allowed_ops:
            raise NotReady(f"operation is not allowed: {operation}")

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: "[redacted]" if any(w in k.lower() for w in ["token", "secret", "authorization", "body", "content", "email", "recipient"]) else self.redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact(v) for v in value]
        if isinstance(value, str):
            for secret in self.secrets:
                if secret:
                    value = value.replace(secret, "[redacted]")
            return re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[email]", value, flags=re.I)
        return value


class ObjectRegistry:
    def __init__(self, directory: Path, run_id: str):
        self.path = directory / run_id / "objects.json"
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.records: dict[str, ObjectRecord] = {}
        if self.path.exists():
            for raw in json.loads(self.path.read_text()):
                obj = ObjectRecord.model_validate(raw)
                if obj.run_id != run_id:
                    raise ValueError("registry run identity mismatch")
                self.records[self.key(obj)] = obj

    @staticmethod
    def key(obj: ObjectRecord) -> str:
        return f"{obj.provider}:{obj.external_id}:{obj.marker}"

    def save(self, obj: ObjectRecord):
        self.records[self.key(obj)] = obj
        temp = self.path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump([o.model_dump(mode="json") for o in self.records.values()], out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, self.path)


class Driver(Protocol):
    name: str
    async def check(self, ctx: RunContext, ref: ConnRef, need: set[str]) -> ConnCheck: ...
    async def prepare(self, ctx: RunContext, key: str, spec: ObjectSpec) -> ObjectRecord: ...
    async def readiness(self, ctx: RunContext, check: Any) -> ConnCheck: ...
    async def snapshot(self, ctx: RunContext, scope: ObserveSpec) -> Any: ...
    async def collect(self, ctx: RunContext, scope: ObserveSpec, since: Any) -> list[Evidence]: ...
    async def cleanup(self, ctx: RunContext, obj: ObjectRecord) -> CleanupResult: ...
    async def recover(self, ctx: RunContext, scenario) -> list[ObjectRecord]: ...


def build_drivers(names: set[str], provider: CredentialProvider, config: dict | None = None) -> dict[str, Driver]:
    installed = {}
    for ep in sorted(entry_points(group="argus.drivers"), key=lambda e: (e.name, e.value)):
        if ep.name in installed:
            raise ValueError(f"ambiguous integration driver: {ep.name}")
        installed[ep.name] = ep
    missing = names - installed.keys()
    if missing:
        raise ValueError(f"integration drivers are not installed: {sorted(missing)}")
    return {name: installed[name].load()((config or {}).get(name, {}), provider) for name in names}
