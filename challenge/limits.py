from dataclasses import dataclass, field
from collections import deque
import math
import os
import time

from model import ModelClient, Usage


class BudgetExhausted(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    db_path: str = "challenge.sqlite3"
    model_base: str = ""
    model: str = "gpt-6-luna"
    model_key: str = field(default="", repr=False)
    trust_proxy: bool = False
    environment: str = "development"
    assessment_url: str = "https://at-helper.com"
    daily_budget: float = 20.0
    input_cost_per_million: float = 0.10
    output_cost_per_million: float = 0.50
    ip_submissions: int = 30
    session_submissions: int = 60
    session_ttl: int = 1800

    def __post_init__(self):
        for name in ("daily_budget", "input_cost_per_million", "output_cost_per_million"):
            if not math.isfinite(getattr(self, name)) or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive and finite")
        if min(self.ip_submissions, self.session_submissions, self.session_ttl) <= 0:
            raise ValueError("Submission limits and session lifetime must be positive")

    @classmethod
    def from_env(cls):
        defaults = cls()
        values = {}
        for name in cls.__dataclass_fields__:
            key = "CHALLENGE_ENV" if name == "environment" else "CHALLENGE_MODEL_BASE" if name == "model_base" else "CHALLENGE_" + name.upper()
            raw = os.environ.get(key)
            if raw is not None:
                if name == "trust_proxy":
                    if raw.casefold() not in {"true", "false", "1", "0"}:
                        raise ValueError("CHALLENGE_TRUST_PROXY must be true, false, 1 or 0")
                    values[name] = raw.casefold() in {"true", "1"}
                else:
                    values[name] = type(getattr(defaults, name))(raw)
        return cls(**values)


class IpLimiter:
    def __init__(self, limit: int):
        self.limit = limit
        self.events: dict[str, deque[float]] = {}

    def admit(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        for key in list(self.events):
            bucket = self.events[key]
            while bucket and bucket[0] <= now - 600:
                bucket.popleft()
            if not bucket:
                del self.events[key]
        bucket = self.events.setdefault(ip, deque())
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


class BudgetedModelClient:
    def __init__(self, model: ModelClient, store, settings: Settings):
        self.model, self.store, self.settings = model, store, settings

    def cost(self, usage: Usage) -> float:
        return (usage.input_tokens * self.settings.input_cost_per_million + usage.output_tokens * self.settings.output_cost_per_million) / 1_000_000

    async def complete(self, messages, tools):
        import json

        # Reserve a conservative byte-based token estimate before contacting the proxy;
        # a crash or failed response leaves the reservation charged rather than resetting it.
        size = len(json.dumps({"messages": messages, "tools": tools}, ensure_ascii=False).encode("utf-8")) + 256
        reservation = self.cost(Usage(size, 300))
        day = self.store.reserve(reservation, self.settings.daily_budget)
        if day is None:
            raise BudgetExhausted()
        reply = await self.model.complete(messages, tools)
        self.store.reconcile(day, reservation, self.cost(reply.usage))
        return reply
