from __future__ import annotations

import asyncio
import re
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .session import Session

LEASE_DEFAULT_TTL_S = 300.0
LEASE_MIN_TTL_S = 30.0
LEASE_MAX_TTL_S = 3600.0
FIXED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")


class LeaseHeld(Exception):
    def __init__(self, expires_in: float):
        self.expires_in = expires_in
        super().__init__(f"lease held for {expires_in:.1f}s")


class LeaseMismatch(Exception):
    pass


class DynamicOnly(Exception):
    pass


@dataclass
class Lease:
    lease_id: str
    ttl_s: float
    expires_at: float


@dataclass(frozen=True)
class Route:
    ok: bool
    session: Session | None
    status: int
    reason: str | None


class FixedEndpoint:
    def __init__(self):
        self.lease: Lease | None = None
        self.active: Session | None = None
        self.generation = 0
        self.rejected: list[dict] = []
        self._session_ids: set[str] = set()
        self._lock = asyncio.Lock()

    def _expire(self, now: float) -> None:
        if self.lease and self.lease.expires_at <= now:
            self.lease = None
            self.active = None
            self._session_ids.clear()

    def acquire(self, ttl_s: float | None, now: float) -> Lease:
        self._expire(now)
        if self.lease:
            raise LeaseHeld(self.lease.expires_at - now)
        ttl = LEASE_DEFAULT_TTL_S if ttl_s is None else float(ttl_s)
        if not LEASE_MIN_TTL_S <= ttl <= LEASE_MAX_TTL_S:
            raise ValueError("ttl_s must be between 30 and 3600")
        self.lease = Lease(secrets.token_urlsafe(24), ttl, now + ttl)
        return self.lease

    def release(self, lease_id: str) -> bool:
        if not self.lease or self.lease.lease_id != lease_id:
            return False
        self.lease = None
        self.active = None
        self._session_ids.clear()
        return True

    def touch(self, lease_id: str, now: float) -> Lease:
        self._expire(now)
        if not self.lease or self.lease.lease_id != lease_id:
            raise LeaseMismatch()
        self.lease.expires_at = now + self.lease.ttl_s
        return self.lease

    def stop(self, session: Session) -> None:
        if self.active is session:
            self.active = None
            self._session_ids.clear()

    async def activate(self, lease_id: str, session: Session, now: float) -> int:
        async with self._lock:
            self.touch(lease_id, now)
            if session.sealed:
                raise ValueError("world is sealed")
            if session.scenario.dynamic_only or (
                session.world is not None and session.world.spec.second_tools is not None
            ):
                raise DynamicOnly()
            if self.active:
                previous = self.active
                self.stop(previous)
                await previous.seal()
            self.touch(lease_id, now)
            if session.sealed:
                raise ValueError("world is sealed")
            self.generation += 1
            self.active = session
            session.generation = self.generation
            session.fixed_endpoint = self
            return self.generation

    async def close(self, session: Session) -> None:
        async with self._lock:
            self.stop(session)
            await session.seal()

    def issue_session_id(self) -> str:
        session_id = f"g{self.generation}-{secrets.token_hex(8)}"
        self._session_ids.add(session_id)
        return session_id

    def route(self, header: str | None, method: str | None) -> Route:
        if self.active and self.active.sealed:
            self.stop(self.active)
        if not self.active:
            status, reason = 503, "no_active_generation"
        elif method == "initialize":
            return Route(True, self.active, 200, None)
        elif not header:
            status, reason = 400, "missing_session_id"
        elif header not in self._session_ids:
            status, reason = 404, "stale_session"
        else:
            return Route(True, self.active, 200, None)
        match = re.match(r"g(\d+)-", header or "")
        record = {
            "reason": reason,
            "status": status,
            "method": method,
            "presented_generation": int(match[1]) if match else None,
        }
        (self.active.rejected_requests if self.active else self.rejected).append(record)
        return Route(False, self.active, status, reason)
