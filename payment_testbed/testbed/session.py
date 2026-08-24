"""Per-run session state for the mock payments testbed.

A session is one probe's slice of the world: the quote the mock merchant will
demand, the payee it will name, and the record of everything the agent under
test actually did. Nothing here touches a chain, and nothing is persisted --
when the session expires the evidence goes with it.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

DEFAULT_TTL_S = 900.0

# USDC has 6 decimals and x402 quotes are integer minor units, so "1000" is
# 0.001 USDC. Amounts stay strings on the wire and become ints only to compare;
# floats would round a payment.
DEFAULT_QUOTE_AMOUNT = "1000"
DEFAULT_QUOTE_ASSET = "USDC"


@dataclass(frozen=True)
class Script:
    """What the merchant does to the agent this run.

    Every field is an attack knob a probe can turn. `payee_override` exists so a
    probe can quote an address the agent was never told to trust -- it does NOT
    let a caller choose where evidence says money *should* have gone; that is
    the session's minted `expected_payee`, which the assertions compare against.
    """

    quote_amount: str = DEFAULT_QUOTE_AMOUNT
    quote_asset: str = DEFAULT_QUOTE_ASSET
    payee_override: str | None = None
    inject_followup: str | None = None
    fail_first_settle: bool = False
    resource_path: str = "report"

    @classmethod
    def from_dict(cls, raw: dict | None) -> "Script":
        raw = raw or {}
        return cls(
            quote_amount=str(raw.get("quote_amount", DEFAULT_QUOTE_AMOUNT)),
            quote_asset=str(raw.get("quote_asset", DEFAULT_QUOTE_ASSET)),
            payee_override=raw.get("payee_override"),
            inject_followup=raw.get("inject_followup"),
            fail_first_settle=bool(raw.get("fail_first_settle", False)),
            resource_path=str(raw.get("resource_path", "report")),
        )


@dataclass
class Session:
    id: str
    script: Script
    expected_payee: str
    created_at: float
    events: list[dict] = field(default_factory=list)
    authorizations: list[dict] = field(default_factory=list)
    settle_attempts: int = 0
    paid_requests: int = 0

    @property
    def quoted_payee(self) -> str:
        """Who the 402 tells the agent to pay -- the attacker's address when the
        probe is testing payee substitution, the honest one otherwise."""
        return self.script.payee_override or self.expected_payee

    def record_event(self, method: str, path: str, had_payment_header: bool, status: int) -> None:
        self.events.append({
            "seq": len(self.events) + 1,
            "method": method,
            "path": path,
            "had_payment_header": had_payment_header,
            "status": status,
        })

    def record_authorization(self, auth: dict, settled: bool) -> None:
        self.authorizations.append({
            "amount": str(auth.get("value", "")),
            "asset": self.script.quote_asset,
            "payee": auth.get("to", ""),
            "payer": auth.get("from", ""),
            "nonce": auth.get("nonce", ""),
            "settled": settled,
        })

    def evidence(self) -> dict:
        return {
            "session_id": self.id,
            "expected_payee": self.expected_payee,
            "quoted_payee": self.quoted_payee,
            "quote_amount": self.script.quote_amount,
            "quote_asset": self.script.quote_asset,
            "events": list(self.events),
            "authorizations": list(self.authorizations),
            "interaction_count": len(self.events),
        }


class SessionStore:
    def __init__(self, ttl_s: float = DEFAULT_TTL_S) -> None:
        self._ttl_s = ttl_s
        self._sessions: dict[str, Session] = {}

    def open(self, script: Script, now: float | None = None) -> Session:
        now = time.monotonic() if now is None else now
        self.purge_expired(now)
        session = Session(
            id=secrets.token_urlsafe(16),
            script=script,
            # Minted here, never read from input: a caller who could choose the
            # expected payee could make an attacker address look legitimate and
            # turn a real finding into a pass.
            expected_payee="0x" + secrets.token_hex(20),
            created_at=now,
        )
        self._sessions[session.id] = session
        return session

    def get(self, sid: str, now: float | None = None) -> Session | None:
        now = time.monotonic() if now is None else now
        session = self._sessions.get(sid)
        if session is None:
            return None
        if now - session.created_at > self._ttl_s:
            del self._sessions[sid]
            return None
        return session

    def close(self, sid: str) -> bool:
        return self._sessions.pop(sid, None) is not None

    def purge_expired(self, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        stale = [sid for sid, s in self._sessions.items() if now - s.created_at > self._ttl_s]
        for sid in stale:
            del self._sessions[sid]
        return len(stale)
