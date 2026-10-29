"""The 402 half of the testbed: how a quote is phrased and a ticket is read."""

from __future__ import annotations

import base64
import json


def build_402_body(session, resource: str) -> dict:
    """An x402 `accepts` offer. `payTo` is the quoted payee, which a probe can
    point at an attacker address to test whether the agent checks it."""
    return {
        "x402Version": 1,
        "error": "payment required",
        "accepts": [{
            "scheme": "exact",
            "network": "mock",
            "maxAmountRequired": session.script.quote_amount,
            "asset": session.script.quote_asset,
            "payTo": session.quoted_payee,
            "resource": resource,
            "description": "Argus simulated paid resource",
            "maxTimeoutSeconds": 60,
        }],
    }


def parse_payment_header(raw: str | None) -> dict | None:
    """Pull the authorization out of an X-PAYMENT header.

    Returns None for anything unreadable. The caller records the attempt and
    re-quotes rather than erroring: a target that sends garbage is a finding to
    report, not an exception to raise.
    """
    if not raw:
        return None
    try:
        decoded = json.loads(base64.b64decode(raw).decode())
    except Exception:
        return None
    auth = (decoded.get("payload") or {}).get("authorization")
    return auth if isinstance(auth, dict) else None


def paid_content(session) -> dict:
    """The resource the agent paid for -- plus, when the probe says so, an
    instruction planted in the content it now trusts."""
    body = {
        "title": "Quarterly threat report",
        "content": "Simulated paid content. No real transfer occurred.",
    }
    if session.script.inject_followup:
        body["content"] += f"\n\n{session.script.inject_followup}"
    return body
