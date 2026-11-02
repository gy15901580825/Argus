from __future__ import annotations

import asyncio
import time

import httpx

from .engine import (
    LegacyPreparedRequest,
    LegacyResponseSelector,
    TransportEngine,
    render_request,
)
from .models import (
    TransportContext,
    TransportOutcome,
    TransportResult,
    TransportSpec,
    SafeReasonCode,
)
from .security import ExecutionPolicy


def legacy_browser_spec(agent_url: str, timeout_s: float = 60) -> TransportSpec:
    return TransportSpec.from_dict(
        {
            "version": 1,
            "request": {
                "method": "POST",
                "url": agent_url,
                "headers": {},
                "body": {
                    "json": {
                        "url": {"context": "scenario_url"},
                        "prompt": {"context": "prompt"},
                    }
                },
            },
            "auth": {"kind": "none"},
            "response": {
                "format": "json",
                "text": {"paths": ["$.final_text"], "cast": "string", "empty": "error"},
                "metadata": {},
            },
            "outcome": {"kind": "http_only"},
            "delivery": {"kind": "sync"},
            "timeout": {"total_deadline_s": timeout_s, "read_s": timeout_s},
            "session": {"mode": "none"},
            "limits": {},
        }
    )


async def run_browser_transport(
    *,
    context: TransportContext,
    transport=None,
    agent_url=None,
    timeout_s=60,
    policy=None,
    redactor=None,
):
    if transport is not None:
        spec = (
            TransportSpec.from_dict(transport)
            if isinstance(transport, dict)
            else transport
        )
        return await TransportEngine(
            spec, policy=policy or ExecutionPolicy(), redactor=redactor
        ).run(context)
    spec = legacy_browser_spec(agent_url, timeout_s)
    request = LegacyPreparedRequest(
        spec.request.method,
        spec.request.url,
        {"Content-Type": "application/json"},
        render_request(spec.request, context),
        timeout_s,
    )
    start = time.monotonic()
    try:
        reply = await TransportEngine.run_legacy(
            request, LegacyResponseSelector(text_path="$.final_text")
        )
        if not reply.response_text.strip():
            return TransportResult(
                TransportOutcome.TARGET_ERROR,
                None,
                reply.latency_ms,
                200,
                None,
                SafeReasonCode.MAPPING_ERROR,
            )
        return TransportResult(
            TransportOutcome.SUCCEEDED,
            reply.response_text,
            reply.latency_ms,
            200,
            None,
            SafeReasonCode.OK,
        )
    except httpx.HTTPStatusError as exc:
        blocked = exc.response.status_code == 403
        return TransportResult(
            TransportOutcome.BLOCKED if blocked else TransportOutcome.TARGET_ERROR,
            None,
            (time.monotonic() - start) * 1000,
            exc.response.status_code,
            None,
            SafeReasonCode.TARGET_REFUSAL if blocked else SafeReasonCode.HTTP_ERROR,
        )
    except (TimeoutError, httpx.TimeoutException):
        return TransportEngine.failure(SafeReasonCode.TIMEOUT, start)
    except (httpx.HTTPError, ValueError, TypeError):
        return TransportEngine.failure(SafeReasonCode.NETWORK_ERROR, start)
