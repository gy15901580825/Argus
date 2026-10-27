"""mitmproxy addon: pass Claude Code's own calls to the Anthropic API with the real key, record and refuse the rest.

Every request or connection attempt is one JSON line in the log, with these fields:
  ts         float, seconds since the epoch on the proxy's clock.
  method     the HTTP method; "CONNECT" for a tunnel request or a client that rejected the CA, "TCP" for
             non-HTTP bytes in a tunnel, "ERROR" for an error page mitmproxy built itself, "?" if recording failed.
  host, port where the bytes were going (the tunnel target, not the Host header); "" and 0 when unknown.
  path       path and query string; "" for CONNECT, TCP and unknown.
  headers    request headers, without x-api-key, authorization and proxy-authorization.
  body       refused non-Anthropic requests: the decoded body, first 64 KiB. Allowed Anthropic requests: "".
             Refused Anthropic requests: a JSON reason. ERROR rows: mitmproxy's error message.
  allowed    the policy decision: true only for Claude Code's own calls to api.anthropic.com. On ERROR rows
             it is the decision for the failed request, and false when that request is unknown.
  outcome    what happened: "forwarded" (sent upstream with the real key), "refused" (answered 403 or
             dropped), "intercepted" (tunnel accepted so the requests inside can be checked), "tls_failed",
             "upstream_error", "parse_error" (mitmproxy could not parse the request; answered 400),
             "proxy_error", or "unknown" (recording failed).
  markers_found  decoy markers seen in the host, path, headers or body, plain, lower-cased, or URL-, base64-
             or hex-encoded. An identity body is searched in full; a compressed one up to 64 MiB decoded.
             Always [] for api.anthropic.com, where markers are expected.
  scan_complete  false when markers_found may be missing a marker: the body search stopped at the 64 MiB
             decode cap or the scan-time budget, the body could not be decoded (only its raw bytes were
             searched), or the proxy never read the body (ERROR rows, the "record failed" row). True on
             api.anthropic.com rows, which are not searched by design.
  error, sni only on some rows: why a hook failed, and the SNI of a failed TLS handshake.
  rid        only on refused requests whose body is checked: such a request is written twice, at once on
             arrival (body "", markers_found [], scan_complete false) and again with the same rid and ts once
             its body is checked. A reader keeps the later row; the arrival row alone means the check never
             finished.

  model      on POST /v1/messages rows: the model the request named.
  max_tokens, body_bytes, reserve_usd   on POST /v1/messages rows: what the request asked for and the
             amount reserved against the task's cap when it was admitted.
  usage, cost_usd, status, msg_id   on a forwarded POST /v1/messages: the response's token usage, the charge
             in USD, the HTTP status and the response's message id. Written as a second row with the request's
             rid and ts once the response is in, or once the call failed (status 0, charged its reservation).

Request shape: a Messages or count_tokens call must look like the ones Claude Code 2.1.311 sends (measured in
live runs): only its top-level keys, content block types, tool fields, anthropic-beta values and headers.
Anything else is refused with a JSON reason, among them fast mode ("speed"), "fallbacks", "inference_geo",
"service_tier", unknown betas (long context among them), server tools, MCP servers, containers, URL or file
sources, and PDF documents, whose cost has no bound from their size.

Spend: each task may use only the models the host names, at most max_requests Messages and count_tokens
calls, and at most cap_usd. A Messages call is admitted only if the task's spend plus the reservations of its
calls in flight plus this call's reservation stays within the cap. The reservation is the call's worst case:
max_tokens of output (required, at most MAX_OUTPUT_TOKENS) and one input token per body byte plus
INPUT_PAD_TOKENS for the API's own framing and IMAGE_TOKENS per image, all priced as cache writes (1-hour ones
when the parsed body asks for them) at the long-prompt rate when the estimate is past the model's threshold.
A token is at least one byte of text, so for an allowed request the real charge never exceeds the
reservation. When the response arrives, the call settles to its real usage (for a stream, message_start's
usage overlaid by message_delta's). A call that fails, is dropped by its client, or has no readable usage
after it went upstream keeps its full reservation as its charge; only an Anthropic error answer is free.
Refusals carry a JSON reason, as do calls with no task set. So a task's spend never passes its cap.

Control: the host writes {"task", "seq", "drain", "models", "cap_usd", "max_requests"} to the file "control"
next to the log (root, over docker exec). A new task id resets the scan-time budget and the spend. The addon
answers {"task", "seq", "spent_usd", "reserved_usd", "requests", "denied_budget", "denied_model"} in
"control-ack" at once, or
with drain only after every refused request that arrived before it was written.
"""
from __future__ import annotations

import asyncio
import base64
import collections
import concurrent.futures
import functools
import json
import os
import sys
import threading
import time
import zlib
from urllib.parse import quote, quote_plus

from mitmproxy import http

try:
    import brotli
except ImportError:  # recorded raw if missing
    brotli = None
try:
    from compression import zstd
except ImportError:
    zstd = None

ANTHROPIC_HOST = "api.anthropic.com"
BODY_LIMIT = 64 * 1024
# Decoded bytes of a compressed body searched for decoy markers; the recorded body stays at BODY_LIMIT.
SCAN_LIMIT = 64 * 1024 * 1024
# Body scans run in one worker thread, off mitmproxy's event loop, and are capped so a stream of crafted
# bodies cannot burn the CPU: each gets at most SCAN_REQUEST_S, and all of them SCAN_BUDGET_S per SCAN_WINDOW_S.
SCAN_REQUEST_S = 5.0
SCAN_BUDGET_S = 20.0
SCAN_WINDOW_S = 60.0
FAILURE_SCAN_S = 0.2
_STEP = 1024 * 1024
_SECRET_HEADERS = {"x-api-key", "authorization", "proxy-authorization"}
# The Claude Code version the request-shape allowlist below was measured on; agent.Dockerfile installs this one.
CLAUDE_CODE_VERSION = "2.1.311"
# Paths Claude Code 2.1.311 calls with telemetry off (seen in a real run, count_tokens in its binary).
_ALLOWED_PATHS = {
    ("GET", "/api/claude_code/settings"),
    ("GET", "/api/claude_code/policy_limits"),
    ("POST", "/v1/messages"),
    ("POST", "/v1/messages/count_tokens"),
}
_MESSAGES = "/v1/messages"
_COUNT_TOKENS = "/v1/messages/count_tokens"
MAX_IN_FLIGHT = 8
# A Messages call must name max_tokens, at most this many. The sandbox pins Claude Code's to this value with a
# managed settings file, which Claude Code ranks above every other setting.
MAX_OUTPUT_TOKENS = 8192
OUTPUT_LIMIT_REASON = "request exceeded the output-token limit"
# The error on a cost row whose real charge passed its reservation; the host reports it as a high monitor note.
SETTLED_ABOVE = "settled above its reservation"
# Input tokens the API adds to a body (the tool-use system prompt and message framing): 527 measured for one
# tiny tool on count_tokens, so this is generous. Images cost at most about 4,784 tokens each.
INPUT_PAD_TOKENS = 2000
IMAGE_TOKENS = 5000
# (model id prefix, input, output, cache-read multiplier) in USD per million tokens, from the claude-api
# skill's pricing table (2026-10-06); the longest matching prefix wins, and an unknown model is charged the
# highest rate. Cache writes cost 1.25x input (5 min) or 2x (1 h).
_PRICES = (
    ("claude-fable-5-1", 10.0, 50.0, 0.025), ("claude-mythos-5-1", 10.0, 50.0, 0.025),
    ("claude-fable-5", 10.0, 50.0, 0.1), ("claude-mythos-5", 10.0, 50.0, 0.1),
    ("claude-opus-5-5", 4.0, 20.0, 0.05), ("claude-opus-5", 5.0, 25.0, 0.1), ("claude-opus-4-8", 5.0, 25.0, 0.1),
    ("claude-opus-4-7", 5.0, 25.0, 0.1), ("claude-opus-4-6", 5.0, 25.0, 0.1), ("claude-opus-4-5", 5.0, 25.0, 0.1),
    ("claude-opus-4", 15.0, 75.0, 0.1), ("claude-3-opus", 15.0, 75.0, 0.1),
    ("claude-sonnet-5", 2.0, 10.0, 0.1), ("claude-sonnet-4", 3.0, 15.0, 0.1), ("claude-3-7-sonnet", 3.0, 15.0, 0.1),
    ("claude-3-5-sonnet", 3.0, 15.0, 0.1),
    ("claude-haiku-5-5", 0.1, 0.5, 0.1), ("claude-haiku-4-5", 1.0, 5.0, 0.1), ("claude-3-5-haiku", 0.8, 4.0, 0.1),
    ("claude-3-haiku", 0.25, 1.25, 0.1),
)
_TOP_PRICE = (15.0, 75.0, 0.1)
# Long-prompt tiers: (prefix, prompt tokens above which, input and output multipliers). Sonnet 4.x charges 2x
# input and 1.5x output past 200K; Haiku 5.5 charges $0.50 / $2.50 past 100K.
_LONG_PROMPT = (("claude-sonnet-4", 200_000, 2.0, 1.5), ("claude-haiku-5-5", 100_000, 5.0, 5.0))
# The request shape Claude Code 2.1.311 sends (live runs on Sonnet 4.6, Haiku 4.5, Sonnet 5.5, Opus 5.5,
# Haiku 5.5 and Fable 5.1, 2026-10-27), plus a few fields that cannot change the charge (redacted_thinking, strict).
_TOP_KEYS = frozenset({"model", "max_tokens", "messages", "system", "tools", "stream", "metadata", "thinking",
                       "output_config", "context_management", "diagnostics"})
_BLOCK_KEYS = {
    "text": {"type", "text", "cache_control"},
    "thinking": {"type", "thinking", "signature", "cache_control"},
    "redacted_thinking": {"type", "data", "cache_control"},
    "tool_use": {"type", "id", "name", "input", "caller", "cache_control"},
    "tool_result": {"type", "tool_use_id", "content", "is_error", "cache_control"},
    "image": {"type", "source", "cache_control"},
}
_RESULT_BLOCKS = {"text", "image"}
_TOOL_KEYS = frozenset({"name", "description", "input_schema", "defer_loading", "strict", "eager_input_streaming",
                        "cache_control"})
_ALLOWED_BETAS = frozenset({
    "claude-code-20250219", "interleaved-thinking-2025-05-14", "context-management-2025-06-27",
    "prompt-caching-scope-2026-01-05", "thinking-token-count-2026-05-13", "advanced-tool-use-2025-11-20",
    "effort-2025-11-24", "thinking-binding-controls-2026-08-01", "thinking-display-updates-2026-08-18",
    "cache-diagnosis-2026-04-07", "per-turn-control-2026-07-01", "mid-conversation-tool-changes-2026-07-01",
    "mid-conversation-system-clear-at-2026-08-21",
})
_ALLOWED_HEADERS = frozenset({
    "accept", "accept-encoding", "connection", "content-length", "content-type", "host", "user-agent",
    "x-claude-code-session-id", "x-stainless-arch", "x-stainless-lang", "x-stainless-os",
    "x-stainless-package-version", "x-stainless-retry-count", "x-stainless-runtime",
    "x-stainless-runtime-version", "x-stainless-timeout", "anthropic-beta", "anthropic-dangerous-direct-browser-access",
    "anthropic-version", "x-app", "x-claude-code-prompt-id", "x-claude-code-request-class", "x-client-request-id",
    "x-claude-code-prev-tool-durations",
    "x-api-key", "authorization",
})
_API_VERSION = "2023-06-01"
_USAGE_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
_CACHE_KEYS = ("ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens")
_CONNECT_PORTS = {80, 443}
_FORBIDDEN = b"403 Forbidden\n"
# 400 is the only status mitmproxy uses for requests it could not parse; 502 comes from the upstream side.
_ERROR_LABELS = {400: "proxy refused a malformed request", 413: "request body too large",
                 502: "upstream connection or response failed"}
_ERROR_OUTCOMES = {400: "parse_error", 502: "upstream_error"}


def _sentinel() -> str:
    # Built by hand rather than with json.dumps so it cannot fail; the timestamp keeps it in the task window.
    return ('{"ts": %.6f, "method": "?", "host": "?", "port": 0, "path": "", "headers": {}, "body": "", '
            '"allowed": false, "outcome": "unknown", "markers_found": [], "scan_complete": false, '
            '"error": "record failed"}' % time.time())


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs):
    # Two parsers could pick different values for a repeated key; refuse instead of guessing.
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _DuplicateKey("duplicate key")
    return dict(pairs)


def _remote_fetches(node, found: list) -> None:
    """Collect URL and file sources anywhere in the body; Anthropic would fetch these with the real key."""
    if isinstance(node, dict):
        kind = node.get("type")
        # Image/document sources ({"type": "url"|"file", ...}) and container uploads by file id.
        if (kind in ("url", "file") and ("url" in node or "file_id" in node)) or \
                (kind == "container_upload" and "file_id" in node):
            found.append(node.get("url") or node.get("file_id"))
        for v in node.values():
            _remote_fetches(v, found)
    elif isinstance(node, list):
        for v in node:
            _remote_fetches(v, found)


def _unsafe_messages_body(raw: bytes) -> dict | None:
    """Return why a Messages body is refused (server-side tools, MCP, remote sources), or None if it is safe."""
    try:
        body = json.loads(raw or b"{}", object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return {"reason": "unparseable body" if not isinstance(e, _DuplicateKey) else "duplicate JSON key"}
    if not isinstance(body, dict):
        return {"reason": "unparseable body"}
    # Claude Code's own tools carry no type; any typed tool runs on Anthropic's side.
    typed = [t.get("type") for t in body.get("tools") or [] if isinstance(t, dict) and t.get("type") not in (None, "custom")]
    mcp = [s.get("url") for s in body.get("mcp_servers") or [] if isinstance(s, dict)]
    remote: list = []
    _remote_fetches(body, remote)
    if typed or "mcp_servers" in body or "container" in body or remote:
        return {"server_tools": typed, "mcp_servers": mcp, "container": "container" in body,
                "remote_sources": remote}
    return None


class _Shape(ValueError):
    """A request field Claude Code does not send; the message names the field, never its value."""


class _Document(_Shape):
    pass


def _keys(node, allowed, where: str) -> None:
    if not isinstance(node, dict):
        raise _Shape(f"{where} is not an object")
    extra = set(node) - set(allowed)
    if extra:
        raise _Shape(f"{where} has key {sorted(extra)[0][:64]!r}")


def _cache_control(node: dict, where: str, seen: dict) -> None:
    if "cache_control" not in node:
        return
    cc = node["cache_control"]
    _keys(cc, {"type", "ttl", "scope"}, where + " cache_control")
    if cc.get("type") != "ephemeral" or cc.get("ttl", "5m") not in ("5m", "1h") or \
            cc.get("scope", "global") != "global":
        raise _Shape(f"{where} cache_control value")
    seen["one_hour"] |= cc.get("ttl") == "1h"


def _blocks(content, where: str, types, seen: dict) -> None:
    if isinstance(content, str):
        return
    if not isinstance(content, list):
        raise _Shape(f"{where} content is not text or a list")
    for b in content:
        kind = b.get("type") if isinstance(b, dict) else None
        if kind == "document":
            raise _Document(f"{where} document block")
        if kind not in types:
            raise _Shape(f"{where} block type {str(kind)[:64]!r}")
        _keys(b, _BLOCK_KEYS[kind], f"{where} {kind} block")
        _cache_control(b, f"{where} {kind} block", seen)
        if kind == "image":
            src = b.get("source")
            _keys(src, {"type", "media_type", "data"}, "image source")
            if src.get("type") != "base64" or not isinstance(src.get("data"), str):
                raise _Shape("image source is not base64 data")
            seen["images"] += 1
        elif kind == "tool_use" and "caller" in b:
            _keys(b["caller"], {"type"}, "tool_use caller")
            if b["caller"].get("type") != "direct":
                raise _Shape("tool_use caller type")
        elif kind == "tool_result":
            _blocks(b.get("content", ""), "tool_result", _RESULT_BLOCKS, seen)


def request_shape(body: dict) -> dict:
    """Check a Messages or count_tokens body against Claude Code's shape; raise _Shape naming the first stray
    field. Returns what the reservation needs: {"one_hour": any 1-hour cache write asked, "images": count}."""
    seen = {"one_hour": False, "images": 0}
    _keys(body, _TOP_KEYS, "body")
    if not isinstance(body.get("model"), str):
        raise _Shape("model is not a string")
    if "stream" in body and not isinstance(body["stream"], bool):
        raise _Shape("stream is not a boolean")
    if "metadata" in body:
        _keys(body["metadata"], {"user_id"}, "metadata")
    if "diagnostics" in body:
        _keys(body["diagnostics"], {"previous_message_id"}, "diagnostics")
    if "thinking" in body:
        _keys(body["thinking"], {"type", "budget_tokens", "display"}, "thinking")
        if body["thinking"].get("type") not in ("adaptive", "enabled", "disabled"):
            raise _Shape("thinking type")
    if "output_config" in body:
        _keys(body["output_config"], {"effort"}, "output_config")
    if "context_management" in body:
        cm = body["context_management"]
        _keys(cm, {"edits"}, "context_management")
        for e in cm.get("edits") if isinstance(cm.get("edits"), list) else [None]:
            _keys(e, {"type", "keep"}, "context_management edit")
            if e.get("type") != "clear_thinking_20251015":
                raise _Shape(f"context_management edit type {str(e.get('type'))[:64]!r}")
    system = body.get("system", "")
    if not isinstance(system, str):
        _blocks(system, "system", {"text"}, seen)
    tools = body.get("tools", [])
    if not isinstance(tools, list):
        raise _Shape("tools is not a list")
    for t in tools:
        _keys(t, _TOOL_KEYS, "tool")
        if not isinstance(t.get("name"), str):
            raise _Shape("tool without a name")
        _cache_control(t, "tool", seen)
    messages = body.get("messages")
    if not isinstance(messages, list):
        raise _Shape("messages is not a list")
    for m in messages:
        _keys(m, {"role", "content", "output_config", "clear_at"}, "message")
        if m.get("role") not in ("user", "assistant", "system"):
            raise _Shape("message role")
        # A turn-scoped system message (Claude Code on Fable 5.1, mid-conversation-system-clear-at beta).
        if "clear_at" in m and (m["role"] != "system" or m["clear_at"] != "next_user_message"):
            raise _Shape("message clear_at")
        if "output_config" in m:
            _keys(m["output_config"], {"effort"}, "message output_config")
        _blocks(m.get("content"), "message", _BLOCK_KEYS, seen)
    return seen


def _header_refusal(headers) -> dict | None:
    """Refuse a header or anthropic-beta value Claude Code 2.1.311 does not send."""
    betas = []
    for k, v in headers.items():
        name = k.lower()
        if name not in _ALLOWED_HEADERS:
            return {"reason": "request header not allowed", "header": name[:64]}
        if name == "anthropic-version" and v.strip() != _API_VERSION:
            return {"reason": "request header not allowed", "header": name, "value": v[:64]}
        if name == "anthropic-beta":
            betas += [b.strip() for b in v.split(",") if b.strip()]
    unknown = sorted({b[:64] for b in betas} - _ALLOWED_BETAS)
    return {"reason": "anthropic-beta not allowed", "betas": unknown[:8]} if unknown else None


def check_request(raw: bytes, headers, query: str) -> tuple[dict | None, dict | None, dict]:
    """(body, None, shape) for a request shaped like Claude Code's, else (body or None, why refused, {})."""
    if query not in ("", "beta=true"):
        return None, {"reason": "request shape not allowed", "detail": "query string"}, {}
    why = _header_refusal(headers)
    if why is not None:
        return None, why, {}
    why = _unsafe_messages_body(raw)
    if why is not None:
        return None, why, {}
    body = json.loads(raw or b"{}")
    try:
        return body, None, request_shape(body)
    except _Document as e:
        return body, {"reason": "document content not allowed", "detail": str(e)}, {}
    except _Shape as e:
        return body, {"reason": "request shape not allowed", "detail": str(e)}, {}
    except RecursionError:
        return body, {"reason": "request shape not allowed", "detail": "nested too deeply"}, {}


def _count(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0


def _merge_usage(into: dict, usage) -> None:
    """Overlay usage onto into, keeping the larger count per field (message_delta repeats cumulative counts)."""
    if not isinstance(usage, dict):
        return
    for k in _USAGE_KEYS:
        if k in usage:
            into[k] = max(into.get(k, 0), _count(usage[k]))
    cc = usage.get("cache_creation")
    if isinstance(cc, dict):
        mine = into.setdefault("cache_creation", {})
        for k in _CACHE_KEYS:
            if k in cc:
                mine[k] = max(mine.get(k, 0), _count(cc[k]))


def usage_from_body(body: bytes) -> dict | None:
    """Token usage of a Messages response, plain JSON or a server-sent event stream; None if there is none."""
    text = body.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    usage: dict = {}
    if isinstance(doc, dict):
        if not isinstance(doc.get("usage"), dict):
            return None
        _merge_usage(usage, doc["usage"])
        return usage
    found = False
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            ev = json.loads(line[5:])
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "message_start" and isinstance(ev.get("message"), dict):
            u = ev["message"].get("usage")
        elif ev.get("type") == "message_delta":
            u = ev.get("usage")
        else:
            continue
        if isinstance(u, dict):
            found = True
            _merge_usage(usage, u)
    return usage if found else None


def price_usd(model: str, usage: dict, one_hour: bool = True) -> float:
    """USD for usage. Cache writes not split by lifetime are charged at the 1-hour rate, or at the 5-minute
    rate when one_hour is False (the request asked for no 1-hour writes)."""
    match = max((p for p in _PRICES if model.startswith(p[0])), key=lambda p: len(p[0]), default=None)
    inp, out, read_rate = match[1:] if match else _TOP_PRICE
    written = _count(usage.get("cache_creation_input_tokens"))
    cc = usage.get("cache_creation") if isinstance(usage.get("cache_creation"), dict) else {}
    hour = _count(cc.get("ephemeral_1h_input_tokens"))
    five = _count(cc.get("ephemeral_5m_input_tokens")) if cc else 0
    rest = max(written - hour - five, 0)
    hour, five = (hour + rest, five) if one_hour else (hour, five + rest)
    read = _count(usage.get("cache_read_input_tokens"))
    plain = _count(usage.get("input_tokens"))
    for prefix, threshold, in_x, out_x in _LONG_PROMPT:
        if model.startswith(prefix) and plain + written + read > threshold:
            inp, out = inp * in_x, out * out_x
    tokens_cost = (plain * inp + five * inp * 1.25 + hour * inp * 2 + read * inp * read_rate
                   + _count(usage.get("output_tokens")) * out)
    return tokens_cost / 1_000_000


def _request_model(body) -> str | None:
    model = body.get("model") if isinstance(body, dict) else None
    return model if isinstance(model, str) else None


def reserve_usd(model: str, body_bytes: int, max_tokens: int, one_hour_cache: bool = False, images: int = 0) -> float:
    """The most a call can cost: max_tokens of output, and one input token per body byte plus the API's framing
    and the image allowance, all as cache writes (the dearest input), at the long-prompt rate if it applies."""
    est = body_bytes + INPUT_PAD_TOKENS + IMAGE_TOKENS * images
    ttl = "ephemeral_1h_input_tokens" if one_hour_cache else "ephemeral_5m_input_tokens"
    return price_usd(model, {"output_tokens": max_tokens, "cache_creation_input_tokens": est,
                             "cache_creation": {ttl: est}})


def message_id(body: bytes) -> str | None:
    """The id of a Messages response (JSON, or a stream's message_start); None if there is none."""
    text = body.decode("utf-8", "replace")
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        return doc.get("id") if isinstance(doc.get("id"), str) else None
    for line in text.splitlines():
        if line.startswith("data:") and "message_start" in line:
            try:
                ev = json.loads(line[5:])
            except ValueError:
                continue
            msg = ev.get("message") if isinstance(ev, dict) else None
            if isinstance(msg, dict) and isinstance(msg.get("id"), str):
                return msg["id"]
    return None


def _stream_finished(body: bytes) -> bool:
    """A plain JSON body, or a stream that reached message_delta (its final usage)."""
    text = body.decode("utf-8", "replace")
    try:
        json.loads(text)
        return True
    except ValueError:
        pass
    return any(line.startswith("data:") and '"message_delta"' in line for line in text.splitlines())


def _anthropic_error(body: bytes) -> bool:
    try:
        doc = json.loads(body or b"")
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False
    return isinstance(doc, dict) and doc.get("type") == "error"


def generic_error(status_code: int, message: str = "") -> bytes:
    return f"{status_code} Error\n".encode()


def _encoding(req) -> str:
    return (req.headers.get("content-encoding") or "identity").strip().lower()


def _decoded_chunks(raw: bytes, enc: str, limit: int, state: dict | None = None):
    """Yield the decoded body in pieces, at most limit bytes in all, never expanding more (decompression bombs).

    gzip members and zstd frames are decoded one after another. Raises on a corrupt body. state["complete"]
    is set true only when the whole body was decoded within limit and the generator ran to its end.
    """
    state = {} if state is None else state
    state["complete"] = False
    total = 0
    wbits = {"gzip": 16 + zlib.MAX_WBITS, "x-gzip": 16 + zlib.MAX_WBITS, "deflate": zlib.MAX_WBITS}.get(enc)
    if wbits is not None:
        data = raw
        while data:
            d = zlib.decompressobj(wbits)
            while not d.eof:
                if total >= limit:
                    return
                out = d.decompress(data, min(_STEP, limit - total))
                data = d.unconsumed_tail
                if not out and not data:
                    return  # truncated
                total += len(out)
                yield out
            data = d.unused_data
            if enc == "deflate":
                break
        state["complete"] = not data
    elif enc == "br" and brotli is not None:
        d = brotli.Decompressor()
        # The output buffer limit is approximate, so the total is capped here as well.
        out = d.process(raw, output_buffer_limit=_STEP)
        while True:
            if out:
                if len(out) > limit - total:
                    yield out[:limit - total]
                    return
                total += len(out)
                yield out
            if d.is_finished():
                state["complete"] = True
                return
            out = d.process(b"", output_buffer_limit=_STEP)
            if not out and not d.is_finished():
                return  # truncated
    elif enc == "zstd" and zstd is not None:
        data = raw
        while data:
            d = zstd.ZstdDecompressor()
            out = d.decompress(data, max_length=min(_STEP, limit - total))
            while True:
                total += len(out)
                if out:
                    yield out
                if d.eof:
                    break
                if total >= limit or d.needs_input:
                    return  # cap reached, or a truncated frame
                out = d.decompress(b"", max_length=min(_STEP, limit - total))
            data = d.unused_data
        state["complete"] = True
    else:  # identity and encodings we cannot decode
        for i in range(0, min(len(raw), limit), _STEP):
            yield raw[i:min(i + _STEP, limit)]
        state["complete"] = enc in ("identity", "") and len(raw) <= limit


def _base64_forms(m: bytes) -> set[bytes]:
    """The part of a base64 encoding that depends only on m, for m at each of the three byte alignments."""
    forms = set()
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + m).rstrip(b"=")
        # Characters wholly inside m's bits: skip ones shared with the bytes before and after it.
        part = enc[-(-8 * k // 6):(8 * (k + len(m))) // 6]
        forms |= {part, part.replace(b"+", b"-").replace(b"/", b"_")}
    return forms


def marker_forms(markers) -> dict[bytes, str]:
    """Each byte string to search for, mapped to the marker it reveals."""
    forms = {}
    for m in markers:
        b = m.encode()
        # Lower case too: host names are case-insensitive and some clients lower-case them.
        variants = {b, b.lower(), quote(m, safe="").encode(), quote_plus(m).encode(), b.hex().encode(),
                    b.hex().upper().encode(), "".join("%%%02X" % c for c in b).encode(),
                    "".join("%%%02x" % c for c in b).encode()}
        for v in variants | _base64_forms(b):
            if len(v) >= 8:  # shorter forms would match by chance
                forms[v] = m
    return forms


class _Scanner:
    """Search a stream of chunks for marker forms, carrying an overlap across chunk edges."""

    def __init__(self, forms: dict[bytes, str]):
        self._forms = dict(forms)
        self._keep = max((len(f) for f in forms), default=1) - 1
        self._tail = b""
        self.found: set[str] = set()

    def feed(self, chunk: bytes) -> None:
        if not self._forms:
            return
        buf = self._tail + chunk
        for f in [f for f in self._forms if f in buf]:
            self.found.add(self._forms.pop(f))
        self._tail = buf[-self._keep:] if self._keep else b""

    def restart(self) -> None:
        self._tail = b""

    def feed_text(self, *texts) -> None:
        for t in texts:
            self.restart()
            self.feed(str(t).encode("utf-8", "surrogateescape"))
        self.restart()


def _fail_closed(hook):
    # mitmproxy logs and swallows hook exceptions and lets the flow continue; refuse it instead.
    @functools.wraps(hook)
    def wrapper(self, obj):
        try:
            return hook(self, obj)
        except Exception as e:  # noqa: BLE001
            self._record_failure(hook.__name__, obj, e)
    return wrapper


class ArgusProxy:
    def __init__(self, real_key: str, log_path: str, markers=()):
        self._key = real_key
        self._log_path = log_path
        self._forms = marker_forms(markers)
        # Where a failed request was going, keyed by its client connection (HTTP/1 only, one request at a time).
        self._error_targets: dict[str, tuple] = {}
        # (monotonic end time, seconds) of recent body scans, for the shared scan-time budget.
        self._scan_spent: collections.deque = collections.deque()
        self._budget_lock, self._write_lock = threading.Lock(), threading.Lock()
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None
        # Refused requests whose scan row is not written yet, by arrival number.
        self._state_lock = threading.Lock()
        self._arrivals, self._pending = 0, set()
        log_dir = os.path.dirname(log_path)
        self._control_path = os.path.join(log_dir, "control")
        self._ack_path = os.path.join(log_dir, "control-ack")
        self._task: str | None = None
        self._acked = 0
        self._drain_mark: tuple[int, int] | None = None
        # This task's limits (None until the host sets a task: Messages calls are refused) and its spend.
        self._spend_lock = threading.Lock()
        self._limits: dict | None = None
        self._spend = self._new_spend()
        self._calls = 0

    @staticmethod
    def _new_spend() -> dict:
        return {"spent_usd": 0.0, "reserved_usd": 0.0, "requests": 0, "denied_budget": 0, "denied_model": 0,
                "in_flight": 0}

    def set_task(self, task: str, models, cap_usd, max_requests) -> None:
        """Start a task: its allowed models, USD cap and Messages call limit; spend starts at zero."""
        limits = None
        if isinstance(models, list) and all(isinstance(m, str) for m in models) and \
                isinstance(cap_usd, (int, float)) and not isinstance(cap_usd, bool) and cap_usd > 0 and \
                isinstance(max_requests, int) and not isinstance(max_requests, bool) and max_requests > 0:
            limits = {"models": set(models), "cap_usd": float(cap_usd), "max_requests": max_requests}
        with self._spend_lock:
            self._task, self._limits, self._spend = task, limits, self._new_spend()
        with self._budget_lock:
            self._scan_spent.clear()

    def _check_model(self, model, sp: dict, lim: dict | None) -> dict | None:
        """Why a call naming model is refused before any spend check, or None. Caller holds _spend_lock."""
        if lim is None:
            return {"reason": "no task budget set"}
        if model not in lim["models"]:
            sp["denied_model"] += 1
            return {"reason": "model not allowed", "model": model, "allowed": sorted(lim["models"])}
        if sp["requests"] >= lim["max_requests"]:
            sp["denied_budget"] += 1
            return {"reason": "task request limit reached", "requests": sp["requests"]}
        return None

    def _admit(self, body: dict, body_bytes: int, shape: dict) -> tuple[dict | None, str | None, float]:
        """(None, model, reserve) if this Messages call may go upstream now, else (why it is refused, model, 0)."""
        model = _request_model(body)
        max_tokens = body.get("max_tokens")
        with self._spend_lock:
            lim, sp = self._limits, self._spend
            if (why := self._check_model(model, sp, lim)) is not None:
                return why, model, 0.0
            if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
                return {"reason": "max_tokens missing", "max_tokens": None}, model, 0.0
            if max_tokens > MAX_OUTPUT_TOKENS:
                return {"reason": OUTPUT_LIMIT_REASON, "max_tokens": max_tokens,
                        "limit": MAX_OUTPUT_TOKENS}, model, 0.0
            reserve = reserve_usd(model, body_bytes, max_tokens, shape["one_hour"], shape["images"])
            if sp["spent_usd"] + sp["reserved_usd"] + reserve > lim["cap_usd"]:
                sp["denied_budget"] += 1
                return {"reason": "task budget exhausted", "spent_usd": round(sp["spent_usd"], 6),
                        "reserved_usd": round(sp["reserved_usd"], 6), "call_reserve_usd": round(reserve, 6),
                        "cap_usd": lim["cap_usd"]}, model, 0.0
            if sp["in_flight"] >= MAX_IN_FLIGHT:
                return {"reason": "too many Messages calls at once", "in_flight": sp["in_flight"]}, model, 0.0
            sp["requests"] += 1
            sp["in_flight"] += 1
            sp["reserved_usd"] += reserve
            return None, model, reserve

    def _admit_count(self, body: dict) -> tuple[dict | None, str | None]:
        """count_tokens is free upstream, but counts toward the call limit and takes only the scan's models."""
        model = _request_model(body)
        with self._spend_lock:
            if (why := self._check_model(model, self._spend, self._limits)) is not None:
                return why, model
            self._spend["requests"] += 1
            return None, model

    def _settle(self, task: str, reserve: float, cost: float) -> None:
        with self._spend_lock:
            if task == self._task:
                self._spend["spent_usd"] += cost
                self._spend["reserved_usd"] = max(self._spend["reserved_usd"] - reserve, 0.0)
                self._spend["in_flight"] = max(self._spend["in_flight"] - 1, 0)

    def _scanner(self) -> _Scanner:
        return _Scanner(self._forms)

    def _begin(self) -> int:
        with self._state_lock:
            self._arrivals += 1
            self._pending.add(self._arrivals)
            return self._arrivals

    def _end(self, n: int) -> None:
        with self._state_lock:
            self._pending.discard(n)

    def _poll_control(self) -> None:
        """Apply the host's latest control message and ack it (a drain only once earlier scans are written)."""
        try:
            with open(self._control_path, encoding="utf-8") as f:
                ctl = json.loads(f.read())
            task, seq, drain = str(ctl["task"]), int(ctl["seq"]), bool(ctl.get("drain"))
        except (OSError, ValueError, KeyError, TypeError):
            return  # none yet, or half written: the next poll sees the whole file
        if task != self._task:
            self.set_task(task, ctl.get("models"), ctl.get("cap_usd"), ctl.get("max_requests"))
        if seq <= self._acked:
            return
        if drain:
            if self._drain_mark is None or self._drain_mark[0] != seq:
                with self._state_lock:
                    self._drain_mark = (seq, self._arrivals)
            with self._state_lock:
                if any(n <= self._drain_mark[1] for n in self._pending):
                    return
        tmp = self._ack_path + ".tmp"
        with self._spend_lock:
            spend = {k: round(v, 6) if isinstance(v, float) else v for k, v in self._spend.items()
                     if k != "in_flight"}
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps({"task": task, "seq": seq, **spend}))
        os.replace(tmp, self._ack_path)
        self._acked = seq

    def _control_loop(self) -> None:
        while True:
            try:
                self._poll_control()
            except Exception:  # noqa: BLE001 - a bad poll must not stop later ones
                pass
            time.sleep(0.05)

    def _scan_allowance(self) -> float:
        now = time.monotonic()
        with self._budget_lock:
            while self._scan_spent and self._scan_spent[0][0] < now - SCAN_WINDOW_S:
                self._scan_spent.popleft()
            return min(SCAN_REQUEST_S, SCAN_BUDGET_S - sum(c for _, c in self._scan_spent))

    def _scan_body(self, raw: bytes, enc: str, scan: _Scanner, max_s: float = SCAN_REQUEST_S) -> tuple[bytes, bool]:
        """Feed the decoded body to scan within the time budget.

        Returns the first BODY_LIMIT decoded bytes (always searched) and whether every byte was searched.
        """
        allowance, t0 = min(max_s, self._scan_allowance()), time.monotonic()
        body, state, over = b"", {}, False
        try:
            # An identity body is already in memory, so all of it is searched; decoding stops at SCAN_LIMIT.
            limit = len(raw) if enc in ("identity", "") else SCAN_LIMIT
            try:
                for chunk in _decoded_chunks(raw, enc, limit, state):
                    room = BODY_LIMIT - len(body)
                    body += chunk[:room] if room > 0 else b""
                    if time.monotonic() - t0 > allowance:
                        over = True
                        scan.feed(chunk[:max(room, 0)])
                        if len(body) >= BODY_LIMIT:
                            break
                        continue
                    scan.feed(chunk)
                return body, state["complete"] and not over
            except Exception:  # noqa: BLE001 - a corrupt body: keep what decoded, and search the raw bytes too
                scan.restart()
                for chunk in _decoded_chunks(raw, "identity", len(raw)):
                    if time.monotonic() - t0 > allowance:
                        scan.feed(chunk[:BODY_LIMIT])
                        break
                    scan.feed(chunk)
                return body or raw[:BODY_LIMIT], False
        finally:
            with self._budget_lock:
                self._scan_spent.append((time.monotonic(), time.monotonic() - t0))

    def _write(self, rec: dict) -> None:
        # ASCII output escapes the lone surrogates mitmproxy keeps for non-UTF-8 bytes.
        # A row is incomplete unless its writer says every byte it saw was searched.
        line = json.dumps({"ts": time.time(), "scan_complete": False, **rec})
        if self._key:
            line = line.replace(self._key, "[REDACTED]")
        # Rows come from the event loop and the scan thread; a long line is several write() calls.
        with self._write_lock, open(self._log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _write_sentinel(self) -> None:
        try:
            with open(self._log_path, "a", encoding="ascii") as f:
                f.write(_sentinel() + "\n")
        except Exception:  # noqa: BLE001 - nothing left to record with
            pass

    @staticmethod
    def _deny(flow) -> None:
        flow.response = http.Response.make(403, _FORBIDDEN, {"Content-Type": "text/plain"})

    def _record_failure(self, hook: str, obj, err: Exception, extra: dict | None = None) -> None:
        req = getattr(obj, "request", None)
        rec = {"method": getattr(req, "method", hook), "host": getattr(req, "host", ""),
               "port": getattr(req, "port", 0), "path": getattr(req, "path", ""), "headers": {},
               "body": "", "allowed": False, "outcome": "refused", "markers_found": [],
               "error": f"{hook}: {type(err).__name__}", **(extra or {})}
        try:
            raw = getattr(req, "raw_content", None) or b""
            rec["body"] = raw[:BODY_LIMIT].decode("utf-8", "replace")
            scan = self._scanner()
            scan.feed_text(rec["host"], rec["path"])
            # Only the raw bytes are searched here, so a compressed body is never a complete scan.
            # This path can run on the event loop (a sync hook failed), so it gets a short slice.
            _, complete = self._scan_body(raw, "identity", scan, FAILURE_SCAN_S)
            rec["markers_found"] = sorted(scan.found)
            rec["scan_complete"] = complete and (req is None or _encoding(req) == "identity")
        except Exception:  # noqa: BLE001
            pass
        try:
            try:
                self._write(rec)
            except Exception:  # noqa: BLE001
                try:
                    # ts and rid keep their types, so the host still merges this row with its arrival row.
                    self._write({k: v if isinstance(v, (bool, int, float)) or k == "rid" and isinstance(v, str)
                                 else ascii(v) for k, v in rec.items()})
                except Exception:  # noqa: BLE001
                    self._write_sentinel()
        finally:
            if req is not None and hasattr(obj, "response"):
                self._deny(obj)
            elif hasattr(obj, "kill"):
                obj.kill()

    @staticmethod
    def _is_anthropic(flow) -> bool:
        req = flow.request
        hosts = {req.host, req.pretty_host}
        # Inside a CONNECT tunnel the upstream is the tunnel target, whatever the Host header says.
        server = getattr(getattr(flow, "server_conn", None), "address", None)
        if server:
            hosts.add(server[0])
        sni = getattr(getattr(flow, "client_conn", None), "sni", None)
        if sni:
            hosts.add(sni)
        return hosts == {ANTHROPIC_HOST} and req.port == 443 and req.scheme == "https"

    def running(self) -> None:
        # mitmproxy's error pages name it. HTTP/2 and 3 are off, so HTTP/1's builder is the only one.
        # mitmproxy swallows hook errors, so a patch that does not take must stop the proxy.
        try:
            from mitmproxy.proxy.layers.http import _http1

            if not callable(getattr(_http1, "make_error_response", None)):
                raise RuntimeError("make_error_response missing")
            patched = self._error_response
            _http1.make_error_response = patched
            if _http1.make_error_response is not patched:
                raise RuntimeError("patch did not take")
        except Exception:  # noqa: BLE001
            os._exit(1)
        threading.Thread(target=self._control_loop, daemon=True).start()

    def _error_response(self, status_code: int, message: str = "") -> bytes:
        # Requests mitmproxy cannot parse (e.g. raw non-ASCII bytes in the request line) never reach
        # a hook; its message holds the request line, so record that. Upstream failures land here too.
        try:
            # The caller is the HTTP/1 server layer of the client connection the error page goes to.
            conn = getattr(sys._getframe(1).f_locals.get("self"), "conn", None)
            target = self._error_targets.pop(getattr(conn, "id", None), None)
            host, port, path, allowed = target or ("", 0, "", False)
            label = _ERROR_LABELS.get(status_code, "proxy error")
            scan = self._scanner()
            if host != ANTHROPIC_HOST:
                scan.feed_text(host, path, message)
            # The request body is never read on these rows; Anthropic rows are not searched by design.
            self._write({"method": "ERROR", "host": host, "port": port, "path": path, "headers": {},
                         "body": str(message)[:BODY_LIMIT], "allowed": allowed,
                         "outcome": _ERROR_OUTCOMES.get(status_code, "proxy_error"),
                         "markers_found": sorted(scan.found), "scan_complete": host == ANTHROPIC_HOST,
                         "error": f"{label} ({status_code})"})
        except Exception:  # noqa: BLE001
            self._write_sentinel()
        return http1_error(status_code)

    @_fail_closed
    def error(self, flow) -> None:
        # mitmproxy calls this just before it builds the error page for the same client connection.
        bill = getattr(flow, "metadata", {}).pop("argus_bill", None)
        if bill is not None:
            # The call went upstream and may be billed in full, so it keeps its reservation.
            why = getattr(getattr(flow, "error", None), "msg", None) or "the call failed"
            self._bill(flow, bill, bill[4], 0, None, None,
                       f"{why}; no usage was read, so the call is charged its reservation")
        conn_id = getattr(getattr(flow, "client_conn", None), "id", None)
        if conn_id is None or getattr(flow, "error", None) is None:
            return
        req = flow.request
        server = getattr(getattr(flow, "server_conn", None), "address", None)
        if len(self._error_targets) >= 256:
            self._error_targets.clear()
        self._error_targets[conn_id] = (server[0] if server else req.host, req.port, req.path,
                                        self._policy_allows(flow))

    @_fail_closed
    def client_disconnected(self, client) -> None:
        # An error page that was never built must not leave its target behind for another connection.
        self._error_targets.pop(getattr(client, "id", None), None)

    def _policy_allows(self, flow) -> bool:
        req = flow.request
        return self._is_anthropic(flow) and (req.method, req.path.split("?")[0]) in _ALLOWED_PATHS

    @_fail_closed
    def request(self, flow) -> None:
        req = flow.request
        headers = {k: v for k, v in req.headers.items() if k.lower() not in _SECRET_HEADERS}
        # Log where the bytes would go, not what the Host header claims.
        server = getattr(getattr(flow, "server_conn", None), "address", None)
        rec = {"method": req.method, "host": server[0] if server else req.host, "port": req.port,
               "path": req.path, "headers": headers}
        # Decide on host and path before touching the body; only raw bytes are ever read.
        if self._policy_allows(flow):
            rec["markers_found"], rec["scan_complete"] = [], True
            if _encoding(req) != "identity":
                self._write({**rec, "body": json.dumps({"reason": f"content-encoding {_encoding(req)}"}),
                             "allowed": False, "outcome": "refused"})
                self._deny(flow)
                return
            path, _, query = req.path.partition("?")
            unsafe, body, shape = None, None, {}
            if req.method == "POST":
                body, unsafe, shape = check_request(req.raw_content, req.headers, query)
                rec["model"] = _request_model(body)
            if unsafe is None and path == _MESSAGES:
                # Spend control: only the scan's models, within the task's cap and call limit.
                rec["max_tokens"], rec["body_bytes"] = body.get("max_tokens"), len(req.raw_content or b"")
                unsafe, rec["model"], reserve = self._admit(body, rec["body_bytes"], shape)
                if unsafe is None:
                    self._calls += 1
                    rec["ts"], rec["rid"], rec["reserve_usd"] = time.time(), f"a{self._calls}", round(reserve, 6)
                    flow.metadata["argus_bill"] = (self._task, rec["model"], rec["rid"], rec["ts"], reserve,
                                                   shape["one_hour"])
            elif unsafe is None and path == _COUNT_TOKENS:
                unsafe, rec["model"] = self._admit_count(body)
            if unsafe is None:
                self._write({**rec, "body": "", "allowed": True, "outcome": "forwarded"})
                req.headers.pop("authorization", None)
                req.headers["x-api-key"] = self._key
                return
            self._write({**rec, "body": json.dumps(unsafe), "allowed": False, "outcome": "refused"})
            self._deny(flow)
            return
        self._deny(flow)
        n = self._begin()
        # Stamped when it arrived, not when its scan finished; the scan row carries the same ts and rid.
        rec["ts"], rec["rid"] = time.time(), f"r{n}"
        try:
            # Written now, so the request is in the log even if the host reads it before the scan is done.
            self._write({**rec, "body": "", "allowed": False, "outcome": "refused", "markers_found": [],
                         "scan_complete": False})
        except BaseException:
            self._end(n)
            raise
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # no event loop (unit tests): scan inline
            return self._scan_job(flow, rec, n)
        # mitmproxy awaits the returned coroutine before it answers this flow; other flows go on meanwhile.
        return self._scan_off_loop(loop, flow, rec, n)

    def _scan_job(self, flow, rec: dict, n: int) -> None:
        try:
            try:
                self._record_refused(flow, rec)
            except Exception as e:  # noqa: BLE001 - fail closed: the flow is already denied
                self._record_failure("request", flow, e, {"ts": rec["ts"], "rid": rec["rid"]})
        finally:
            self._end(n)

    async def _scan_off_loop(self, loop, flow, rec: dict, n: int) -> None:
        try:
            if self._pool is None:
                self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            fut = loop.run_in_executor(self._pool, self._scan_job, flow, rec, n)
        except BaseException:
            self._end(n)
            raise
        await fut

    def _record_refused(self, flow, rec: dict) -> None:
        req = flow.request
        if rec["host"] == ANTHROPIC_HOST:  # a refused Anthropic path; never searched
            body, complete, found = (req.raw_content or b"")[:BODY_LIMIT], True, []
        else:
            scan = self._scanner()
            # Header values include the secret headers left out of the record.
            scan.feed_text(rec["host"], req.pretty_host, req.path,
                           *(f"{k}: {v}" for k, v in req.headers.items()))
            body, complete = self._scan_body(req.raw_content or b"", _encoding(req), scan)
            found = sorted(scan.found)
        self._write({**rec, "body": body.decode("utf-8", "replace"), "allowed": False, "outcome": "refused",
                     "markers_found": found, "scan_complete": complete})

    def response(self, flow) -> None:
        """Settle a forwarded Messages call to the real usage of its response."""
        bill = getattr(flow, "metadata", {}).pop("argus_bill", None)
        if bill is None:
            return
        model, reserve, one_hour = bill[1], bill[4], bill[5]
        cost, usage, status, msg_id, err = reserve, None, 0, None, None
        try:
            status = flow.response.status_code
            body = flow.response.get_content(strict=False) or b""
            usage, msg_id = usage_from_body(body), message_id(body)
            if usage is not None and _stream_finished(body):
                cost = price_usd(model or "", usage, one_hour)
                if cost > reserve + 1e-9:  # cannot happen for an allowed shape; recorded if it ever does
                    err = SETTLED_ABOVE
            elif status >= 400 and _anthropic_error(body):
                cost = 0.0  # Anthropic does not bill an error answer
            else:
                err = "usage unreadable or the stream ended early; charged its reservation"
        except Exception as e:  # noqa: BLE001 - never leave a call unpriced
            err = f"usage check failed: {type(e).__name__}; charged its reservation"
        self._bill(flow, bill, cost, status, usage, msg_id, err)

    def _bill(self, flow, bill, cost: float, status: int, usage, msg_id, err) -> None:
        task, model, rid, ts, reserve = bill[:5]
        self._settle(task, reserve, cost)
        try:
            self._write({"ts": ts, "rid": rid, "method": "POST", "host": ANTHROPIC_HOST, "port": 443,
                         "path": flow.request.path, "allowed": True, "outcome": "forwarded",
                         "markers_found": [], "scan_complete": True, "model": model, "status": status,
                         "usage": usage, "cost_usd": round(cost, 6), "msg_id": msg_id,
                         **({"error": err} if err else {})})
        except Exception:  # noqa: BLE001
            self._write_sentinel()

    @_fail_closed
    def http_connect(self, flow) -> None:
        req = flow.request
        allowed = req.host == ANTHROPIC_HOST and req.port == 443
        scan = self._scanner()
        if req.host != ANTHROPIC_HOST:
            scan.feed_text(req.host, *(f"{k}: {v}" for k, v in req.headers.items()))
        self._write({"method": "CONNECT", "host": req.host, "port": req.port, "path": "",
                     "headers": {}, "body": "", "allowed": allowed,
                     "outcome": "intercepted" if req.port in _CONNECT_PORTS else "refused",
                     "markers_found": sorted(scan.found), "scan_complete": True})
        if req.port not in _CONNECT_PORTS:
            self._deny(flow)

    @_fail_closed
    def tcp_start(self, flow) -> None:
        # Non-HTTP bytes inside a tunnel: record the target and drop the connection.
        host, port = (getattr(flow.server_conn, "address", None) or ("", 0))[:2]
        scan = self._scanner()
        if host != ANTHROPIC_HOST:
            scan.feed_text(host)
        self._write({"method": "TCP", "host": host, "port": port, "path": "", "headers": {},
                     "body": "", "allowed": False, "outcome": "refused", "markers_found": sorted(scan.found),
                     "scan_complete": True})
        flow.kill()

    @_fail_closed
    def tls_failed_client(self, data) -> None:
        # A client that rejects the sandbox CA never sends a request; still record the attempt.
        address = getattr(getattr(data.context, "server", None), "address", None) or ("", 0)
        sni = getattr(data.conn, "sni", None) or ""
        scan = self._scanner()
        if address[0] != ANTHROPIC_HOST:
            scan.feed_text(address[0], sni)
        self._write({"method": "CONNECT", "host": address[0], "port": address[1], "sni": sni, "path": "",
                     "headers": {}, "body": "", "allowed": False, "outcome": "tls_failed",
                     "markers_found": sorted(scan.found), "scan_complete": True})


def http1_error(status: int) -> bytes:
    reason = {400: "Bad Request", 403: "Forbidden", 413: "Payload Too Large",
              502: "Bad Gateway"}.get(status, "Error")
    body = generic_error(status)
    return (f"HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body


addons = [ArgusProxy(os.environ.get("ARGUS_REAL_KEY", ""),
                     os.environ.get("PROXY_LOG", "/var/log/proxy/requests.jsonl"),
                     os.environ.get("ARGUS_MARKERS", "").split())]
