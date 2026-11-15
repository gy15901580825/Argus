"""Run-scoped witnesses for model requests and trace exports.

Only bounded, masked observations survive request handling. Incoming headers and
bodies exist solely while forwarding or inspecting the current request.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from urllib.parse import urlsplit

from aiohttp import ClientError, ClientSession, ClientTimeout, DummyCookieJar, web
from yarl import URL
from argus_transport.security import Redactor

_HTTP_LOGGER = logging.Logger("argus.witness.http", level=logging.CRITICAL + 1)

CHANNELS = frozenset({"model_relay", "otlp"})
_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host",
})


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class WitnessSpec:
    model_relay: dict | None = None
    otlp: dict | None = None
    agent_logging: str = ""
    bind: str = "127.0.0.1"
    secret_placeholder: str = "argus_secret"

    def __post_init__(self):
        if self.model_relay is not None:
            if not isinstance(self.model_relay, dict) or set(self.model_relay) != {"upstream"}:
                raise ValueError("witness.model_relay requires only upstream")
            upstream = self.model_relay["upstream"]
            try:
                p = urlsplit(upstream)
                port = p.port
                valid = (isinstance(upstream, str) and p.hostname and port != 0
                         and (p.scheme == "https" or p.scheme == "http" and _loopback(p.hostname))
                         and p.username is None and p.password is None
                         and not p.query and not p.fragment
                         and not any(c.isspace() or ord(c) < 32 for c in upstream))
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise ValueError("witness upstream must be HTTPS or loopback HTTP origin+path without credentials, query or fragment")
        if self.otlp is not None and (not isinstance(self.otlp, dict) or self.otlp):
            raise ValueError("witness.otlp must be an empty object")
        if not isinstance(self.agent_logging, str):
            raise ValueError("witness.agent_logging must be a string")
        if not isinstance(self.bind, str):
            raise ValueError("witness.bind must be an IP address or localhost")
        if self.bind != "localhost":
            try:
                ipaddress.ip_address(self.bind)
            except ValueError:
                raise ValueError("witness.bind must be an IP address or localhost") from None
        if not isinstance(self.secret_placeholder, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", self.secret_placeholder):
            raise ValueError("witness.secret_placeholder must be a placeholder name")

    @classmethod
    def from_dict(cls, raw):
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("unknown witness keys or invalid witness object")
        return cls(**raw)


def binds_canary(request):
    """Whether a request binding references the canary, ignoring literal data."""
    if not isinstance(request, dict):
        return False

    def expression(value):
        if not isinstance(value, dict) or "literal" in value:
            return False
        if value.get("context") == "secret_canary":
            return True
        return (any(expression(v) for v in value.get("object", {}).values())
                or any(expression(v) for v in value.get("array", ())))

    body = request.get("body", {})
    bindings = [*body.get("json", {}).values(), *request.get("query", {}).values()]
    if "text" in body:
        bindings.append(body["text"])
    return any(expression(value) for value in bindings)


@dataclass(frozen=True)
class RelayRecord:
    index: int
    received_at: float
    path: str
    body_size: int
    placeholder_seen: bool
    canary_seen: bool
    excerpt: str | None
    status: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class ExportRecord:
    index: int
    received_at: float
    content_type: str
    size: int
    canary_seen: bool
    values_seen: tuple[bool, ...]
    span_count: int | None


_CURRENT = contextvars.ContextVar("witness_run", default=None)


@contextmanager
def witness_scope(run):
    token = _CURRENT.set(run)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_witness():
    return _CURRENT.get()


def _headers(headers):
    blocked = _HOP_HEADERS | {part.strip().lower() for name, value in headers.items()
                              if name.lower() == "connection" for part in value.split(",")}
    return [(k, v) for k, v in headers.items() if k.lower() not in blocked]


def _span_count(body):
    try:
        data = json.loads(body)
        return sum(len(scope.get("spans", [])) for resource in data.get("resourceSpans", [])
                   for scope in resource.get("scopeSpans", resource.get("instrumentationLibrarySpans", [])))
    except (ValueError, TypeError, AttributeError):
        return 0


class WitnessRun:
    def __init__(self, spec: WitnessSpec):
        self.spec = spec
        self.canary = "ARGUS-CANARY-NOTAKEY-" + base64.b32encode(secrets.token_bytes(7)).decode()[:10]
        self.fingerprint = hashlib.sha256(self.canary.encode()).hexdigest()[:8]
        self.marker = f"<canary sha256:{self.fingerprint}>"
        self.token = secrets.token_urlsafe(24)
        self.relay_records: list[RelayRecord] = []
        self.export_records: list[ExportRecord] = []
        self._values: tuple[str, ...] = ()
        self._servers = {}
        self._client = None
        self.urls = {}

    def __repr__(self):
        return f"WitnessRun(sha256:{self.fingerprint})"

    def register_values(self, values):
        if not isinstance(values, (list, tuple)) or any(not isinstance(v, str) or not v for v in values):
            raise ValueError("witness values must be a list of nonempty plain strings")
        self._values = tuple(values)

    async def start(self, channels):
        try:
            for channel in channels:
                if channel not in CHANNELS or getattr(self.spec, channel) is None:
                    raise ValueError("requested witness channel is not configured")
                if channel in self._servers:
                    continue
                app = web.Application(client_max_size=16 * 1024 * 1024)
                prefix = f"/r/{self.token}/"
                if channel == "model_relay":
                    app.router.add_route("*", prefix + "{tail:.*}", self._relay)
                    if self._client is None:
                        self._client = ClientSession(auto_decompress=False, trust_env=False, cookie_jar=DummyCookieJar(),
                            skip_auto_headers={"Accept-Encoding", "User-Agent", "Content-Type"},
                            timeout=ClientTimeout(total=None, sock_connect=10, sock_read=300))
                else:
                    app.router.add_post(prefix + "v1/traces", self._export)
                server = web.AppRunner(app, access_log=None, logger=_HTTP_LOGGER, auto_decompress=False)
                self._servers[channel] = server
                await server.setup()
                site = web.TCPSite(server, "127.0.0.1" if self.spec.bind == "localhost" else self.spec.bind, 0)
                await site.start()
                host = self.spec.bind
                if ":" in host:
                    host = f"[{host}]"
                port = site._server.sockets[0].getsockname()[1]
                self.urls[channel] = f"http://{host}:{port}{prefix}"
        except BaseException:
            await self.aclose()
            raise
        return dict(self.urls)

    def _excerpt(self, body, redactor):
        text = body.decode("utf-8", errors="replace")
        positions = [p for p in (text.find(self.canary), text.find("%" + self.spec.secret_placeholder + "%")) if p >= 0]
        if not positions:
            return None
        # Mask before slicing: a cut must never retain a fragment of the canary.
        first = min(positions)
        safe = redactor.clean(text[:first]) + redactor.clean(text[first:].replace(self.canary, self.marker))
        start = max(0, len(redactor.clean(text[:first])) - 40)
        return safe[start:start + 160]

    async def _relay(self, request):
        if not request.raw_path.startswith(f"/r/{self.token}/"):
            return web.Response(status=404)
        received = time.monotonic()
        body = await request.read()
        # Header-derived masks live only for this request and are never recorded.
        redactor = Redactor(v for k, v in request.headers.items()
                            if any(part in k.lower() for part in ("key", "token", "secret", "credential", "authorization", "cookie", "auth")))
        for k, v in request.headers.items():
            if k.lower() == "authorization" and " " in v:
                redactor.add(v.split(" ", 1)[1])
        path = request.raw_path[len(f"/r/{self.token}/"):].split("?", 1)[0]
        record = RelayRecord(len(self.relay_records) + 1, received,
                             redactor.clean(path.replace(self.canary, self.marker)), len(body),
                             ("%" + self.spec.secret_placeholder + "%").encode() in body,
                             self.canary.encode() in body, self._excerpt(body, redactor))
        position = len(self.relay_records)
        self.relay_records.append(record)
        upstream = self.spec.model_relay["upstream"].rstrip("/") + "/" + request.raw_path[len(f"/r/{self.token}/"):]
        response = None
        try:
            async with self._client.request(request.method, URL(upstream, encoded=True), data=body,
                                            headers=_headers(request.headers), allow_redirects=False) as remote:
                self.relay_records[position] = replace(record, status=remote.status)
                if remote.status >= 400:
                    return web.Response(status=remote.status, text="upstream HTTP failure")
                response = web.StreamResponse(status=remote.status, headers=_headers(remote.headers))
                await response.prepare(request)
                async for chunk in remote.content.iter_any():
                    await response.write(chunk)
                await response.write_eof()
                return response
        except (ClientError, OSError, TimeoutError):
            self.relay_records[position] = replace(self.relay_records[position], error="upstream_transport_error")
            if response is not None and response.prepared:
                response.force_close()
                return response
            return web.Response(status=502, text="upstream transport failure")

    async def _export(self, request):
        if not request.raw_path.startswith(f"/r/{self.token}/"):
            return web.Response(status=404)
        received = time.monotonic()
        body = await request.read()
        content_type = request.content_type
        if content_type not in {"application/json", "application/x-protobuf", "application/protobuf"}:
            return web.Response(status=415, text="unsupported trace content type")
        self.export_records.append(ExportRecord(len(self.export_records) + 1, received,
            content_type, len(body), self.canary.encode() in body,
            tuple(value.encode() in body for value in self._values),
            _span_count(body) if content_type == "application/json" else None))
        return web.Response(body=b"{}" if content_type == "application/json" else b"", content_type=content_type)

    def evidence(self, start, end):
        return {"fingerprint": self.fingerprint,
                "agent_logging": self.spec.agent_logging.replace(self.canary, self.marker),
                "model_relay": [asdict(r) for r in self.relay_records if start <= r.received_at <= end],
                "otlp": [asdict(r) for r in self.export_records if start <= r.received_at <= end]}

    async def aclose(self):
        try:
            for server in self._servers.values():
                await server.cleanup()
        finally:
            self._servers.clear()
            if self._client is not None:
                await self._client.close()
                self._client = None
