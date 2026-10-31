"""Localhost aiohttp microserver that serves one scenario page per probe run.

Listens on 127.0.0.1, ephemeral port, unless the caller passes another host,
port or the public URL the agent should use. The target browser-using agent (running
on customer infra OR a Playwright instance we drive) navigates to the URL.
After the probe completes we stop the server."""

from __future__ import annotations

import asyncio
import secrets
from typing import Awaitable, Callable

from aiohttp import web

# Caps keep a chatty or hostile agent from growing the evidence without bound.
_MAX_TRAP_REQUESTS = 50
_MAX_BODY_CHARS = 4000
# A body that stalls is cut here and kept as incomplete, so one request cannot hold the run.
_BODY_READ_TIMEOUT_S = 5.0
# How long settle() waits for bodies still arriving after the agent returns.
_SETTLE_TIMEOUT_S = 2.0


async def _read_body(request: web.Request, entry: dict) -> None:
    """Fill entry["body"] as chunks arrive, so a cut-off read keeps what came."""
    raw = b""
    async for chunk in request.content.iter_chunked(65536):
        raw += chunk
        text = raw.decode("utf-8", errors="replace")
        entry["body"] = text[:_MAX_BODY_CHARS]
        # 4 bytes per char is the UTF-8 worst case, so stopping here still fills 4000 chars.
        if len(raw) > _MAX_BODY_CHARS * 4:
            return
    entry["complete"] = len(raw.decode("utf-8", errors="replace")) <= _MAX_BODY_CHARS


class ScenarioServer:
    def __init__(
        self,
        render_fn: Callable[[], tuple[bytes | str, str]],
        host: str = "127.0.0.1",
        port: int = 0,
        public_url: str | None = None,
    ):
        self._render_fn = render_fn
        self._host = host
        self._port = port
        self._public_url = public_url
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._url: str | None = None
        self._sink_url: str | None = None
        self._page_loads = 0
        self._trap_requests: list[dict] = []
        self._in_flight = 0
        self._idle = asyncio.Event()
        self._idle.set()
        # Unguessable path prefix: a third party who finds the port cannot load the
        # page or post to the sink and so cannot change the verdict.
        self._token = secrets.token_urlsafe(12)

    @property
    def sink_url(self) -> str:
        """Where the agent can send data; valid once start() has returned."""
        if self._sink_url is None:
            raise RuntimeError("ScenarioServer.sink_url is only available after start()")
        return self._sink_url

    async def settle(self, timeout: float = _SETTLE_TIMEOUT_S) -> None:
        """Wait until no sink body is still arriving, at most `timeout` seconds."""
        try:
            await asyncio.wait_for(self._idle.wait(), timeout)
        except asyncio.TimeoutError:
            pass  # the late entries stay marked complete=False

    def evidence(self) -> dict:
        """What the agent did on the trap: page loads plus every request to /sink."""
        return {
            "interaction_count": self._page_loads + len(self._trap_requests),
            "page_loads": self._page_loads,
            "trap_requests": [dict(r) for r in self._trap_requests],
        }

    async def start(self) -> str:
        prefix = f"/{self._token}"

        async def handler(request: web.Request) -> web.Response:
            if request.method == "GET":  # HEAD is served but is not the agent loading the page
                self._page_loads += 1
            body, content_type = self._render_fn()
            if isinstance(body, bytes):
                return web.Response(body=body, content_type=content_type)
            return web.Response(text=body, content_type=content_type)

        async def sink(request: web.Request) -> web.Response:
            if len(self._trap_requests) < _MAX_TRAP_REQUESTS:
                # Take the slot before awaiting the body: the cap and arrival order must not
                # depend on how fast each body arrives.
                entry = {
                    "method": request.method,
                    # Without the token, so the record reads the same on every run.
                    "path": request.path[len(prefix):],
                    "query": request.rel_url.raw_query_string,
                    "body": "",
                    # True only once the whole body is in "body"; a check must not read a part as all.
                    "complete": False,
                }
                self._trap_requests.append(entry)
                self._in_flight += 1
                self._idle.clear()
                try:
                    await asyncio.wait_for(_read_body(request, entry), _BODY_READ_TIMEOUT_S)
                except asyncio.TimeoutError:
                    pass  # keep what arrived; complete stays False
                finally:
                    self._in_flight -= 1
                    if not self._in_flight:
                        self._idle.set()
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_get(prefix + "/scenario", handler, allow_head=False)
        app.router.add_head(prefix + "/scenario", handler)
        app.router.add_route("*", prefix + "/sink", sink)
        app.router.add_route("*", prefix + "/sink/{tail:.*}", sink)
        # Short, so a connection that never finishes its body cannot hold stop() for 60 s.
        self._runner = web.AppRunner(app, shutdown_timeout=1.0)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._host, self._port)
        try:
            await self._site.start()
        except OSError as e:
            await self.stop()
            raise RuntimeError(
                f"trap page could not listen on {self._host}:{self._port} ({e.strerror or e}); "
                "pick another trap_port or free that one"
            ) from e
        # Resolve assigned ephemeral port via the only path aiohttp 3.x exposes
        # (TCPSite.name returns "http://host:0" when port=0; no public accessor).
        # Pin requirements to aiohttp<4 — revisit if the private attr changes shape.
        sockets = getattr(self._site._server, "sockets", None) or ()  # noqa: SLF001
        if not sockets:
            await self.stop()
            raise RuntimeError(f"ScenarioServer failed to bind any socket on {self._host}:{self._port}")
        host, port = sockets[0].getsockname()[:2]
        # With a public URL the agent reaches us through it (LAN address, container alias, tunnel).
        base = self._public_url.rstrip("/") if self._public_url else f"http://{host}:{port}"
        self._url = f"{base}/{self._token}/scenario"
        self._sink_url = f"{base}/{self._token}/sink"
        return self._url

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
