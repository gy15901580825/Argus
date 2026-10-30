"""Localhost aiohttp microserver that serves one scenario page per probe run.

Listens on 127.0.0.1, ephemeral port, unless the caller passes another host,
port or the public URL the agent should use. The target browser-using agent (running
on customer infra OR a Playwright instance we drive) navigates to the URL.
After the probe completes we stop the server."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from aiohttp import web

# Caps keep a chatty or hostile agent from growing the evidence without bound.
_MAX_TRAP_REQUESTS = 50
_MAX_BODY_CHARS = 4000


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

    @property
    def sink_url(self) -> str:
        """Where the agent can send data; valid once start() has returned."""
        if self._sink_url is None:
            raise RuntimeError("ScenarioServer.sink_url is only available after start()")
        return self._sink_url

    def evidence(self) -> dict:
        """What the agent did on the trap: page loads plus every request to /sink."""
        return {
            "interaction_count": self._page_loads + len(self._trap_requests),
            "page_loads": self._page_loads,
            "trap_requests": list(self._trap_requests),
        }

    async def start(self) -> str:
        async def handler(request: web.Request) -> web.Response:
            self._page_loads += 1
            body, content_type = self._render_fn()
            if isinstance(body, bytes):
                return web.Response(body=body, content_type=content_type)
            return web.Response(text=body, content_type=content_type)

        async def sink(request: web.Request) -> web.Response:
            if len(self._trap_requests) < _MAX_TRAP_REQUESTS:
                # 4 bytes per char is the UTF-8 worst case, so the cut below is still 4000 chars.
                raw = b""
                async for chunk in request.content.iter_chunked(65536):
                    raw += chunk
                    if len(raw) > _MAX_BODY_CHARS * 4:
                        break
                self._trap_requests.append({
                    "method": request.method,
                    "path": request.path,
                    "query": request.query_string,
                    "body": raw.decode("utf-8", errors="replace")[:_MAX_BODY_CHARS],
                })
            return web.Response(text="ok")

        app = web.Application()
        app.router.add_get("/scenario", handler)
        app.router.add_route("*", "/sink", sink)
        app.router.add_route("*", "/sink/{tail:.*}", sink)
        self._runner = web.AppRunner(app)
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
        self._url = base + "/scenario"
        self._sink_url = base + "/sink"
        return self._url

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
