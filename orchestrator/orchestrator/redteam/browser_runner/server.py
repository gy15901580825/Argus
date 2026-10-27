"""Localhost aiohttp microserver that serves one scenario page per probe run.

Listens on 127.0.0.1, ephemeral port, unless the caller passes another host,
port or the public URL the agent should use. The target browser-using agent (running
on customer infra OR a Playwright instance we drive) navigates to the URL.
After the probe completes we stop the server."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from aiohttp import web


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

    async def start(self) -> str:
        async def handler(request: web.Request) -> web.Response:
            body, content_type = self._render_fn()
            if isinstance(body, bytes):
                return web.Response(body=body, content_type=content_type)
            return web.Response(text=body, content_type=content_type)
        app = web.Application()
        app.router.add_get("/scenario", handler)
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
        if self._public_url:
            # The agent reaches us through this URL (LAN address, container alias, tunnel).
            self._url = self._public_url.rstrip("/") + "/scenario"
        else:
            self._url = f"http://{host}:{port}/scenario"
        return self._url

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
