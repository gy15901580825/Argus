from contextlib import asynccontextmanager
from typing import AsyncIterator

from aiohttp import web


class RecordingApp:
    def __init__(self):
        self.app = web.Application()
        self.calls: list[tuple[str, str, dict, bytes]] = []

    def route(self, method, path, handler):
        async def record(request):
            self.calls.append(
                (
                    request.method,
                    request.raw_path,
                    dict(request.headers),
                    await request.read(),
                )
            )
            return await handler(request)

        self.app.router.add_route(method, path, record)


@asynccontextmanager
async def serve(app: RecordingApp) -> AsyncIterator[str]:
    runner = web.AppRunner(app.app, shutdown_timeout=0.1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    finally:
        await runner.cleanup()
