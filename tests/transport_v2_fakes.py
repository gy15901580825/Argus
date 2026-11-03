import asyncio
import concurrent.futures
import threading
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncIterator, Iterator

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
    runner = web.AppRunner(app.app, shutdown_timeout=0.1, handler_cancellation=True)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    finally:
        await runner.cleanup()


@contextmanager
def serve_in_thread(app: RecordingApp) -> Iterator[str]:
    ready = concurrent.futures.Future()
    loop = asyncio.new_event_loop()
    stop = None

    async def run():
        nonlocal stop
        stop = asyncio.Event()
        try:
            async with serve(app) as origin:
                ready.set_result(origin)
                await stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc)
            else:
                raise

    def worker():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run())
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        yield ready.result(timeout=5)
    finally:
        if stop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('fake HTTP server did not stop')
