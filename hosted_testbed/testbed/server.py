import asyncio
import logging

from aiohttp import web
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_server import Server


class SafeRequestHandler(RequestHandler):
    def handle_error(self, request, status=500, exc=None, message=None):
        if request.writer.output_size > 0:
            raise ConnectionError("response already started")
        response = web.json_response({"error": "request_rejected"}, status=status)
        response.force_close()
        return response


class SafeServer(Server):
    def __call__(self):
        return SafeRequestHandler(self, loop=self._loop, **self._kwargs)


class SafeAppRunner(web.AppRunner):
    async def _make_server(self):
        original = await super()._make_server()
        logger = logging.getLogger("hosted.http")
        logger.disabled = True
        options = {**original._kwargs, "access_log": None, "logger": logger, "debug": False}
        return SafeServer(original.request_handler, request_factory=original.request_factory,
                          handler_cancellation=original.handler_cancellation,
                          loop=asyncio.get_running_loop(), **options)


async def serve(application, host, port):
    runner = SafeAppRunner(application, handle_signals=True)
    try:
        await runner.setup()
        await web.TCPSite(runner, host, port).start()
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
