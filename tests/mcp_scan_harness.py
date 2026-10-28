"""Serve the scan-mcp fixture servers over Streamable HTTP or stdio for tests."""
from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterator

SERVERS = Path(__file__).resolve().parent / "fixtures" / "mcp_scan" / "servers.py"
SHUTDOWN_GRACE_S = 2


def _load_servers() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mcp_scan_fixture_servers", SERVERS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Gate:
    """401 without the required header, 403 with a wrong value; a plain-text body, as many gateways send."""

    def __init__(self, app: Any, require_header: tuple[str, str] | None, oauth: bool) -> None:
        self._app = app
        self._header = (require_header[0].lower().encode(), require_header[1].encode()) if require_header else None
        self._oauth = oauth

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or (self._header is None and not self._oauth):
            await self._app(scope, receive, send)
            return
        sent = [v for k, v in scope["headers"] if self._header and k == self._header[0]]
        if self._header and sent == [self._header[1]]:
            await self._app(scope, receive, send)
            return
        status = 403 if sent else 401
        headers = [(b"content-type", b"text/plain")]
        if self._oauth and status == 401:
            headers.append((b"www-authenticate", b'Bearer resource_metadata="https://example.invalid/.well-known/x"'))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"unauthorized"})


@contextlib.contextmanager
def serve_http(name: str, *, require_header: tuple[str, str] | None = None, oauth: bool = False,
               json_response: bool = False) -> Iterator[str]:
    """Serve fixture `name` on a free 127.0.0.1 port in a thread; yields the /mcp URL."""
    import uvicorn

    server_app = _load_servers().build(name).streamable_http_app(json_response=json_response)
    app = _Gate(server_app, require_header, oauth)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="on",
                                           timeout_graceful_shutdown=SHUTDOWN_GRACE_S))
    thread = threading.Thread(target=lambda: asyncio.run(server.serve(sockets=[sock])), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline, "fixture server did not start"
            time.sleep(0.01)
        yield f"http://127.0.0.1:{sock.getsockname()[1]}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
    assert not thread.is_alive(), "fixture server did not stop"


def stdio_argv(name: str) -> tuple[str, ...]:
    return (sys.executable, str(SERVERS), name)
