"""A small stdio transport for scan-mcp: exact child environment, a byte cap per line, captured stderr.

The SDK's `stdio_client` merges HOME, LOGNAME, PATH, SHELL, TERM and USER into the child's environment and
buffers a stdout line without limit, so it cannot keep the minimal environment or the line cap.
"""
from __future__ import annotations

import os
import signal
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, AsyncIterator

if TYPE_CHECKING:
    from argus.mcp_scan.client import StdioServer

STDERR_KEEP = 4096
STOP_WAIT_S = 2.0
_REAP_WAIT_S = 2.0


class StdioProcess:
    def __init__(self, process: Any) -> None:
        self._process = process
        self._stderr = bytearray()
        self.line_too_long = False

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    @property
    def stderr_tail(self) -> str:
        return self._stderr.decode("utf-8", "replace")

    def _keep_stderr(self, chunk: bytes) -> None:
        self._stderr += chunk
        del self._stderr[:-STDERR_KEEP]


def _signal_group(pgid: int, sig: int) -> bool:
    """True when the group still had a member to signal."""
    try:
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


@asynccontextmanager
async def stdio_streams(server: StdioServer, *, line_max: int) -> AsyncIterator[tuple[Any, Any, StdioProcess]]:
    """Spawn the server in its own process group and speak newline-delimited JSON-RPC over its pipes."""
    import subprocess

    import anyio
    import mcp_types
    from mcp.shared.message import SessionMessage

    process = await anyio.open_process(
        list(server.argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(server.env), cwd=server.cwd, start_new_session=True)
    proc = StdioProcess(process)
    read_send, read_recv = anyio.create_memory_object_stream[Any](0)
    write_send, write_recv = anyio.create_memory_object_stream[Any](0)

    async def read_stdout() -> None:
        buf = bytearray()
        async with read_send:
            try:
                async for chunk in process.stdout:
                    buf += chunk
                    while (i := buf.find(b"\n")) >= 0 and i <= line_max:
                        line = bytes(buf[:i])
                        del buf[: i + 1]
                        if not line.strip():
                            continue
                        try:
                            item: Any = SessionMessage(mcp_types.jsonrpc_message_adapter.validate_json(
                                line, by_name=False))
                        except Exception as exc:  # a non-JSON-RPC line; the session hears of it, as with the SDK
                            item = exc
                        await read_send.send(item)
                    if buf.find(b"\n") > line_max or len(buf) > line_max:
                        # Past the cap the session is over: closing the stream fails every waiting request.
                        proc.line_too_long = True
                        return
            except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                pass

    async def read_stderr() -> None:
        try:
            async for chunk in process.stderr:
                proc._keep_stderr(chunk)
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass

    async def write_stdin() -> None:
        try:
            async with write_recv:
                async for message in write_recv:
                    data = message.message.model_dump_json(by_alias=True, exclude_unset=True) + "\n"
                    await process.stdin.send(data.encode())
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            # The server stopped reading: end the session instead of leaving a request waiting.
            await read_send.aclose()

    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(read_stdout)
            tg.start_soon(read_stderr)
            tg.start_soon(write_stdin)
            try:
                yield read_recv, write_send, proc
            finally:
                tg.cancel_scope.cancel()
    finally:
        await _stop(process)
        for stream in (read_recv, write_send):
            stream.close()


async def _stop(process: Any) -> None:
    """Close stdin, wait, SIGTERM the process group, wait, SIGKILL; shielded so a cancelled scan still stops it."""
    import anyio

    with anyio.CancelScope(shield=True):
        if process.returncode is None:
            try:
                await process.stdin.aclose()
            except Exception:
                pass
            with anyio.move_on_after(STOP_WAIT_S):
                await process.wait()
        # Signal the group even when the leader has exited: children it started may remain.
        if _signal_group(process.pid, signal.SIGTERM):
            with anyio.move_on_after(STOP_WAIT_S):
                await process.wait()
            _signal_group(process.pid, signal.SIGKILL)
        with anyio.move_on_after(_REAP_WAIT_S):
            await process.wait()
            # Read the pipes to their end so asyncio closes the subprocess transport now, not at garbage collection.
            for stream in (process.stdout, process.stderr):
                try:
                    while await stream.receive():
                        pass
                except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
                    pass
            await process.aclose()
