"""What the commands that speak MCP share: the SDK check, terminal-safe text and the stop-signal takeover."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata
import re
import signal

# Server- or agent-chosen text (tool names, errors) must not be able to drive the user's terminal.
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# A CI cancel sends SIGTERM; Ctrl-C sends SIGINT. Both stop the run the same way.
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)
STOP_MESSAGES = {signal.SIGINT: "Interrupted", signal.SIGTERM: "Terminated"}


def sdk_problem(extra: str) -> str | None:
    """Why the MCP SDK cannot be used, naming the `argus-probe[extra]` install, or None when it can."""
    hint = f"{extra} needs the MCP SDK 2.3 or newer: pip install 'argus-probe[{extra}]'"
    try:
        import mcp  # noqa: F401
    except ImportError:
        return hint
    try:
        found = importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        return hint
    m = re.match(r"(\d+)\.(\d+)", found)
    if m is None or not (2, 3) <= (int(m[1]), int(m[2])) < (3, 0):
        return f"{hint} (found mcp {found})"
    return None


@contextlib.contextmanager
def cancel_on_stop_signals(task: asyncio.Task):
    # Handlers installed by the work itself (uvicorn's in mcp-trap) would stop it only after a grace
    # period, so the run would go on against a dead peer; cancel the task at once instead.
    loop = asyncio.get_running_loop()
    hits: list[int] = []

    def handler(signum, frame):
        hits.append(signum)
        loop.call_soon_threadsafe(task.cancel)

    previous = {sig: signal.signal(sig, handler) for sig in STOP_SIGNALS}
    try:
        yield hits
    finally:
        for sig, old in previous.items():
            # If the server already exited, it restored the original handler; leave that in place.
            if signal.getsignal(sig) is handler:
                signal.signal(sig, old)
