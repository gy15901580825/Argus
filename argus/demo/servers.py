"""In-process servers: the bundled testbeds for `testbed_url: "local"`, and the demo agents `quickstart` runs."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn

from argus.demo import bypass_proxy_for_localhost
from argus.demo.mcp_testbed.demo_agent import app as _agent_mod
from argus.demo.mcp_testbed.testbed import app as _testbed_mod

# Same 12 ids as the MCP probe library and .github/workflows/action-e2e.yml.
PROBE_IDS: tuple[str, ...] = (
    "mcp_budget_unbounded_tool_loop",
    "mcp_confused_deputy_chained_forward",
    "mcp_confused_deputy_result_injection",
    "mcp_credential_lure_api_key",
    "mcp_credential_lure_compliance_framing",
    "mcp_poison_description_exfil",
    "mcp_poison_description_multi_turn",
    "mcp_poison_non_english",
    "mcp_rugpull_after_relist",
    "mcp_rugpull_silent_escalation",
    "mcp_shadow_claims_newer_version",
    "mcp_shadow_near_name",
)


# `testbed_url: "local"` asks `run --local` for the bundled testbed on 127.0.0.1 for the run.
LOCAL = "local"
# Pins that testbed's port, for an agent that may only call allowlisted origins. Unset: a free port.
PORT_ENV = "ARGUS_TESTBED_PORT"
LABELS = {"mcp": "MCP", "payment": "payment"}
_KIND_ENVIRONMENT = {"mcp_agent": "mcp", "payment_agent": "payment"}


def _bind(port: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if port and os.name != "nt":
        # A pinned port must be reusable right after the previous run closed it.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    return sock


class _StartupErrors(logging.Handler):
    """Keeps the last line of each uvicorn error, which for a traceback is the exception itself."""

    def __init__(self) -> None:
        super().__init__(logging.ERROR)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        lines = [ln.strip() for ln in record.getMessage().splitlines() if ln.strip()]
        if lines:
            self.lines.append(lines[-1])


@contextmanager
def _serve(app, sock: socket.socket, name: str = "local server") -> Iterator[str]:
    """Serve `app` on the pre-bound `sock` in a thread; yield its URL; always stop it and free the port."""
    server = None
    thread = None
    errors = _StartupErrors()
    try:
        # A bounded graceful shutdown: an agent cut off mid-request must not hold the thread.
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", timeout_graceful_shutdown=2))
        failure: list[BaseException] = []

        def run() -> None:
            try:
                asyncio.run(server.serve(sockets=[sock]))
            except BaseException as e:  # uvicorn exits a failed startup with SystemExit
                failure.append(e)

        logging.getLogger("uvicorn.error").addHandler(errors)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                why = errors.lines[0] if errors.lines else repr(failure[0]) if failure else "timed out"
                raise RuntimeError(f"the {name} did not start: {why}")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        logging.getLogger("uvicorn.error").removeHandler(errors)
        if server is not None:
            server.should_exit = True
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive() and server is not None:
                server.force_exit = True
                thread.join(timeout=5)
        sock.close()


# Per testbed module: [runs serving it, PUBLIC_BASE_URL before the first]. Runs can overlap in one process.
_PUBLIC_URL_LOCK = threading.Lock()
_PUBLIC_URL_USERS: dict[str, list] = {}


@contextmanager
def _serve_testbed(mod, sock: socket.socket, name: str) -> Iterator[str]:
    """Serve a bundled testbed module so it hands out its own address.

    The testbed reads TESTBED_PUBLIC_URL once at import; an exported value would send the agent elsewhere.
    The first run to enter saves the value and the last to leave restores it."""
    entered = False
    try:
        # Inside the try, so a Ctrl-C right after the increment still reaches the decrement.
        with _PUBLIC_URL_LOCK:
            users = _PUBLIC_URL_USERS.setdefault(mod.__name__, [0, None, None])
            if users[0] == 0:
                users[1] = mod.PUBLIC_BASE_URL
                if hasattr(mod, "CONTROL_TOKEN"):
                    users[2] = mod.CONTROL_TOKEN
                    mod.CONTROL_TOKEN = secrets.token_urlsafe(32)
            users[0] += 1
            entered = True
            mod.PUBLIC_BASE_URL = ""
        with _serve(mod.app, sock, name) as url:
            yield url
    finally:
        if entered:
            with _PUBLIC_URL_LOCK:
                users[0] -= 1
                if users[0] == 0:
                    mod.PUBLIC_BASE_URL = users[1]
                    if hasattr(mod, "CONTROL_TOKEN"):
                        mod.CONTROL_TOKEN = users[2]


@contextmanager
def serve_demo_agent(agent_mod, testbed_url: str) -> Iterator[str]:
    """Serve a bundled demo agent paired with `testbed_url`; yield its chat-completions URL."""
    agent_mod.set_testbed_origin(testbed_url)
    with _serve(agent_mod.app, _bind(), "demo agent") as url:
        yield f"{url}/v1/chat/completions"


@contextmanager
def start_mcp_demo() -> Iterator[dict]:
    # Pre-bound sockets avoid a port race between picking and listening.
    _agent_mod.set_weaknesses(None)
    with _serve_testbed(_testbed_mod, _bind(), "bundled MCP testbed") as testbed_url, \
            serve_demo_agent(_agent_mod, testbed_url) as agent_url:
        yield {
            "kind": "mcp_agent",
            "control_token": _testbed_mod.CONTROL_TOKEN,
            "testbed_url": testbed_url,
            "sandbox": True,
            "inner": {"kind": "openai_compat", "endpoint_url": agent_url, "model": "demo"},
        }


def local_environment(spec) -> str | None:
    """"mcp" or "payment" when `spec` asks for the bundled testbed, else None."""
    if not isinstance(spec, dict) or spec.get("testbed_url") != LOCAL:
        return None
    env = spec.get("environment") if spec.get("kind") == "testbed_agent" else _KIND_ENVIRONMENT.get(spec.get("kind"))
    return env if env in LABELS else None


def _pinned_port() -> int:
    from argus.local import LocalRunError

    raw = os.environ.get(PORT_ENV, "").strip()
    if not raw:
        return 0
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise LocalRunError(f"{PORT_ENV}={raw!r} is not a port number (1-65535)", code="config")
    return int(raw)


@contextmanager
def local_testbed(spec: dict) -> Iterator[dict]:
    """Yield `spec` with `testbed_url: "local"` replaced by a bundled testbed on 127.0.0.1, stopped on exit.

    Any other spec is yielded unchanged and nothing starts."""
    env = local_environment(spec)
    if env is None:
        yield spec
        return
    from argus.local import LocalRunError

    if env == "mcp":
        mod = _testbed_mod
    else:
        from argus.demo.payment_testbed.testbed import app as mod
    port = _pinned_port()
    try:
        sock = _bind(port)
    except OSError as e:
        hint = f"; free it or change {PORT_ENV}" if port else ""
        raise LocalRunError(
            f"cannot start the bundled {LABELS[env]} testbed on 127.0.0.1:{port}: {e.strerror or e}{hint}",
            code="config") from e
    bypass_proxy_for_localhost()
    with _serve_testbed(mod, sock, f"bundled {LABELS[env]} testbed") as url:
        yield {**spec, "testbed_url": url, **({"control_token": mod.CONTROL_TOKEN} if env == "mcp" else {})}
