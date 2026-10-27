"""In-process demo servers for `argus-probe quickstart`: the MCP testbed and a scripted insecure agent."""
from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn

from orchestrator.redteam.demo.mcp_testbed.demo_agent import app as _agent_mod
from orchestrator.redteam.demo.mcp_testbed.testbed import app as _testbed_mod

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


def _bind() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    return sock


@contextmanager
def start_mcp_demo() -> Iterator[dict]:
    # Pre-bound sockets avoid a port race between picking and listening.
    socks = [_bind(), _bind()]
    ports = [s.getsockname()[1] for s in socks]
    _agent_mod.set_testbed_origin(f"http://127.0.0.1:{ports[0]}")
    _agent_mod.set_weaknesses(None)
    servers = [
        uvicorn.Server(uvicorn.Config(app, log_level="warning"))
        for app in (_testbed_mod.app, _agent_mod.app)
    ]
    threads = [
        threading.Thread(target=lambda s=srv, k=sk: asyncio.run(s.serve(sockets=[k])), daemon=True)
        for srv, sk in zip(servers, socks)
    ]
    try:
        for t in threads:
            t.start()
        deadline = time.monotonic() + 10
        while not all(s.started for s in servers):
            if time.monotonic() > deadline:
                raise RuntimeError("demo servers did not start")
            time.sleep(0.02)
        yield {
            "kind": "mcp_agent",
            "testbed_url": f"http://127.0.0.1:{ports[0]}",
            "sandbox": True,
            "inner": {
                "kind": "openai_compat",
                "endpoint_url": f"http://127.0.0.1:{ports[1]}/v1/chat/completions",
                "model": "demo",
            },
        }
    finally:
        for s in servers:
            s.should_exit = True
        for t in threads:
            t.join(timeout=5)
        for sk in socks:
            sk.close()
