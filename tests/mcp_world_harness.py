from contextlib import contextmanager
from argus.demo import servers
from argus.demo.mcp_testbed.demo_agent import app as agent_mod
from argus.demo.mcp_testbed.testbed import app as testbed_mod
from argus.demo.mcp_testbed.testbed import session as session_mod


@contextmanager
def serve_world_demo(weaknesses: str, mcp_mode: str):
    previous_grace, previous_timeout = (
        session_mod.SETTLE_GRACE_S,
        session_mod.SETTLE_TIMEOUT_S,
    )
    previous_weaknesses, previous_origin = (
        agent_mod._weaknesses,
        agent_mod._TESTBED_ORIGIN,
    )
    try:
        session_mod.SETTLE_GRACE_S = 0.0
        session_mod.SETTLE_TIMEOUT_S = 0.5
        agent_mod.set_weaknesses(weaknesses)
        with servers._serve_testbed(
            testbed_mod, servers._bind(), "MCP world testbed"
        ) as testbed_url:
            with servers.serve_demo_agent(agent_mod, testbed_url) as agent_url:
                yield {
                    "kind": "mcp_agent",
                    "testbed_url": testbed_url,
                    "control_token": testbed_mod.CONTROL_TOKEN,
                    "mcp_mode": mcp_mode,
                    "sandbox": True,
                    "inner": {
                        "kind": "openai_compat",
                        "endpoint_url": agent_url,
                        "model": "demo",
                    },
                }
    finally:
        session_mod.SETTLE_GRACE_S, session_mod.SETTLE_TIMEOUT_S = (
            previous_grace,
            previous_timeout,
        )
        agent_mod._weaknesses = previous_weaknesses
        agent_mod.set_testbed_origin(previous_origin)
