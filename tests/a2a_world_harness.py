from contextlib import contextmanager
import secrets

from argus.demo import servers
from argus.demo.a2a_testbed.demo_agent import app as demo
from argus.demo.a2a_testbed.testbed.app import create_testbed

DEMO_CAPABILITIES = (
    "peer_http_json_1_0",
    "observable_action_sink",
    "observable_agent_lineage",
    "target_receiver",
    "three_hop_chain",
)


class HarnessSpec(dict):
    pass


@contextmanager
def serve_a2a_demo(weaknesses: str, capabilities: tuple[str, ...] = DEMO_CAPABILITIES):
    credentials = {
        role: "Bearer " + secrets.token_urlsafe(24)
        for role in ("planner", "reviewer", "executor")
    }
    driver = "Bearer " + secrets.token_urlsafe(24)
    token = secrets.token_urlsafe(24)
    control_sock, peer_sock, agent_sock = (
        servers._bind(),
        servers._bind(),
        servers._bind(),
    )
    peer_url = f"http://127.0.0.1:{peer_sock.getsockname()[1]}"
    testbed = create_testbed(
        control_token=token,
        public_base_url=peer_url,
        settle_grace_s=0.0,
        settle_timeout_s=0.5,
    )
    demo.configure(
        peer_base_url=peer_url,
        credentials=credentials,
        driver_credential=driver,
        weaknesses=weaknesses,
    )
    with (
        servers._serve(
            testbed.control_app, control_sock, "A2A controller"
        ) as control_url,
        servers._serve(testbed.peer_app, peer_sock, "A2A peers"),
        servers._serve(demo.app, agent_sock, "A2A demo") as agent_url,
    ):
        result = HarnessSpec(
            kind="a2a_agent",
            testbed_url=control_url,
            peer_url=peer_url,
            control_token=token,
            sandbox=True,
            capabilities=list(capabilities),
            agent_credentials=credentials,
            receiver={
                "url": agent_url + "/agents/executor",
                "headers": [["Authorization", driver]],
            },
            inner={
                "kind": "openai_compat",
                "endpoint_url": agent_url + "/v1/chat/completions",
                "model": "demo",
            },
        )
        result.testbed = testbed
        yield result
