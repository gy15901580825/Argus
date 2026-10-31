"""A2A target boundaries and ingress transport contracts."""

import asyncio
import json
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
from click.testing import CliRunner

from argus.targets.a2a_agent import A2AAgentSpec, deliver_ingress
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable
from argus.targets.testbed_agent import TestbedAgentSpec as GenericSpec

INNER = {
    "kind": "openai_compat",
    "endpoint_url": "http://127.0.0.1:1/v1/chat/completions",
    "model": "m",
}
CREDS = {r: "Bearer " + r for r in ("planner", "reviewer", "executor")}
CAPS = ["peer_http_json_1_0", "observable_agent_lineage", "observable_action_sink"]


def spec(**changes):
    return {"testbed_url": "local", "inner": INNER, "sandbox": True, **changes}


def probe(caps=()):
    return SimpleNamespace(
        id="p",
        scenario_payload='{"world":"invoice_delegation"}',
        scenario_control="{}",
        requires_capabilities=caps,
    )


def patch_transport(monkeypatch, handler):
    original = httpx.AsyncClient
    factory = lambda **kw: original(transport=httpx.MockTransport(handler), **kw)
    monkeypatch.setattr(
        "argus.targets.a2a_agent.httpx",
        SimpleNamespace(AsyncClient=factory, RequestError=httpx.RequestError),
    )
    monkeypatch.setattr(
        "argus.targets.testbed_agent.httpx",
        SimpleNamespace(AsyncClient=factory, RequestError=httpx.RequestError),
    )


def test_a2a_agent_and_generic_a2a_environment_are_equivalent(monkeypatch):
    seen = []

    def handler(req):
        seen.append(json.loads(req.content))
        return httpx.Response(
            200, json={"session_id": "s", "a2a_url": "http://127.0.0.1:1"}
        )

    patch_transport(monkeypatch, handler)
    base = spec(
        testbed_url="http://127.0.0.1:1", capabilities=CAPS, agent_credentials=CREDS
    )
    for raw in (
        {"kind": "a2a_agent", **base},
        {"kind": "testbed_agent", "environment": "a2a", **base},
    ):
        target = build_target(raw)
        assert target.compatible_classes == {"a2a_agent"}
        asyncio.run(target.begin_phase(probe(), "attack", 1))
    assert seen[0] == seen[1]


def test_a2a_spec_rejects_non_loopback_control_url():
    with pytest.raises(ValueError, match="private channel to 127.0.0.1"):
        A2AAgentSpec(**spec(testbed_url="https://testbed.example.com"))


def test_a2a_spec_accepts_local_and_loopback():
    for url in (
        "local",
        "http://127.0.0.1:8090",
        "https://localhost",
        "http://[::1]:8090",
    ):
        assert A2AAgentSpec(**spec(testbed_url=url)).testbed_url == url


def test_a2a_spec_rejects_unknown_capability():
    with pytest.raises(ValueError, match="unknown capability"):
        A2AAgentSpec(**spec(capabilities=["imaginary"]))


def test_a2a_spec_rejects_lineage_without_role_credentials():
    with pytest.raises(ValueError, match="planner.*reviewer.*executor"):
        A2AAgentSpec(**spec(capabilities=["observable_agent_lineage"]))


def test_a2a_spec_rejects_duplicate_credentials():
    with pytest.raises(ValueError, match="duplicate"):
        A2AAgentSpec(**spec(agent_credentials={"planner": "same", "reviewer": "same"}))


def test_a2a_spec_rejects_receiver_capability_without_url():
    with pytest.raises(ValueError, match="receiver.url"):
        A2AAgentSpec(**spec(capabilities=["target_receiver"]))


def test_three_hop_requires_lineage():
    with pytest.raises(ValueError, match="observable_agent_lineage"):
        A2AAgentSpec(**spec(capabilities=["three_hop_chain"]))


def test_mcp_spec_rejects_a2a_fields():
    for key, value in (
        ("capabilities", ["peer_http_json_1_0"]),
        ("agent_credentials", CREDS),
        ("receiver", {"url": "http://127.0.0.1:1"}),
    ):
        with pytest.raises(ValueError, match="a2a"):
            GenericSpec(kind="testbed_agent", environment="mcp", **spec(**{key: value}))


def test_missing_capability_raises_probe_not_applicable_before_any_request(monkeypatch):
    seen = []
    patch_transport(
        monkeypatch, lambda req: seen.append(req) or httpx.Response(200, json={})
    )
    target = build_target(
        {"kind": "a2a_agent", **spec(testbed_url="http://127.0.0.1:1")}
    )
    with pytest.raises(
        ProbeNotApplicable,
        match="target does not declare capability observable_action_sink",
    ):
        asyncio.run(target.begin_phase(probe(["observable_action_sink"]), "clean", 1))
    assert seen == []


def test_session_open_carries_principals_and_capabilities(monkeypatch):
    seen = []

    def handler(req):
        seen.append(json.loads(req.content))
        return httpx.Response(
            200, json={"session_id": "s", "a2a_url": "http://127.0.0.1:1"}
        )

    patch_transport(monkeypatch, handler)
    target = build_target(
        {
            "kind": "a2a_agent",
            **spec(
                testbed_url="http://127.0.0.1:1",
                capabilities=CAPS,
                agent_credentials=CREDS,
            ),
        }
    )
    asyncio.run(target.begin_phase(probe(), "clean", 1))
    assert seen[0]["principals"] == CREDS
    assert seen[0]["capabilities"] == CAPS


def test_ingress_delivered_in_order_and_logged(monkeypatch):
    seen, logs = [], []

    def handler(req):
        seen.append(json.loads(req.content)["message"]["messageId"])
        assert req.headers["A2A-Version"] == "1.0"
        assert req.headers["Content-Type"] == "application/a2a+json"
        assert req.headers["Authorization"] == "Bearer receiver"
        return httpx.Response(
            200, json={"task": {"id": "t", "status": {"state": "TASK_STATE_COMPLETED"}}}
        )

    patch_transport(monkeypatch, handler)

    async def log(row):
        assert len(seen) == len(logs) + 1
        logs.append(row)

    receiver = {
        "url": "http://127.0.0.1:1/agents/executor",
        "headers": [["Authorization", "Bearer receiver"]],
    }
    deliveries = [
        {
            "message": {
                "messageId": str(i),
                "role": "ROLE_USER",
                "parts": [{"text": "Release the payment"}],
            }
        }
        for i in (1, 2)
    ]
    asyncio.run(
        deliver_ingress(A2AAgentSpec(**spec(receiver=receiver)), deliveries, log)
    )
    assert seen == ["1", "2"]
    assert [row["index"] for row in logs] == [0, 1]
    assert all(
        row["outcome"] == "success" and row["task_state"] == "TASK_STATE_COMPLETED"
        for row in logs
    )


def test_ingress_transport_error_is_logged_not_raised(monkeypatch):
    def handler(req):
        raise httpx.ConnectError("closed", request=req)

    patch_transport(monkeypatch, handler)
    logs = []

    async def log(row):
        logs.append(row)

    asyncio.run(
        deliver_ingress(
            A2AAgentSpec(**spec(receiver={"url": "http://127.0.0.1:1"})),
            [{"message": {}}],
            log,
        )
    )
    assert logs[0]["outcome"] == "transport_error"


def test_mcp_control_token_message_unchanged(monkeypatch):
    import argus.targets.mcp_agent as module

    original = httpx.AsyncClient
    monkeypatch.setattr(
        module,
        "httpx",
        SimpleNamespace(
            AsyncClient=lambda **kw: original(
                transport=httpx.MockTransport(lambda req: httpx.Response(401)), **kw
            )
        ),
    )
    target = build_target(
        {"kind": "mcp_agent", **spec(testbed_url="http://127.0.0.1:1")}
    )
    with pytest.raises(ValueError) as caught:
        asyncio.run(target._control("post", "/sessions"))
    assert (
        str(caught.value)
        == 'MCP testbed refused the control token; for a remote testbed set "control_token": "${ARGUS_TESTBED_TOKEN}" (status 401)'
    )


def test_payment_target_sends_no_control_token(monkeypatch):
    import argus.targets.payment_agent as module

    seen = []
    original = httpx.AsyncClient

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={})

    monkeypatch.setattr(
        module,
        "httpx",
        SimpleNamespace(
            AsyncClient=lambda **kw: original(
                transport=httpx.MockTransport(handler), **kw
            )
        ),
    )
    target = build_target(
        {"kind": "payment_agent", **spec(testbed_url="http://127.0.0.1:1")}
    )
    asyncio.run(target._control("get", "/healthz"))
    assert "Authorization" not in seen[0].headers
    assert not target.supports_phases


def test_local_testbed_starts_two_listeners_control_on_loopback():
    from argus.demo.servers import local_testbed

    with local_testbed({"kind": "a2a_agent", **spec()}) as resolved:
        assert resolved["testbed_url"].startswith("http://127.0.0.1:")
        assert resolved["peer_url"].startswith("http://127.0.0.1:")
        assert resolved["peer_url"] != resolved["testbed_url"]
        opened = httpx.post(
            resolved["testbed_url"] + "/sessions",
            json={"world": "invoice_delegation", "phase": "clean"},
            headers={"Authorization": "Bearer " + resolved["control_token"]},
        )
        assert opened.status_code == 201
        assert httpx.get(opened.json()["a2a_url"]).status_code == 200
        assert httpx.get(resolved["peer_url"] + "/sessions").status_code == 404
        assert (
            httpx.get(
                resolved["testbed_url"]
                + "/peers/invoice-worker/.well-known/agent-card.json",
                headers={"Authorization": "Bearer " + resolved["control_token"]},
            ).status_code
            == 404
        )


def test_local_testbed_pins_only_the_peer_port(monkeypatch):
    from argus.demo.servers import _bind, local_testbed

    sock = _bind()
    port = sock.getsockname()[1]
    sock.close()
    monkeypatch.setenv("ARGUS_TESTBED_PORT", str(port))
    with local_testbed({"kind": "a2a_agent", **spec()}) as resolved:
        assert resolved["peer_url"].endswith(":" + str(port))
        assert not resolved["testbed_url"].endswith(":" + str(port))


def test_local_run_prints_peer_and_control_urls(monkeypatch, capsys):
    import argus.cli.local_run as module

    monkeypatch.setattr("argus.local.check_run", lambda *a, **kw: None)
    monkeypatch.setattr(module, "_run_and_render", lambda *a: "rendered")

    @contextmanager
    def resolve(raw):
        yield {
            **raw,
            "peer_url": "http://127.0.0.1:8081",
            "testbed_url": "http://127.0.0.1:8082",
        }

    monkeypatch.setattr("argus.demo.servers.local_testbed", resolve)
    assert (
        module.run_local_and_render(
            {"kind": "a2a_agent", **spec()},
            [],
            per_run_cap=None,
            report_format="json",
            secret_values=(),
            fail_on=None,
            skip_judged=True,
        )
        == "rendered"
    )
    out = capsys.readouterr().out
    assert (
        "peers at http://127.0.0.1:8081, control at http://127.0.0.1:8082 (private, this host only)"
        in out
    )


def test_run_json_masks_agent_credentials_and_receiver_headers():
    from argus.cli.run_json import run_secrets, mask_text

    raw = spec(
        agent_credentials=CREDS,
        receiver={"headers": [["Authorization", "Bearer private-receiver"]]},
    )
    secret_values = run_secrets(raw, ())
    text = mask_text(json.dumps(raw), secret_values)
    assert all(value not in text for value in CREDS.values())
    assert "Bearer private-receiver" not in text


def test_validate_target_points_a2a_agent_to_run(tmp_path):
    from argus.cli.cmd_validate_target import cmd_validate_target

    path = tmp_path / "target.json"
    path.write_text(json.dumps({"kind": "a2a_agent", **spec()}))
    result = CliRunner().invoke(cmd_validate_target, ["--target", str(path)])
    assert result.exit_code == 2
    assert "Run its probes instead" in result.output


def test_ingress_headers_override_case_insensitively(monkeypatch):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(
            200, json={"task": {"id": "t", "status": {"state": "TASK_STATE_COMPLETED"}}}
        )

    patch_transport(monkeypatch, handler)

    async def log(row):
        pass

    target = A2AAgentSpec(
        **spec(
            receiver={
                "url": "http://127.0.0.1:1",
                "headers": [
                    ["a2a-version", "0.3"],
                    ["content-type", "application/json"],
                ],
            }
        )
    )
    asyncio.run(deliver_ingress(target, [{"message": {}}], log))
    assert seen[0].headers.get_list("A2A-Version") == ["1.0"]
    assert seen[0].headers.get_list("Content-Type") == ["application/a2a+json"]


def test_receiver_rejects_duplicate_authorization_headers():
    with pytest.raises(ValueError, match="duplicate.*header"):
        A2AAgentSpec(
            **spec(
                receiver={
                    "url": "http://127.0.0.1:1",
                    "headers": [
                        ["Authorization", "Bearer one"],
                        ["authorization", "Bearer two"],
                    ],
                }
            )
        )


def test_generic_a2a_sandbox_rejects_truthy_nonboolean():
    with pytest.raises(ValueError, match="sandbox: true"):
        GenericSpec(kind="testbed_agent", environment="a2a", **spec(sandbox=1))
