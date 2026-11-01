import json
from types import SimpleNamespace
import httpx
import pytest
from argus.demo import servers
from argus.probe import load_probe_library
from argus import api
from argus.runner import Runner
from argus.targets import build_target

INNER = {
    "kind": "openai_compat",
    "endpoint_url": "http://127.0.0.1:9/v1/chat/completions",
    "model": "demo",
}
PROBE = SimpleNamespace(
    id="p",
    scenario_payload=json.dumps(
        {"scenario": "agent_world", "world": "invoice_memory", "inject": "memory_note"}
    ),
    scenario_control='{"inject":null}',
)


def spec(**kw):
    return {
        "kind": "mcp_agent",
        "testbed_url": "local",
        "sandbox": True,
        "inner": INNER,
        **kw,
    }


async def test_begin_phase_applies_control_override_only_in_clean():
    with servers.local_testbed(spec()) as resolved:
        target = build_target(resolved)
        ids = []
        for phase in ["clean", "attack"]:
            await target.begin_phase(PROBE, phase, 1)
            sid = target._session["session_id"]
            ids.append(sid)
            response = httpx.post(
                target._session["mcp_url"],
                json={
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "crm_lookup",
                        "arguments": {"customer": "Acme Corp"},
                    },
                },
            )
            evidence = await target.end_phase()
            assert evidence["phase"] == phase
            assert bool(evidence["attack_delivered"]) == (phase == "attack")
        assert ids[0] != ids[1]
        await target.aclose()


async def test_begin_conversation_bumps_counter():
    with servers.local_testbed(spec()) as resolved:
        target = build_target(resolved)
        await target.begin_phase(PROBE, "clean", 1)
        await target.begin_conversation(2)
        assert (await target.collect_evidence())["conversation"] == 2
        await target.aclose()


async def test_end_phase_returns_sealed_evidence():
    with servers.local_testbed(spec()) as resolved:
        target = build_target(resolved)
        await target.begin_phase(PROBE, "clean", 1)
        sid = target._session["session_id"]
        assert (await target.end_phase())["sealed"] is True
        assert (
            httpx.get(
                resolved["testbed_url"] + f"/sessions/{sid}/evidence",
                headers={"Authorization": "Bearer " + resolved["control_token"]},
            ).status_code
            == 404
        )
        await target.aclose()


async def test_fixed_mode_renders_fixed_mcp_url_and_holds_lease():
    with servers.local_testbed(spec(mcp_mode="fixed")) as resolved:
        target = build_target(resolved)
        await target.begin_phase(PROBE, "clean", 1)
        assert target.rendered_prompt("{mcp_url}") == resolved["testbed_url"] + "/mcp"
        assert (await target._control("get", f"/lease/{target._lease_id}")).json()[
            "active_session_id"
        ] == target._session["session_id"]
        await target.aclose()
        lid = (await target._control("post", "/lease")).json()["lease_id"]
        await target._control("delete", f"/lease/{lid}")


async def test_fixed_mode_second_target_errors_while_lease_held():
    with servers.local_testbed(spec(mcp_mode="fixed")) as resolved:
        first, second = build_target(resolved), build_target(resolved)
        await first.begin_phase(PROBE, "clean", 1)
        with pytest.raises(ValueError, match="in use by another run.*expires in"):
            await second.begin_phase(PROBE, "clean", 1)
        await first.aclose()
        await second.aclose()


async def test_rug_pull_probe_is_skipped_in_fixed_mode():
    with servers.local_testbed(spec(mcp_mode="fixed")) as resolved:
        target = build_target(resolved)
        probe = next(
            p
            for p in load_probe_library(api.PROBES_DIR)
            if p.id == "mcp_rugpull_after_relist"
        )
        findings = [
            f
            async for f in Runner(target, SimpleNamespace(), api.RUBRICS_DIR).run_probe(
                probe
            )
        ]
        assert (
            findings[0].verdict == "skipped"
            and "mcp_mode dynamic" in findings[0].reasoning
            and "rug_pull" in findings[0].reasoning
        )
        await target.aclose()


def test_mcp_mode_validation():
    with pytest.raises(ValueError):
        build_target(spec(mcp_mode="static"))
    with pytest.raises(ValueError):
        build_target(
            {
                **spec(mcp_mode="fixed"),
                "kind": "testbed_agent",
                "environment": "payment",
            }
        )


async def test_existing_mcp_probe_in_fixed_mode_runs():
    with servers.start_mcp_demo() as resolved:
        target = build_target({**resolved, "mcp_mode": "fixed"})
        probe = next(
            p
            for p in load_probe_library(api.PROBES_DIR)
            if p.id == "mcp_confused_deputy_result_injection"
        )
        findings = [
            f
            async for f in Runner(target, SimpleNamespace(), api.RUBRICS_DIR).run_probe(
                probe
            )
        ]
        assert findings[0].verdict != "error"
        await target.aclose()


def _bare(kind_spec):
    target = build_target(kind_spec)
    target._session = {
        "session_id": "s",
        "mcp_url": "http://127.0.0.1:1/s/x/mcp",
        "mcp_url_2": "http://127.0.0.1:1/s/x/mcp2",
    }
    return target


def test_second_mcp_url_placeholder_is_rendered():
    target = _bare(spec(testbed_url="http://127.0.0.1:1"))
    assert target.rendered_prompt("A {mcp_url} B {mcp_url_2}") == (
        "A http://127.0.0.1:1/s/x/mcp B http://127.0.0.1:1/s/x/mcp2"
    )


def test_generic_mcp_environment_renders_second_url_but_payment_does_not():
    generic = _bare({**spec(testbed_url="http://127.0.0.1:1"), "kind": "testbed_agent", "environment": "mcp"})
    assert generic.rendered_prompt("{mcp_url_2}") == "http://127.0.0.1:1/s/x/mcp2"
    payment = _bare({**spec(testbed_url="http://127.0.0.1:1"), "kind": "testbed_agent", "environment": "payment"})
    payment._session["merchant_url"] = "http://127.0.0.1:1/m"
    assert payment.rendered_prompt("{mcp_url_2}") == "{mcp_url_2}"


def test_missing_placeholder_value_is_left_verbatim():
    target = _bare(spec(testbed_url="http://127.0.0.1:1"))
    del target._session["mcp_url_2"]
    assert target.rendered_prompt("{mcp_url} {mcp_url_2}") == (
        "http://127.0.0.1:1/s/x/mcp {mcp_url_2}"
    )


async def test_send_prompt_renders_both_urls_in_prompt_and_history():
    from argus.targets._base import Turn

    target = _bare(spec(testbed_url="http://127.0.0.1:1"))
    received = []

    async def send(prompt, history=()):
        received.append((prompt, history))
        return "ok", 1.0

    target._inner = SimpleNamespace(send_prompt=send)
    history = (Turn("user", "Earlier {mcp_url} {mcp_url_2}"),)
    result = await target.send_prompt("Now {mcp_url} {mcp_url_2}", history)
    assert result == ("ok", 1.0)
    assert received == [(
        "Now http://127.0.0.1:1/s/x/mcp http://127.0.0.1:1/s/x/mcp2",
        (Turn("user", "Earlier http://127.0.0.1:1/s/x/mcp http://127.0.0.1:1/s/x/mcp2"),),
    )]
    assert history[0].content == "Earlier {mcp_url} {mcp_url_2}"
