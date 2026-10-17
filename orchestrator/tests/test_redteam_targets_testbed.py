"""The generic testbed_agent kind and the base class shared with mcp/payment."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from orchestrator.redteam.probe import VALID_TARGET_CLASSES
from orchestrator.redteam.targets import build_target
from orchestrator.redteam.targets import testbed_agent as testbed_mod
from orchestrator.redteam.targets.mcp_agent import MCPAgentTarget
from orchestrator.redteam.targets.payment_agent import PaymentAgentTarget
from orchestrator.redteam.targets.testbed_agent import (
    ENVIRONMENTS,
    GenericTestbedAgentTarget,
    TestbedAgentSpec,
    TestbedAgentTarget,
)

INNER = {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:1/v1/chat/completions", "model": "m"}


def _spec(**kw):
    base = {"kind": "testbed_agent", "environment": "mcp", "testbed_url": "http://tb", "inner": INNER, "sandbox": True}
    base.update(kw)
    return base


def test_registry_has_exactly_mcp_and_payment():
    assert set(ENVIRONMENTS) == {"mcp", "payment"}
    assert ENVIRONMENTS["mcp"]["url_key"] == "mcp_url"
    assert ENVIRONMENTS["payment"]["url_key"] == "merchant_url"


def test_every_environment_class_is_a_valid_probe_target_class():
    for env in ENVIRONMENTS:
        assert f"{env}_agent" in VALID_TARGET_CLASSES


def test_existing_targets_are_subclasses_of_the_base():
    assert issubclass(MCPAgentTarget, TestbedAgentTarget)
    assert issubclass(PaymentAgentTarget, TestbedAgentTarget)
    assert MCPAgentTarget.url_key == "mcp_url"
    assert PaymentAgentTarget.url_key == "merchant_url"


@pytest.mark.parametrize("env,cls", [("mcp", "mcp_agent"), ("payment", "payment_agent")])
def test_factory_builds_generic_target_with_matching_compat_class(env, cls):
    t = build_target(_spec(environment=env))
    assert isinstance(t, GenericTestbedAgentTarget)
    assert t.compatible_classes == frozenset({cls})
    assert t.url_key == ENVIRONMENTS[env]["url_key"]


def test_unknown_environment_names_the_known_ones():
    with pytest.raises(ValueError, match="mcp.*payment|payment.*mcp"):
        TestbedAgentSpec(**_spec(environment="teleport"))


def test_missing_environment_is_rejected():
    with pytest.raises(ValueError, match="environment"):
        TestbedAgentSpec(**{k: v for k, v in _spec().items() if k != "environment"})


def test_sandbox_must_be_true():
    with pytest.raises(ValueError, match="sandbox"):
        TestbedAgentSpec(**_spec(sandbox=False))


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def _fake_client_factory(session):
    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            assert url == "http://tb/sessions"
            return _FakeResp(session)

    return FakeClient


@pytest.mark.parametrize(
    "env,key,url",
    [("payment", "merchant_url", "http://tb/s/s1/pay"), ("mcp", "mcp_url", "http://tb/s/s1/mcp")],
)
def test_send_prompt_renders_the_environment_placeholder(monkeypatch, env, key, url):
    monkeypatch.setattr(
        testbed_mod,
        "httpx",
        SimpleNamespace(AsyncClient=_fake_client_factory({"session_id": "s1", key: url})),
    )
    seen = {}

    class FakeInner:
        supports_history = False

        async def send_prompt(self, prompt, history=()):
            seen["prompt"] = prompt
            return "ok", 1.0

    t = build_target(_spec(environment=env))
    t._inner = FakeInner()
    asyncio.run(t.send_prompt("go to {" + key + "}"))
    assert seen["prompt"] == f"go to {url}"


@pytest.mark.parametrize("env,noun", [("mcp", "unstaged MCP server"), ("payment", "unstaged merchant")])
def test_generic_messages_use_the_environment_noun(env, noun):
    t = build_target(_spec(environment=env))
    probe = SimpleNamespace(id="p1", scenario_payload="not json")
    with pytest.raises(ValueError, match=noun):
        t._script_for(probe)
