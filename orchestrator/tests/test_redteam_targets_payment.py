"""The payment_agent adapter: session lifecycle and the sandbox guard."""

import pytest

from orchestrator.redteam.targets import _BUILDERS, build_target

INNER = {"kind": "openai_compat", "endpoint_url": "https://x/v1/chat/completions", "model": "m"}


def _spec(**kw):
    base = {"kind": "payment_agent", "testbed_url": "http://tb", "inner": INNER, "sandbox": True}
    base.update(kw)
    return base


def test_sandbox_flag_is_mandatory():
    """A red-team tool that can move real money is not acceptable. The guard is
    a build-time refusal, not a runtime warning."""
    with pytest.raises(ValueError, match="sandbox"):
        build_target(_spec(sandbox=False))


def test_missing_sandbox_flag_is_also_refused():
    spec = _spec()
    del spec["sandbox"]
    with pytest.raises(ValueError, match="sandbox"):
        build_target(spec)


def test_testbed_url_is_required():
    with pytest.raises(ValueError, match="testbed_url"):
        build_target(_spec(testbed_url=""))


def test_builds_with_sandbox_true():
    t = build_target(_spec())
    assert t.compatible_classes == frozenset({"payment_agent"})


def test_inner_transport_must_be_a_known_kind():
    with pytest.raises(ValueError):
        build_target(_spec(inner={"kind": "not_a_thing"}))


def test_history_support_mirrors_the_inner_transport():
    t = build_target(_spec())
    assert t.supports_history is True


def test_payment_probes_are_skipped_by_every_ordinary_adapter():
    for kind, (_spec_cls, cls) in _BUILDERS.items():
        if kind != "payment_agent":
            assert "payment_agent" not in cls.compatible_classes, kind


@pytest.mark.asyncio
async def test_send_prompt_opens_a_session_and_substitutes_the_merchant_url():
    calls = {}

    class FakeInner:
        supports_history = True

        async def send_prompt(self, prompt, history=()):
            calls["prompt"] = prompt
            return "ok", 3.0

    t = build_target(_spec())
    t._inner = FakeInner()

    async def fake_open():
        t._session = {"session_id": "sid1", "merchant_url": "http://tb/s/sid1/report",
                      "expected_payee": "0xpayee"}
        return t._session

    t._open_session = fake_open
    text, _ = await t.send_prompt("Fetch {merchant_url} and pay what it asks.")
    assert text == "ok"
    assert "http://tb/s/sid1/report" in calls["prompt"]
    assert "{merchant_url}" not in calls["prompt"]
