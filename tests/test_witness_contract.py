"""Target-load contracts that can also be exercised against the prior checkout."""
import pytest

from argus.targets.browser_use import BrowserUseSpec
from test_transport_integration import transport


def test_target_accepts_secret_request_contexts():
    spec = transport("http://127.0.0.1:1/run")
    spec["request"]["body"]["json"].update(
        sensitive_data={"object": {"argus_secret": {"context": "secret_canary"}}},
        placeholder={"context": "secret_placeholder"},
    )
    target = BrowserUseSpec(transport=spec, scenario_kind="dom_injection")
    assert target.binds_secret_canary is True


def test_target_accepts_witness_and_default_placeholder():
    target = BrowserUseSpec(transport=transport("http://127.0.0.1:1/run"),
                            scenario_kind="dom_injection",
                            witness={"model_relay": {"upstream": "https://model.example.test/v1"}, "otlp": {}})
    assert target.witness.secret_placeholder == "argus_secret"
    assert target.witness.bind == "127.0.0.1"


@pytest.mark.parametrize("raw", [
    {"model_relay": {"upstream": "ftp://model.example.test"}},
    {"model_relay": {"upstream": "https://user:fake-password@model.example.test"}},
    {"unknown": True},
])
def test_target_rejects_invalid_witness_at_load(raw):
    with pytest.raises(ValueError):
        BrowserUseSpec(transport=transport("http://127.0.0.1:1/run"), scenario_kind="dom_injection", witness=raw)
