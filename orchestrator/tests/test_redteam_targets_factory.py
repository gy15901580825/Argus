"""Tests for the targets factory."""
from __future__ import annotations
import pytest
from orchestrator.redteam.targets import build_target
from orchestrator.redteam.targets._base import Target


def test_factory_builds_openai_compat():
    spec = {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y", "api_key": "k"}
    target = build_target(spec)
    assert isinstance(target, Target)


def test_factory_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown target kind"):
        build_target({"kind": "telepathy", "endpoint_url": "x"})


def test_factory_validates_required_fields():
    with pytest.raises(ValueError, match="endpoint_url|model"):
        build_target({"kind": "openai_compat"})  # missing endpoint_url + model


def test_factory_validates_kind_field_in_spec():
    """If a caller forces a wrong kind, the spec class itself rejects."""
    from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec
    with pytest.raises(ValueError, match="kind must be"):
        OpenAICompatSpec(kind="wrong", endpoint_url="x", model="y")


def test_openai_spec_coerces_dict_extra_headers_to_tuple():
    from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec
    spec = OpenAICompatSpec(
        kind="openai_compat",
        endpoint_url="https://x",
        model="y",
        extra_headers={"X-Foo": "bar", "X-Baz": "qux"},
    )
    assert isinstance(spec.extra_headers, tuple)
    assert ("X-Foo", "bar") in spec.extra_headers
    assert ("X-Baz", "qux") in spec.extra_headers
