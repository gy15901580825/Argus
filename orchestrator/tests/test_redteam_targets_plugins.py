"""Tests for third-party target adapters registered via the `argus.targets` entry-point group."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

import orchestrator.redteam.targets as targets_mod
from orchestrator.redteam.targets import build_target
from orchestrator.redteam.targets._base import Target
from orchestrator.redteam.targets.openai_compat import OpenAICompatTarget


@dataclass(frozen=True)
class EchoSpec:
    kind: str
    reply: str = "hi"


class EchoTarget(Target):
    def __init__(self, spec: EchoSpec):
        self.spec = spec

    async def send_prompt(self, prompt, history=()):
        return self.spec.reply, 0.0


def _ep(name: str, load):
    return SimpleNamespace(name=name, value=f"fake_plugin:{name}", load=load)


@pytest.fixture
def install_plugins(monkeypatch):
    """Replace the entry-point lookup with the given fake entry points."""
    def _install(*eps):
        def fake_entry_points(*, group):
            assert group == "argus.targets"
            return list(eps)
        monkeypatch.setattr(targets_mod, "entry_points", fake_entry_points)
        targets_mod._plugin_builders.cache_clear()

    yield _install
    targets_mod._plugin_builders.cache_clear()


def test_plugin_kind_resolves(install_plugins):
    install_plugins(_ep("echo", lambda: (EchoSpec, EchoTarget)))

    target = build_target({"kind": "echo", "reply": "pong"})

    assert type(target) is EchoTarget
    assert target.spec == EchoSpec(kind="echo", reply="pong")


def test_plugin_cannot_override_builtin_kind(install_plugins, caplog):
    loaded = []

    def load():
        loaded.append(True)
        return (EchoSpec, EchoTarget)

    install_plugins(_ep("openai_compat", load))

    with caplog.at_level(logging.WARNING, logger=targets_mod.__name__):
        # Scan plugins explicitly: building a built-in kind never needs the scan.
        plugins = targets_mod._plugin_builders()
        target = build_target(
            {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y", "api_key": "k"}
        )

    assert type(target) is OpenAICompatTarget
    assert loaded == []  # the shadowing plugin is never even imported
    assert plugins == {}
    assert any("built-in kind" in r.getMessage() for r in caplog.records)


def test_broken_plugin_is_skipped_and_others_still_load(install_plugins, caplog):
    def broken():
        raise ImportError("missing dependency")

    install_plugins(_ep("broken", broken), _ep("echo", lambda: (EchoSpec, EchoTarget)))

    with caplog.at_level(logging.WARNING, logger=targets_mod.__name__):
        target = build_target({"kind": "echo"})

    assert type(target) is EchoTarget
    assert any("'broken'" in r.getMessage() and "failed to load" in r.getMessage() for r in caplog.records)
    with pytest.raises(ValueError, match="unknown target kind: 'broken'"):
        build_target({"kind": "broken"})


def test_unknown_kind_still_rejected_with_no_plugins(install_plugins):
    install_plugins()
    with pytest.raises(ValueError, match="unknown target kind"):
        build_target({"kind": "telepathy"})


class OtherTarget(EchoTarget):
    pass


def test_two_plugins_same_kind_first_by_value_wins(install_plugins, caplog):
    second = SimpleNamespace(name="echo", value="zz_plugin:echo", load=lambda: (EchoSpec, OtherTarget))
    first = SimpleNamespace(name="echo", value="aa_plugin:echo", load=lambda: (EchoSpec, EchoTarget))
    install_plugins(second, first)

    with caplog.at_level(logging.WARNING, logger=targets_mod.__name__):
        target = build_target({"kind": "echo"})

    assert type(target) is EchoTarget
    assert any("zz_plugin:echo" in r.getMessage() and "already registered" in r.getMessage() for r in caplog.records)
