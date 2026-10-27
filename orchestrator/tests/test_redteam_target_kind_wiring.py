"""Every target adapter must be reachable from the CLI, or nobody can use it.

`orchestrator/redteam/targets/__init__.py::_BUILDERS` is the source of truth for
adapters. The CLI pre-checks `kind` against `_KNOWN_KINDS`, so a kind missing
there is rejected locally and its probes, rubrics and testbeds are dead code
that no other test would catch.

The CLI loader is loaded by file path rather than imported, so this guard runs
inside the orchestrator CI job. It depends only on the standard library.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CLI_LOADER = REPO / "cli" / "argus_probe" / "target_loader.py"


def _load(module_name: str, path: Path):
    assert path.is_file(), f"{path} is missing; this guard cannot check what it cannot read"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _builder_kinds() -> set[str]:
    from orchestrator.redteam.targets import _BUILDERS

    return set(_BUILDERS)


def _cli_kinds() -> set[str]:
    loader = _load("_wiring_cli_target_loader", CLI_LOADER)
    kinds = set(loader._KNOWN_KINDS)
    assert kinds, "could not read _KNOWN_KINDS — the guard has gone blind"
    return kinds


def test_every_adapter_is_reachable_through_the_cli():
    missing = sorted(_builder_kinds() - _cli_kinds())
    assert not missing, (
        f"{missing} are registered adapters that `argus-probe` refuses locally "
        f"before the request is ever sent"
    )


def test_the_cli_does_not_invent_kinds_of_its_own():
    """The other direction: a kind the CLI accepts that no adapter serves
    fails at run time instead of at load time."""
    assert not sorted(_cli_kinds() - _builder_kinds())


@pytest.mark.parametrize("kind", ["payment_agent", "mcp_agent", "testbed_agent"])
def test_world_acting_adapters_demand_sandbox_true_in_the_cli(kind):
    """`sandbox` is a safety interlock, not a convenience default: these two
    adapters move real money / reach a real MCP server if it is wrong. The
    orchestrator refuses a falsy sandbox, but it must not be the only refusal —
    a spec that never reaches the orchestrator must still be rejected."""
    loader = _load("_wiring_cli_target_loader", CLI_LOADER)

    base = {"kind": kind, "testbed_url": "https://tb.example.com",
            "inner": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y"}}
    if kind == "testbed_agent":
        base["environment"] = "mcp"
    for bad in ({**base}, {**base, "sandbox": False}):
        with pytest.raises(loader.TargetLoadError):
            loader.load_target_spec(json.dumps(bad))

    assert loader.load_target_spec(json.dumps({**base, "sandbox": True}))
