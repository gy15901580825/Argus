"""tests/e2e/conftest.py skips only the live suite under tests/e2e/, not every path that contains "e2e"."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_E2E_DIR = Path(__file__).resolve().parent / "e2e"


def _hook():
    spec = importlib.util.spec_from_file_location("_live_suite_conftest", _E2E_DIR / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.pytest_collection_modifyitems


def _item(path: Path, keywords=()):
    item = SimpleNamespace(path=path, fspath=path, keywords={k: True for k in keywords}, markers=[])
    item.add_marker = item.markers.append
    return item


def _skipped(item) -> bool:
    return any(getattr(m, "name", None) == "skip" for m in item.markers)


@pytest.fixture(autouse=True)
def _no_live_env(monkeypatch):
    for name in ("ARGUS_E2E", "ANTHROPIC_API_KEY", "TARGET_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_only_items_under_tests_e2e_or_marked_e2e_are_skipped():
    live = _item(_E2E_DIR / "test_targets_e2e.py")
    marked = _item(Path(__file__).resolve(), keywords=["e2e"])
    sibling = _item(Path(__file__).resolve().parent / "test_mcp_trap_e2e.py")
    other_checkout = _item(Path("/work/argus-e2e-checkout/tests/test_cli.py"))
    _hook()(None, [live, marked, sibling, other_checkout])
    assert [_skipped(i) for i in (live, marked, sibling, other_checkout)] == [True, True, False, False]


def test_live_env_runs_the_live_suite(monkeypatch):
    for name, value in (("ARGUS_E2E", "1"), ("ANTHROPIC_API_KEY", "k"), ("TARGET_API_KEY", "k")):
        monkeypatch.setenv(name, value)
    live = _item(_E2E_DIR / "test_targets_e2e.py")
    _hook()(None, [live])
    assert not _skipped(live)
