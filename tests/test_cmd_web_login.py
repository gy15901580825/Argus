"""argus-probe web-login, driven against a fake Playwright (no real browser opens)."""
from __future__ import annotations

import json
import os
import stat
import sys
import types

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main

STATE = {"cookies": [{"name": "session", "value": "ok", "domain": "chat.example", "path": "/"}],
         "origins": []}


class _FakeError(Exception):
    pass


@pytest.fixture
def fake_playwright(monkeypatch):
    calls: dict = {"launch": [], "goto": [], "closed": False}

    class Context:
        def new_page(self):
            page = types.SimpleNamespace(goto=lambda url: calls["goto"].append(url))
            return page

        def storage_state(self):
            # The user has pressed Enter by now, so the prompt ran first.
            calls["state_after_prompt"] = calls.get("prompted", False)
            return STATE

    class Browser:
        def new_context(self, **kw):
            calls["context_kwargs"] = kw
            return Context()

        def close(self):
            calls["closed"] = True

    class Chromium:
        def launch(self, **kw):
            calls["launch"].append(kw)
            if calls.get("launch_error"):
                raise calls["launch_error"]
            return Browser()

    class Manager:
        def __enter__(self):
            return types.SimpleNamespace(chromium=Chromium())

        def __exit__(self, *exc):
            return False

    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = Manager
    sync_api.Error = _FakeError
    package = types.ModuleType("playwright")
    package.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    import click
    real_prompt = click.prompt

    def prompt(*a, **kw):
        calls["prompted"] = True
        return real_prompt(*a, **kw)

    monkeypatch.setattr("argus.cli.cmd_web_login.click.prompt", prompt)
    return calls


def test_saves_storage_state_as_0600(tmp_path, fake_playwright):
    out = tmp_path / "state.json"
    result = CliRunner().invoke(main, ["web-login", "https://chat.example/", "--out", str(out)], input="\n")
    assert result.exit_code == 0, result.output
    assert fake_playwright["launch"] == [{"headless": False}]
    assert fake_playwright["goto"] == ["https://chat.example/"]
    assert fake_playwright["state_after_prompt"] is True
    assert fake_playwright["closed"] is True
    assert json.loads(out.read_text()) == STATE
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "session cookies" in result.output and "Do not commit" in result.output


def test_refuses_to_overwrite_without_force(tmp_path, fake_playwright):
    out = tmp_path / "state.json"
    out.write_text("keep me")
    result = CliRunner().invoke(main, ["web-login", "https://chat.example/", "--out", str(out)], input="\n")
    assert result.exit_code == 1
    assert "--force" in result.output
    assert out.read_text() == "keep me"
    assert fake_playwright["launch"] == []  # refused before any browser opened


def test_force_replaces_a_world_readable_file_with_a_0600_one(tmp_path, fake_playwright):
    out = tmp_path / "state.json"
    out.write_text("old")
    os.chmod(out, 0o644)
    result = CliRunner().invoke(main, ["web-login", "https://chat.example/", "--out", str(out), "--force"],
                                input="\n")
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text()) == STATE
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_browser_failure_names_the_install_step(tmp_path, fake_playwright):
    fake_playwright["launch_error"] = _FakeError("Executable doesn't exist at /x/chrome\ncall log ...")
    out = tmp_path / "state.json"
    result = CliRunner().invoke(main, ["web-login", "https://chat.example/", "--out", str(out)], input="\n")
    assert result.exit_code == 1
    assert "Executable doesn't exist" in result.output
    assert "playwright install chromium" in result.output
    assert not out.exists()


def test_missing_playwright_prints_the_install_hint_and_exits_2(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    out = tmp_path / "state.json"
    result = CliRunner().invoke(main, ["web-login", "https://chat.example/", "--out", str(out)], input="\n")
    assert result.exit_code == 2
    assert "pip install 'argus-probe[web]' && playwright install chromium" in result.output
    assert not out.exists()
