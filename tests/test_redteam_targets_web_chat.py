# tests/test_redteam_targets_web_chat.py
"""web_chat target against a local fixture chat page (tests/fixtures/web_chat/).

Browser tests skip when Playwright or Chromium is missing; spec tests always run.
"""
from __future__ import annotations

import functools
import importlib.util
import json
import os
import re
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from argus.targets import build_target
from argus.targets._base import TargetDeliveryError, Turn
from argus.targets.web_chat import WebChatSpec, WebChatTarget

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "web_chat"


def _reply(turn: int, prompt: str, via: str = "click") -> str:
    # Mirrors the reply template in fixtures/web_chat/index.html.
    return f"turn {turn} ({via}): echo {prompt} - streamed word by word"


def _browsers_dir(executable: str) -> str:
    for parent in Path(executable).parents:
        if re.fullmatch(r"chromium(_headless_shell)?-\d+", parent.name):
            return str(parent.parent)
    return str(Path(executable).parent)


@pytest.fixture(scope="module")
def browsers_path():
    """Skip unless Chromium launches; return where Playwright keeps it.

    conftest points HOME at a temp dir, which hides Playwright's default
    browser cache, so tests pass the real location explicitly."""
    if importlib.util.find_spec("playwright") is None:
        pytest.skip("Playwright is not installed")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            p.chromium.launch().close()
            path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or _browsers_dir(p.chromium.executable_path)
    except Exception as e:
        pytest.skip(f"Chromium cannot be launched: {str(e).splitlines()[0]}")
    return path


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def base_url():
    handler = functools.partial(_QuietHandler, directory=str(FIXTURE_DIR))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
async def make_target(browsers_path, base_url, monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", browsers_path)
    made: list[WebChatTarget] = []

    def make(query: str = "", **overrides) -> WebChatTarget:
        fields = dict(
            kind="web_chat", url=f"{base_url}/index.html{query}",
            input_selector="#input", response_selector=".assistant", send_selector="#send",
            settle_ms=300, timeout_s=10.0,
        )
        fields.update(overrides)
        target = WebChatTarget(WebChatSpec(**fields))
        made.append(target)
        return target

    yield make
    for target in made:
        await target.aclose()


def _history(*pairs: tuple[str, str]) -> tuple[Turn, ...]:
    turns: list[Turn] = []
    for prompt, reply in pairs:
        turns += [Turn(role="user", content=prompt), Turn(role="assistant", content=reply)]
    return tuple(turns)


# --- reading the reply -------------------------------------------------------

async def test_streamed_reply_is_returned_whole_not_a_prefix(make_target):
    target = make_target()
    started = time.monotonic()
    text, latency_ms = await target.send_prompt("hello")
    elapsed_ms = (time.monotonic() - started) * 1000
    assert text == _reply(1, "hello")
    # The stream alone takes about 0.9 s; latency ends when the reply stopped changing,
    # before the settle wait that confirmed it.
    assert 800 < latency_ms < elapsed_ms - 300


async def test_busy_selector_waits_through_a_pause_longer_than_settle(make_target):
    target = make_target("?pause=1", busy_selector="#stop")
    text, _ = await target.send_prompt("hello")
    assert text == _reply(1, "hello")


async def test_without_busy_selector_a_pause_longer_than_settle_returns_the_prefix(make_target):
    # Documents why busy_selector exists: text stability alone cannot see a stalled stream.
    target = make_target("?pause=1")
    text, _ = await target.send_prompt("hello")
    words = _reply(1, "hello").split(" ")
    assert text == " ".join(words[: len(words) // 2])


async def test_enter_sends_when_send_selector_is_empty(make_target):
    target = make_target(send_selector="")
    text, _ = await target.send_prompt("by keyboard")
    assert text == _reply(1, "by keyboard", via="enter")


# --- conversations -----------------------------------------------------------

async def test_single_shot_sends_each_start_a_fresh_conversation(make_target):
    target = make_target()
    first, _ = await target.send_prompt("first")
    second, _ = await target.send_prompt("second")
    assert first == _reply(1, "first")
    assert second == _reply(1, "second")


async def test_mismatched_history_raises_and_matching_history_continues(make_target):
    target = make_target()
    first, _ = await target.send_prompt("first")
    with pytest.raises(TargetDeliveryError, match="can only continue the conversation"):
        await target.send_prompt("second", history=_history(("something else", first)))
    # The refused call touched nothing, so the real history still continues the chat.
    second, _ = await target.send_prompt("second", history=_history(("first", first)))
    assert second == _reply(2, "second")


async def test_closed_page_cannot_continue_but_a_fresh_send_restarts(make_target):
    target = make_target()
    first, _ = await target.send_prompt("first")
    await target._page.close()
    with pytest.raises(TargetDeliveryError, match="page holding this conversation was closed"):
        await target.send_prompt("second", history=_history(("first", first)))
    assert (await target.send_prompt("again"))[0] == _reply(1, "again")


async def test_history_before_any_send_raises_without_starting_a_browser(make_target):
    target = make_target()
    with pytest.raises(TargetDeliveryError, match="can only continue the conversation"):
        await target.send_prompt("second", history=_history(("first", "reply")))
    assert target._browser is None


async def test_new_chat_selector_starts_fresh_where_a_reload_keeps_the_old_chat(make_target):
    plain = make_target("?persist=1")
    await plain.send_prompt("a")
    # The reload shows turn 1 again; only the new element is the reply.
    assert (await plain.send_prompt("b"))[0] == _reply(2, "b")

    with_button = make_target("?persist=1", new_chat_selector="#new-chat")
    await with_button.send_prompt("a")
    assert (await with_button.send_prompt("b"))[0] == _reply(1, "b")


# --- failures ----------------------------------------------------------------

async def test_page_that_never_answers_times_out_quickly(make_target):
    target = make_target("?silent=1", timeout_s=1.0)
    started = time.monotonic()
    with pytest.raises(TargetDeliveryError, match="no new element matched response_selector '.assistant'"):
        await target.send_prompt("hello")
    assert time.monotonic() - started < 4


async def test_busy_timeout_says_busy_and_shows_what_was_seen(make_target):
    target = make_target("?pause=1", busy_selector="#stop", timeout_s=1.2)
    with pytest.raises(TargetDeliveryError) as info:
        await target.send_prompt("hello")
    words = _reply(1, "hello").split(" ")
    assert "busy_selector '#stop' was still visible" in str(info.value)
    assert repr(" ".join(words[: len(words) // 2])) in str(info.value)


async def test_storage_state_cookie_renders_the_chat(make_target, tmp_path, base_url):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"cookies": [{
        "name": "session", "value": "ok", "domain": "127.0.0.1", "path": "/", "expires": -1,
        "httpOnly": False, "secure": False, "sameSite": "Lax",
    }], "origins": []}))
    target = make_target("?auth=1", storage_state=str(state))
    text, _ = await target.send_prompt("logged in")
    assert text == _reply(1, "logged in")


async def test_without_storage_state_the_turn_fails_naming_input_selector(make_target):
    target = make_target("?auth=1", timeout_s=1.0)
    with pytest.raises(TargetDeliveryError, match="waiting for input_selector '#input' failed"):
        await target.send_prompt("hello")


async def test_chromium_missing_becomes_delivery_error_with_install_hint(make_target, monkeypatch, tmp_path):
    target = make_target()
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    with pytest.raises(TargetDeliveryError, match="playwright install chromium"):
        await target.send_prompt("hello")
    assert target._playwright is None


# --- lifecycle ---------------------------------------------------------------

async def test_aclose_without_start_and_twice_does_not_raise(make_target):
    never_started = make_target()
    await never_started.aclose()

    target = make_target()
    await target.send_prompt("hello")
    browser = target._browser
    assert browser.is_connected()
    await target.aclose()
    await target.aclose()
    assert not browser.is_connected()


@pytest.mark.skipif(importlib.util.find_spec("playwright") is None, reason="Playwright is not installed")
def test_build_target_registers_web_chat_without_starting_a_browser():
    target = build_target({
        "kind": "web_chat", "url": "https://chat.example/", "input_selector": "#in",
        "response_selector": ".bot",
    })
    assert isinstance(target, WebChatTarget)
    assert target.supports_history is True
    assert "llm_chat" in target.compatible_classes
    assert target._playwright is None and target._browser is None


def test_missing_playwright_raises_install_hint(monkeypatch):
    import argus.targets.web_chat as web_chat

    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(web_chat.importlib.util, "find_spec",
                        lambda name, *a: None if name == "playwright" else real_find_spec(name, *a))
    spec = WebChatSpec(url="https://chat.example/", input_selector="#in", response_selector=".bot")
    with pytest.raises(ValueError, match=re.escape("pip install 'argus-probe[web]' && playwright install chromium")):
        WebChatTarget(spec)


# --- spec validation ---------------------------------------------------------

_OK = dict(kind="web_chat", url="https://chat.example/", input_selector="#in", response_selector=".bot")


@pytest.mark.parametrize("overrides, message", [
    ({"kind": "custom_http"}, "kind must be 'web_chat'"),
    ({"url": ""}, "url is required"),
    ({"input_selector": ""}, "input_selector is required"),
    ({"response_selector": ""}, "response_selector is required"),
    ({"url": "ftp://chat.example/"}, "url must be an http"),
    ({"url": "chat.example"}, "url must be an http"),
    ({"url": "file:///etc/passwd"}, "url must be an http"),
    ({"settle_ms": 0}, "settle_ms must be a number greater than 0"),
    ({"settle_ms": -5}, "settle_ms must be a number greater than 0"),
    ({"settle_ms": True}, "settle_ms must be a number greater than 0"),
    ({"settle_ms": "2000"}, "settle_ms must be a number greater than 0"),
    ({"timeout_s": 0}, "timeout_s must be a number greater than 0"),
    ({"timeout_s": float("nan")}, "timeout_s must be a number greater than 0"),
    ({"storage_state": "/nonexistent/state.json"}, "storage_state file not found"),
    ({"headless": "false"}, "headless must be true or false"),
    ({"headless": 0}, "headless must be true or false"),
])
def test_spec_rejects(overrides, message):
    with pytest.raises(ValueError, match=re.escape(message)):
        WebChatSpec(**{**_OK, **overrides})


def test_spec_defaults():
    spec = WebChatSpec(**_OK)
    assert (spec.send_selector, spec.new_chat_selector, spec.busy_selector, spec.storage_state) == ("", "", "", "")
    assert (spec.headless, spec.settle_ms, spec.timeout_s) == (True, 2000, 120.0)


def test_spec_expands_home_in_storage_state():
    home = Path(os.environ["HOME"])
    (home / "state.json").write_text("{}")
    spec = WebChatSpec(**_OK, storage_state="~/state.json")
    assert spec.storage_state == str(home / "state.json")
