"""Web chat adapter — drives a chat page in Chromium through Playwright.

For agents reachable only through a web chat UI. The prompt is typed into
`input_selector` and sent; the reply is the text of every `response_selector`
element that appeared after the send, read once it has stopped changing for
`settle_ms` and no `busy_selector` element is visible.

Playwright is an optional dependency, so it is imported only when a browser is
actually needed.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import os
import time
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlsplit

from argus.targets._base import Target, TargetDeliveryError, Turn

_INSTALL_HINT = "pip install 'argus-probe[web]' && playwright install chromium"
_POLL_S = 0.2
_SNIPPET_CHARS = 200

# One round trip per poll, so the count and the texts come from the same DOM state.
_NEW_TEXTS_JS = "(els, n0) => els.length > n0 ? els.slice(n0).map(e => e.innerText) : null"


@dataclass(frozen=True)
class WebChatSpec:
    kind: str = "web_chat"
    url: str = ""
    input_selector: str = ""
    response_selector: str = ""
    send_selector: str = ""
    new_chat_selector: str = ""
    busy_selector: str = ""
    storage_state: str = ""
    headless: bool = True
    settle_ms: int = 2000
    timeout_s: float = 120.0

    def __post_init__(self) -> None:
        # Validate kind first.
        if self.kind != "web_chat":
            raise ValueError(f"kind must be 'web_chat', got {self.kind!r}")
        for name in ("url", "input_selector", "response_selector"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"url must be an http(s) URL, got {self.url!r}")
        # JSON "false" is a truthy string and would silently run headless.
        if not isinstance(self.headless, bool):
            raise ValueError(f"headless must be true or false, got {self.headless!r}")
        for name in ("settle_ms", "timeout_s"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
                raise ValueError(f"{name} must be a number greater than 0, got {value!r}")
        if self.storage_state:
            path = os.path.expanduser(self.storage_state)
            if not os.path.isfile(path):
                raise ValueError(f"storage_state file not found: {path}")
            object.__setattr__(self, "storage_state", path)


def _first_line(e: Exception) -> str:
    # Playwright appends a multi-line call log; the first line says what went wrong.
    return (str(e).strip().splitlines() or [type(e).__name__])[0][:300]


@contextlib.asynccontextmanager
async def _step(what: str):
    from playwright.async_api import Error as PlaywrightError

    try:
        yield
    except PlaywrightError as e:
        raise TargetDeliveryError(f"web_chat: {what} failed: {_first_line(e)}") from e


class WebChatTarget(Target):
    supports_history: ClassVar[bool] = True

    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "llm_chat", "agent_with_tools", "agent_with_rag",
        "http-chat", "tool-using", "rag",
    })

    def __init__(self, spec: WebChatSpec) -> None:
        # The browser starts on the first send: this constructor also runs just
        # to validate specs, and in a worker thread.
        if importlib.util.find_spec("playwright") is None:
            raise ValueError(f"web_chat needs Playwright: {_INSTALL_HINT}")
        self.spec = spec
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        # What the page is showing, as the runner will pass it back as history.
        self._transcript: list[Turn] = []

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        history = tuple(history)
        # Never replay: retyping old prompts would show the judge replies the page never gave.
        if history and history != tuple(self._transcript):
            raise TargetDeliveryError(
                "web_chat can only continue the conversation it is showing; the history "
                f"passed ({len(history)} turns) is not the one on the page "
                f"({len(self._transcript)} turns)"
            )
        if history and self._page.is_closed():
            self._transcript = []
            raise TargetDeliveryError("web_chat: the page holding this conversation was closed")
        transcript, self._transcript = list(history), []
        page = await self._ensure_page()
        deadline = time.monotonic() + self.spec.timeout_s
        if not history:
            await self._open_new_chat(page, deadline)
        text, latency_ms = await self._exchange(page, prompt, deadline)
        # Set only on success, so a turn that failed half way cannot be continued.
        self._transcript = [*transcript, Turn(role="user", content=prompt),
                            Turn(role="assistant", content=text)]
        return text, latency_ms

    async def aclose(self) -> None:
        context, browser, playwright = self._context, self._browser, self._playwright
        self._page = self._context = self._browser = self._playwright = None
        self._transcript = []
        # A browser that already died raises on close; there is nothing left to release then.
        for close in (context and context.close, browser and browser.close,
                      playwright and playwright.stop):
            if close:
                with contextlib.suppress(Exception):
                    await close()

    async def _ensure_page(self):
        if self._page is not None and not self._page.is_closed():
            return self._page
        # A crashed or closed page cannot be reused; start over with a new browser.
        await self.aclose()
        from playwright.async_api import async_playwright

        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.spec.headless)
        except Exception as e:
            await self.aclose()
            raise TargetDeliveryError(
                f"web_chat could not start Chromium ({_first_line(e)}); "
                "run `playwright install chromium`"
            ) from e
        try:
            self._context = await self._browser.new_context(
                storage_state=self.spec.storage_state or None
            )
            self._page = await self._context.new_page()
        except Exception as e:
            await self.aclose()
            raise TargetDeliveryError(
                f"web_chat could not open a browser context ({_first_line(e)}); "
                f"check storage_state {self.spec.storage_state!r}"
            ) from e
        return self._page

    async def _open_new_chat(self, page, deadline: float) -> None:
        s = self.spec
        async with _step(f"loading url {s.url!r}"):
            await page.goto(s.url, wait_until="domcontentloaded", timeout=_ms_left(deadline))
        async with _step(f"waiting for input_selector {s.input_selector!r}"):
            await page.locator(s.input_selector).wait_for(state="visible", timeout=_ms_left(deadline))
        if s.new_chat_selector:
            async with _step(f"clicking new_chat_selector {s.new_chat_selector!r}"):
                await page.locator(s.new_chat_selector).click(timeout=_ms_left(deadline))

    async def _exchange(self, page, prompt: str, deadline: float) -> tuple[str, float]:
        s = self.spec
        responses = page.locator(s.response_selector)
        box = page.locator(s.input_selector)
        async with _step(f"counting response_selector {s.response_selector!r}"):
            n0 = await responses.count()
        async with _step(f"typing into input_selector {s.input_selector!r}"):
            await box.fill(prompt, timeout=_ms_left(deadline))
        if s.send_selector:
            async with _step(f"clicking send_selector {s.send_selector!r}"):
                await page.locator(s.send_selector).click(timeout=_ms_left(deadline))
        else:
            async with _step(f"pressing Enter in input_selector {s.input_selector!r}"):
                await box.press("Enter", timeout=_ms_left(deadline))
        sent = time.monotonic()
        busy = page.locator(f"{s.busy_selector} >> visible=true") if s.busy_selector else None
        settle_s = s.settle_ms / 1000.0

        # Done once the new text is non-empty and nothing has moved for settle_s:
        # a text change or a visible busy element restarts the quiet window.
        text: str | None = None
        quiet_since = sent
        while True:
            async with _step(f"reading response_selector {s.response_selector!r}"):
                texts = await responses.evaluate_all(_NEW_TEXTS_JS, n0)
            is_busy = False
            if busy is not None:
                async with _step(f"checking busy_selector {s.busy_selector!r}"):
                    is_busy = await busy.count() > 0
            now = time.monotonic()
            current = None if texts is None else "\n".join(t.strip() for t in texts if t.strip())
            if current != text or is_busy:
                text, quiet_since = current, now
            if text and now - quiet_since >= settle_s:
                return text, (quiet_since - sent) * 1000.0
            if now >= deadline:
                raise TargetDeliveryError(self._timeout_reason(text, is_busy))
            await asyncio.sleep(min(_POLL_S, deadline - now))

    def _timeout_reason(self, text: str | None, is_busy: bool) -> str:
        s = self.spec
        if text is None:
            why = f"no new element matched response_selector {s.response_selector!r}"
        elif is_busy:
            why = f"busy_selector {s.busy_selector!r} was still visible"
        elif not text:
            why = "the new reply stayed empty"
        else:
            why = f"the reply was still changing (settle_ms={s.settle_ms})"
        seen = f"; seen so far: {text[:_SNIPPET_CHARS]!r}" if text else ""
        return f"web_chat: no finished reply within timeout_s={s.timeout_s:g}: {why}{seen}"


def _ms_left(deadline: float) -> float:
    # Playwright treats 0 as "no timeout", so never hand it 0.
    return max(1.0, (deadline - time.monotonic()) * 1000.0)
