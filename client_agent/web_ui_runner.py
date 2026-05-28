"""
Web UI Test Runner for client_agent.

Runs browser exploration locally via browser-use + Playwright, connecting to a
user-provided Chrome instance through Chrome DevTools Protocol (CDP).

Designed to be called from client_agent.py tool handlers.
"""

import asyncio
import base64
import http.server
import json
import logging
import os
import socket
import time
import uuid
from typing import Any

import httpx
import threading

logger = logging.getLogger("WebUIRunner")

# ---------------------------------------------------------------------------
# Screenshot HTTP server  (serves /tmp/webui-screenshots/ on port 9224)
# ---------------------------------------------------------------------------
_SCREENSHOT_ROOT = "/tmp/webui-screenshots"
_HTTP_PORT = 9224
_http_server_started = False
_http_server_lock = threading.Lock()


def _ensure_screenshot_server() -> None:
    """Start a CORS-enabled static HTTP server once (daemon thread)."""
    global _http_server_started
    with _http_server_lock:
        if _http_server_started:
            return
        os.makedirs(_SCREENSHOT_ROOT, exist_ok=True)

        class _Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=_SCREENSHOT_ROOT, **kwargs)

            def end_headers(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                super().end_headers()

            def log_message(self, fmt, *args):  # suppress access logs
                pass

        http.server.HTTPServer.allow_reuse_address = True
        try:
            server = http.server.HTTPServer(("", _HTTP_PORT), _Handler)
        except OSError as e:
            logger.warning("Screenshot server port %d busy (%s), skipping", _HTTP_PORT, e)
            _http_server_started = True  # Mark as started to avoid retrying
            return
        threading.Thread(
            target=server.serve_forever, daemon=True, name="screenshot-server"
        ).start()
        _http_server_started = True
        logger.info("Screenshot HTTP server started on port %d", _HTTP_PORT)


# ---------------------------------------------------------------------------
# API Service credentials (set by client_agent after OAuth login)
# ---------------------------------------------------------------------------
_api_service_url: str | None = None
_api_access_token: str | None = None


def set_api_credentials(api_service_url: str, access_token: str) -> None:
    """Store API Service credentials so screenshot uploads and LLM proxy can authenticate."""
    global _api_service_url, _api_access_token
    _api_service_url = api_service_url
    _api_access_token = access_token


def _get_llm_proxy_config() -> tuple[str, str]:
    """Return (base_url, api_key) for the LLM proxy on the API Service.

    The API Service exposes an OpenAI-compatible endpoint at
    /api/v1/llm/chat/completions.  We set base_url so the openai SDK
    hits that endpoint, and use the user's access token as the api_key
    (the proxy authenticates via the same token).
    """
    if not _api_service_url or not _api_access_token:
        raise RuntimeError(
            "API Service credentials not set. "
            "Ensure the client agent registered successfully before running LLM tasks."
        )
    base = _api_service_url.rstrip("/")
    if not base.endswith("/api/v1"):
        base = f"{base}/api/v1"
    return f"{base}/llm", _api_access_token


# ---------------------------------------------------------------------------
# In-memory task store  +  per-task cancel events
# ---------------------------------------------------------------------------
_tasks: dict[str, dict] = {}
_cancel_events: dict[str, threading.Event] = {}
_tasks_lock = threading.Lock()

_TEST_SCRIPT_PROMPT = """\
You are a senior SDET. Generate a complete pytest + Playwright test script based on this
web exploration report.

TARGET URL: {url}
TARGET DOMAIN: {domain}

EXPLORATION REPORT:
{report}

REQUIREMENTS:
- Use pytest + playwright-pytest (sync API, `page` fixture from conftest.py)
- conftest.py is separate — DO NOT redefine the `page` fixture
- All test assertions MUST stay within {domain} — never assert on external domains
- For each external redirect in the report, add a test that:
    1. Navigates to the page containing the redirect element
    2. Clicks the element
    3. Asserts new_url starts with the expected external domain
    4. page.go_back() to return to {domain}
- Always use page.wait_for_load_state("networkidle") after navigation
- Always use page.wait_for_selector() with timeout=10000 before asserting element presence
- Use expect(page).to_have_url() for URL assertions with re.compile() for partial matches

REQUIRED test functions (write ALL of these):
  test_page_loads          — verify {url} returns 200, title is non-empty, no JS error banners visible
  test_navigation          — click each top-level nav link, verify URL stays on {domain} and page loads
  test_core_journey        — exercise the primary feature flow found in the report (step by step)
  test_form_validation     — find the main form; test empty submit, invalid email, >100 char input
  test_external_redirects  — verify each redirect discovered goes to the correct domain (skip if none)
  test_security_basics     — paste XSS payload in search/text field, verify no alert fires

MARKERS:
  @pytest.mark.smoke      → test_page_loads, test_navigation, test_core_journey
  @pytest.mark.security   → test_security_basics
  @pytest.mark.redirect   → test_external_redirects
  @pytest.mark.validation → test_form_validation

BEST PRACTICES:
  - Add page.set_default_timeout(15000) at the start of each test
  - Use try/except for optional UI elements (e.g., cookie banners, login prompts)
  - Each test must be independent and self-contained
  - Add a comment above each test explaining what it verifies

Generate ONLY the Python file content. No markdown fences. Start with import statements.
"""


# ---------------------------------------------------------------------------
# CDP pre-flight connectivity check
# ---------------------------------------------------------------------------
async def _check_cdp_reachable(cdp_url: str) -> None:
    """Raise a descriptive ConnectionError if Chrome CDP is not reachable."""
    check_url = cdp_url.rstrip("/") + "/json/version"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(check_url)
            resp.raise_for_status()
    except httpx.ConnectError as exc:
        raise ConnectionError(
            f"Cannot reach Chrome CDP at {cdp_url}. "
            "Make sure Chrome is running with --remote-debugging-port=9222 "
            "BEFORE starting the Web UI test. "
            "Example: google-chrome --remote-debugging-port=9222 --no-first-run "
            "--disable-backgrounding-occluded-windows "
            "--disable-renderer-backgrounding "
            "--disable-background-timer-throttling"
        ) from exc
    except Exception as exc:
        raise ConnectionError(
            f"CDP health-check failed for {cdp_url}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Core async runner
# ---------------------------------------------------------------------------
def _extract_domain(url: str) -> str:
    """Return the registered domain (scheme + netloc) from a URL."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else url



async def _run_exploration(
    task_id: str,
    url: str,
    cdp_url: str | None,
    max_steps: int,
    llm_model: str,
    credentials: dict | None,
    business_context: str | None,
    user_persona: str,
) -> None:
    """Background coroutine: runs browser-use Agent and generates test script."""
    task = _tasks[task_id]
    task["status"] = "running"
    task["started_at"] = time.time()

    try:
        from browser_use import Agent, BrowserProfile, ChatOpenAI  # type: ignore

        llm_base_url, llm_api_key = _get_llm_proxy_config()
        llm = ChatOpenAI(model=llm_model, temperature=0.2,
                         api_key=llm_api_key, base_url=llm_base_url)

        # Pre-flight: verify Chrome CDP endpoint is reachable before handing off to
        # browser-use. Fail early with a clear message rather than a deep httpx traceback.
        if cdp_url:
            await _check_cdp_reachable(cdp_url)

        # Chrome flags that prevent the screenshot watchdog from timing out.
        _ANTI_THROTTLE_ARGS = [
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-background-timer-throttling",
            "--disable-background-networking",
            "--disable-ipc-flooding-protection",
        ]
        _DOCKER_HEADLESS_ARGS = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--run-all-compositor-stages-before-draw",
        ]

        browser_args = list(_ANTI_THROTTLE_ARGS)
        if not cdp_url:
            browser_args += _DOCKER_HEADLESS_ARGS

        # Default to visible browser so users can watch the exploration.
        # Only go headless when HEADLESS=true is explicitly set in env
        # (e.g. Docker / CI where no display is available).
        force_headless = os.environ.get("HEADLESS", "").lower() in ("true", "1")
        browser_profile = BrowserProfile(
            headless=force_headless if not cdp_url else False,
            cdp_url=cdp_url,
            args=browser_args,
            chromium_sandbox=False,
        )

        has_credentials = bool(credentials)
        domain = _extract_domain(url)

        from web_ui_phases import PhaseState, run_all_phases

        phase_state = PhaseState(
            url=url,
            domain=domain,
            credentials=credentials if has_credentials else None,
            business_context=business_context,
            user_persona=user_persona,
        )

        cancel_event = _cancel_events.get(task_id)

        # Pre-create screenshot directory so _check_cancel can write immediately
        task_screenshot_dir = os.path.join(_SCREENSHOT_ROOT, task_id)
        os.makedirs(task_screenshot_dir, exist_ok=True)
        _ensure_screenshot_server()
        live_screenshot_count = [0]

        # Collect JS console errors and failed network requests via CDP.
        _console_errors: list[dict] = []
        _network_errors: list[dict] = []
        _cdp_listeners_attached = [False]
        _phase_agents: list = []  # retained so we can aggregate history across phases

        async def _attach_cdp_listeners(_agent: Any) -> None:
            """Attach CDP listeners for console and network errors (once)."""
            if _cdp_listeners_attached[0]:
                return
            try:
                bs = getattr(_agent, "browser_session", None)
                if bs is None:
                    return
                page = None
                ctx = getattr(bs, "browser_context", None)
                if ctx is not None:
                    pages = getattr(ctx, "pages", None)
                    if pages:
                        page = pages[-1] if callable(getattr(pages, '__getitem__', None)) else None
                if page is None:
                    page = getattr(bs, "current_page", None)
                if page is None:
                    return

                def _on_console(msg):
                    if msg.type in ("error", "warning"):
                        _console_errors.append({
                            "step": task.get("steps_done", 0),
                            "level": msg.type,
                            "text": msg.text[:500] if msg.text else "",
                            "url": page.url if hasattr(page, "url") else "",
                        })
                page.on("console", _on_console)

                def _on_response(response):
                    try:
                        if response.status >= 400:
                            _network_errors.append({
                                "step": task.get("steps_done", 0),
                                "status": response.status,
                                "url": response.url[:300] if response.url else "",
                            })
                    except Exception:
                        pass
                page.on("response", _on_response)

                _cdp_listeners_attached[0] = True
                logger.info("CDP console/network listeners attached for task %s", task_id)
            except Exception as exc:
                logger.debug("Could not attach CDP listeners: %s", exc)

        async def _check_cancel(_agent: Any) -> None:
            """Called by browser-use after every step — update step count + capture screenshot."""
            await _attach_cdp_listeners(_agent)

            # Update live step counter: sum across all phase agents seen so far.
            try:
                total = 0
                for _ag in _phase_agents:
                    h = getattr(_ag, "history", None)
                    total += len(getattr(h, "history", []) or [])
                task["steps_done"] = total
            except Exception:
                pass

            # Capture screenshot via browser_session.take_screenshot() (browser-use 0.11.x).
            try:
                bs = getattr(_agent, "browser_session", None)
                if bs is not None:
                    step_idx = max(0, task["steps_done"] - 1)
                    img_path = os.path.join(task_screenshot_dir, f"step_{step_idx:03d}.png")
                    ss_bytes = await bs.take_screenshot()
                    with open(img_path, "wb") as fh:
                        fh.write(ss_bytes)
                    live_screenshot_count[0] += 1
            except Exception:
                pass  # screenshot failure is non-fatal

            # Inject a budget reminder into the current phase agent's message context.
            try:
                steps_done = task.get("steps_done", 0)
                steps_left = max_steps - steps_done
                mm = getattr(_agent, "_message_manager", None)
                if mm is not None:
                    from langchain_core.messages import HumanMessage
                    budget_msg = (
                        f"╔════════════════════════════════════╗\n"
                        f"║  STEP BUDGET: {steps_done}/{max_steps} used · "
                        f"{steps_left} remaining     ║\n"
                        f"╚════════════════════════════════════╝\n"
                    )
                    if steps_left <= 2:
                        budget_msg += (
                            "⚠️  FINAL STEPS — wrap up this phase's JSON output NOW.\n"
                        )
                    mm._add_context_message(HumanMessage(content=budget_msg))
            except Exception as exc:
                logger.debug("Budget injection failed: %s", exc)

            if cancel_event and cancel_event.is_set():
                raise InterruptedError(f"Task {task_id} cancelled by user")

        def _agent_factory(task: str, **_kwargs):
            ag = Agent(
                task=task,
                llm=llm,
                browser_profile=browser_profile,
                llm_timeout=86400,
                step_timeout=600,
                max_failures=20,
            )
            _phase_agents.append(ag)
            return ag

        async def _on_phase_start(phase_name: str, budget: int) -> None:
            task["current_phase"] = phase_name
            logger.info(
                "Task %s entering phase %s (budget=%d)",
                task_id, phase_name, budget,
            )

        try:
            await run_all_phases(
                state=phase_state,
                max_steps=max_steps,
                agent_factory=_agent_factory,
                on_phase_start=_on_phase_start,
                on_step_end=_check_cancel,
            )
        except InterruptedError:
            logger.info("Task %s: interrupted (cancel) mid-phase", task_id)
        except TimeoutError as screenshot_exc:
            logger.warning(
                "Task %s: CDP screenshot timed out (%s). Continuing with partial "
                "phase results. Permanent fix: launch Chrome with "
                "--disable-backgrounding-occluded-windows "
                "--disable-renderer-backgrounding "
                "--disable-background-timer-throttling",
                task_id, screenshot_exc,
            )

        # Synthesise a combined history so downstream screenshot backfill,
        # steps_done accounting, and bug-count extraction all keep working.
        combined_steps: list = []
        for _ag in _phase_agents:
            h = getattr(_ag, "history", None)
            if h is not None:
                combined_steps.extend(getattr(h, "history", []) or [])

        class _CombinedHistory:
            def __init__(self, steps, final_text):
                self.history = steps
                self._final = final_text

            def final_result(self):
                return self._final

        history = _CombinedHistory(combined_steps, phase_state.as_final_report())

        was_cancelled = cancel_event and cancel_event.is_set()
        if was_cancelled:
            logger.info("Task %s cancelled — recovering partial results", task_id)
            if not history.history:
                task["status"] = "cancelled"
                task["finished_at"] = time.time()
                logger.info("Task %s cancelled with no recoverable history", task_id)
                return

        task["steps_done"] = len(history.history)
        final_output = history.final_result() or ""

        # ── Append automated CDP findings ────────────────────────────
        # These are objective, machine-captured signals that supplement
        # the agent's subjective observations.
        cdp_section_parts = []
        if _console_errors:
            # Deduplicate by (text, url) and keep first 20
            seen = set()
            unique_errors = []
            for e in _console_errors:
                key = (e["text"][:100], e["url"])
                if key not in seen:
                    seen.add(key)
                    unique_errors.append(e)
            cdp_section_parts.append(
                "\n\nAUTO-DETECTED CONSOLE ERRORS (captured via CDP — not agent-reported):\n"
                + "\n".join(
                    f"  [{e['level'].upper()}] step {e['step']} | {e['url']}\n    {e['text']}"
                    for e in unique_errors[:20]
                )
            )
            logger.info("Task %s: captured %d unique console errors", task_id, len(unique_errors))

        if _network_errors:
            # Deduplicate by (status, url) and keep first 20
            seen_net = set()
            unique_net = []
            for e in _network_errors:
                key = (e["status"], e["url"][:100])
                if key not in seen_net:
                    seen_net.add(key)
                    unique_net.append(e)
            cdp_section_parts.append(
                "\n\nAUTO-DETECTED NETWORK ERRORS (captured via CDP — not agent-reported):\n"
                + "\n".join(
                    f"  HTTP {e['status']} | step {e['step']} | {e['url']}"
                    for e in unique_net[:20]
                )
            )
            logger.info("Task %s: captured %d unique network errors", task_id, len(unique_net))

        if cdp_section_parts:
            final_output += "".join(cdp_section_parts)

        # Store full output (up to 32KB to avoid DB column overflow)
        task["final_output"] = final_output[:32000]
        task["console_errors"] = len(_console_errors)
        task["network_errors"] = len(_network_errors)

        # Extract bug counts from final output (includes CDP-detected errors)
        bug_counts = _count_bugs(final_output, len(_console_errors), len(_network_errors))
        task["bug_counts"] = bug_counts

        # Screenshots were captured live in _check_cancel via browser_session.take_screenshot().
        # Backfill any missed steps from browser-use 0.11.x history (screenshot_path on disk).
        import shutil
        saved_count = live_screenshot_count[0]
        for i, step in enumerate(history.history):
            img_path = os.path.join(task_screenshot_dir, f"step_{i:03d}.png")
            if os.path.exists(img_path):
                continue  # already captured live
            try:
                # browser-use 0.11.x: state.screenshot_path is a file path on disk
                ss_path = getattr(getattr(step, "state", None), "screenshot_path", None)
                if ss_path and os.path.exists(ss_path):
                    shutil.copy2(ss_path, img_path)
                    saved_count += 1
                    continue
                # Older fallback: state.screenshot is base64
                screenshot_b64 = getattr(getattr(step, "state", None), "screenshot", None)
                if screenshot_b64:
                    img_data = base64.b64decode(screenshot_b64)
                    with open(img_path, "wb") as fh:
                        fh.write(img_data)
                    saved_count += 1
            except Exception:
                pass
        task["screenshot_count"] = saved_count
        task["screenshot_base_url"] = (
            f"http://localhost:{_HTTP_PORT}/{task_id}/" if saved_count > 0 else None
        )
        logger.info("Saved %d screenshots for task %s (live=%d)", saved_count, task_id, live_screenshot_count[0])

        # Upload screenshots to API Service → R2
        if saved_count > 0 and _api_service_url and _api_access_token:
            try:
                r2_urls = await _upload_screenshots_to_api(
                    task_id, task_screenshot_dir, saved_count,
                    _api_service_url, _api_access_token,
                )
                task["screenshot_r2_urls"] = r2_urls
            except Exception as exc:
                logger.warning("Screenshot R2 upload failed for task %s: %s", task_id, exc)
                task["screenshot_r2_urls"] = []
        else:
            task["screenshot_r2_urls"] = []

        # Generate pytest test script (use codex model for better code generation)
        script_model = task.get("script_model") or os.getenv("OPENAI_SCRIPT_MODEL", "gpt-5.3-codex")
        logger.info("Generating test script for task %s with model %s...", task_id, script_model)
        test_script = await _generate_test_script(url, final_output, script_model, _extract_domain(url))
        task["test_script"] = test_script
        task["has_test_script"] = bool(test_script)

        task["status"] = "completed"
        task["finished_at"] = time.time()
        if was_cancelled:
            task["partial"] = True
            logger.info(
                "Task %s completed (PARTIAL after cancel) — steps: %d/%d, bugs: %s, screenshots: %d",
                task_id, task["steps_done"], max_steps, bug_counts, saved_count,
            )
        else:
            logger.info(
                "Task %s completed — steps: %d, bugs: %s, screenshots: %d",
                task_id, task["steps_done"], bug_counts, saved_count,
            )

        # Persist final results to API Service DB (independent of orchestrator SSE connection).
        # This ensures results survive page refresh / SSE disconnect during the run.
        if _api_service_url and _api_access_token:
            try:
                import datetime as _dt
                r2_urls = task.get("screenshot_r2_urls") or []
                async with httpx.AsyncClient(verify=False, timeout=30.0) as _client:
                    await _client.patch(
                        f"{_api_service_url.rstrip('/')}/api/v1/web-ui-tasks/{task_id}",
                        headers={"Authorization": f"Bearer {_api_access_token}"},
                        json={
                            "status": "completed",
                            "steps_done": task["steps_done"],
                            "finished_at": _dt.datetime.utcnow().isoformat(),
                            "bug_counts": bug_counts,
                            "final_output": task.get("final_output") or "",
                            "test_script": test_script,
                            "screenshot_urls": r2_urls,
                        },
                    )
                logger.info("Task %s results persisted to DB by client agent", task_id)
            except Exception as exc:
                logger.warning("Client agent DB persist failed for task %s: %s", task_id, exc)

    except (InterruptedError, Exception) as exc:
        is_cancelled = (
            isinstance(exc, InterruptedError)
            or (isinstance(_cancel_events.get(task_id), threading.Event)
                and _cancel_events[task_id].is_set())
        )
        if is_cancelled:
            task["status"] = "cancelled"
            logger.info("Task %s stopped: %s", task_id, exc)
        elif isinstance(exc, ConnectionError):
            logger.error("Task %s CDP connectivity error: %s", task_id, exc)
            task["status"] = "failed"
            task["error"] = str(exc)
        else:
            logger.exception("Web UI exploration failed for task %s", task_id)
            task["status"] = "failed"
            task["error"] = str(exc)
        task["finished_at"] = time.time()
    finally:
        _cancel_events.pop(task_id, None)


async def _upload_screenshots_to_api(
    task_id: str,
    screenshot_dir: str,
    count: int,
    api_url: str,
    token: str,
) -> list[str]:
    """Upload per-step PNGs to the API Service; returns list of R2 public URLs."""
    urls: list[str] = []
    base = api_url.rstrip("/")
    endpoint = f"{base}/api/v1/web-ui-tasks/{task_id}/screenshots"
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        for i in range(count):
            img_path = os.path.join(screenshot_dir, f"step_{i:03d}.png")
            if not os.path.exists(img_path):
                continue
            try:
                with open(img_path, "rb") as fh:
                    img_bytes = fh.read()
                resp = await client.post(
                    endpoint,
                    headers=headers,
                    files={"file": (f"step_{i:03d}.png", img_bytes, "image/png")},
                    data={"step_index": str(i)},
                )
                if resp.status_code == 200:
                    urls.append(resp.json()["url"])
                    logger.debug("Screenshot upload step %d → %s", i, resp.json()["url"])
                else:
                    logger.warning(
                        "Screenshot upload step %d failed: %s %s",
                        i, resp.status_code, resp.text[:200],
                    )
            except Exception as exc:
                logger.warning("Screenshot upload step %d error: %s", i, exc)

    logger.info("Uploaded %d/%d screenshots for task %s", len(urls), count, task_id)
    return urls


def _count_bugs(final_output: str, console_errors: int = 0, network_errors: int = 0) -> dict:
    """Count BUG lines, NOTEs, REDIRECT FAILs, Phase 3 coverage in agent output."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "redirect_fail": 0}
    phase3_items = {
        "VAL-1", "VAL-2", "VAL-3", "VAL-4",
        "FUNC-1", "FUNC-2", "FUNC-3", "FUNC-4", "FUNC-5",
        "SEC-1", "SEC-2", "SEC-3", "SEC-4",
        "UX-1", "UX-2", "UX-3",
        "JS-ERR", "REDIRECT-AUDIT",
    }
    phase3_done = set()
    note_count = 0
    for line in final_output.splitlines():
        upper = line.upper()
        # Match both "BUG:" and "BUG-NN:" formats
        if upper.lstrip().startswith("BUG"):
            if "CRITICAL" in upper:
                counts["critical"] += 1
            elif "HIGH" in upper:
                counts["high"] += 1
            elif "MEDIUM" in upper:
                counts["medium"] += 1
            elif "LOW" in upper:
                counts["low"] += 1
        # Count observations/notes
        if upper.lstrip().startswith("NOTE-"):
            note_count += 1
        # Count redirect failures from the REDIRECT CHECKS section
        if "REDIRECT:" in upper and "| FAIL" in upper:
            counts["redirect_fail"] += 1
        # Track Phase 3 checklist completion
        for item in phase3_items:
            if upper.lstrip().startswith(item + ":"):
                phase3_done.add(item)
    counts["phase3_coverage"] = len(phase3_done)
    counts["phase3_total"] = len(phase3_items)
    counts["observations"] = note_count
    counts["console_errors"] = console_errors
    counts["network_errors"] = network_errors
    return counts


async def _generate_test_script(url: str, report: str, llm_model: str, domain: str = "") -> str:
    """Call LLM to generate pytest + Playwright test script.

    Uses Responses API (for codex models) or Chat Completions API (for chat models)
    via the LLM proxy.
    """
    import re
    import httpx

    llm_base_url, llm_api_key = _get_llm_proxy_config()
    prompt = _TEST_SCRIPT_PROMPT.format(
        url=url,
        domain=domain or _extract_domain(url),
        report=report[:12000],
    )
    system_msg = "You are a senior SDET generating pytest Playwright tests."

    try:
        # Codex models use the Responses API; chat models use Chat Completions
        is_codex = "codex" in llm_model.lower()

        if is_codex:
            api_url = f"{llm_base_url}/responses"
            payload = {
                "model": llm_model,
                "input": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": prompt},
                ],
                "max_output_tokens": 16384,
                "temperature": 0.1,
            }
        else:
            api_url = f"{llm_base_url}/chat/completions"
            payload = {
                "model": llm_model,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": prompt},
                ],
                "max_completion_tokens": 16384,
                "temperature": 0.1,
            }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {llm_api_key}",
        }

        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(api_url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        # Extract text from response
        if is_codex:
            # Responses API format: output[].content[].text
            code = ""
            for item in data.get("output", []):
                if item.get("type") == "message":
                    for part in item.get("content", []):
                        if part.get("type") == "output_text":
                            code += part.get("text", "")
        else:
            # Chat Completions format
            code = data["choices"][0]["message"]["content"]

        # Strip markdown fences if present
        code = re.sub(r"^```python\s*", "", code.strip(), flags=re.MULTILINE)
        code = re.sub(r"^```\s*$", "", code, flags=re.MULTILINE)
        return code.strip()

    except Exception as exc:
        logger.warning("Test script generation failed: %s", exc)
        return f"# Test script generation failed: {exc}\n# URL: {url}\n"


# ---------------------------------------------------------------------------
# Public API (called by client_agent tool handlers)
# ---------------------------------------------------------------------------

def start_web_ui_test(
    url: str,
    cdp_url: str | None = None,
    max_steps: int = 100,
    llm_model: str | None = None,
    script_model: str | None = None,
    credentials: dict | None = None,
    business_context: str | None = None,
    user_persona: str = "new_user",
) -> dict:
    """
    Start a web UI exploration task in the background.
    Returns immediately with task_id — does not block.
    """
    import threading

    effective_model = llm_model or os.getenv("OPENAI_MODEL", "gpt-5.4-mini")
    effective_script_model = script_model or os.getenv("OPENAI_SCRIPT_MODEL", "gpt-5.3-codex")
    effective_cdp = cdp_url or os.getenv("CDP_URL") or None

    task_id = str(uuid.uuid4())
    with _tasks_lock:
        _cancel_events[task_id] = threading.Event()
        _tasks[task_id] = {
            "task_id": task_id,
            "url": url,
            "cdp_url": effective_cdp,
            "status": "pending",
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "steps_done": 0,
            "max_steps": max_steps,
            "error": None,
            "bug_counts": None,
            "has_test_script": False,
            "final_output": None,
            "screenshot_count": 0,
            "screenshot_base_url": None,
            "script_model": effective_script_model,
        }

    def _thread_runner():
        """Run _run_exploration in its own event loop, isolated from the WebSocket loop."""
        asyncio.run(
            _run_exploration(
                task_id=task_id,
                url=url,
                cdp_url=effective_cdp,
                max_steps=max_steps,
                llm_model=effective_model,
                credentials=credentials,
                business_context=business_context,
                user_persona=user_persona,
            )
        )

    thread = threading.Thread(target=_thread_runner, daemon=True, name=f"web-ui-{task_id[:8]}")
    thread.start()

    logger.info(
        "Web UI test task %s started in thread %s — url=%s cdp=%s",
        task_id, thread.name, url, effective_cdp,
    )
    return {"task_id": task_id, "status": "pending"}


def get_web_ui_test_status(task_id: str) -> dict:
    """Return current task status (no test_script field to keep response small)."""
    task = _tasks.get(task_id)
    if not task:
        return {"error": f"Task {task_id} not found"}
    return {k: v for k, v in task.items() if k != "test_script"}


def get_web_ui_test_result(task_id: str) -> dict:
    """Return full task record including test_script (only call when status==completed)."""
    task = _tasks.get(task_id)
    if not task:
        return {"error": f"Task {task_id} not found"}
    return dict(task)


def cancel_web_ui_test(task_id: str) -> dict:
    """Signal the background thread to stop after the current browser-use step."""
    with _tasks_lock:
        task = _tasks.get(task_id)
        if not task:
            return {"error": f"Task {task_id} not found"}
        if task["status"] not in ("pending", "running"):
            return {"status": task["status"], "message": "Task is not running"}
        event = _cancel_events.get(task_id)
        if event:
            event.set()
        task["status"] = "cancelled"
        task["finished_at"] = time.time()
    logger.info("Cancel requested for task %s", task_id)
    return {"task_id": task_id, "status": "cancelled"}
