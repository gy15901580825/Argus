import asyncio
import concurrent.futures
import json
import logging
import os
import re
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict

load_dotenv()

# Ensure local browser_use is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "browser_use"))

logger = logging.getLogger(__name__)

app = FastAPI(title="Web UI Testing Service")


@app.on_event("startup")
async def _create_output_dirs():
    """Ensure all output directories exist on startup."""
    for d in (FEATURES_DIR, TESTS_DIR, BUGS_DIR, SCENARIOS_DIR, TEST_RESULTS_DIR):
        d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Output directories
# ---------------------------------------------------------------------------
OUTPUT_DIR = Path("output")
FEATURES_DIR = OUTPUT_DIR / "features"
TESTS_DIR = OUTPUT_DIR / "tests"
BUGS_DIR = OUTPUT_DIR / "bugs"
SCENARIOS_DIR = OUTPUT_DIR / "scenarios"
TEST_RESULTS_DIR = OUTPUT_DIR / "test_results"
VIDEOS_DIR = OUTPUT_DIR / "videos"


# ---------------------------------------------------------------------------
# Pydantic models – request / task record
# ---------------------------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class TaskRequest(BaseModel):
    url: str
    max_steps: int = 100
    headless: bool = True
    llm_model: str = "gpt-5.4-mini"
    use_vision: bool = True
    allowed_domains: list[str] | None = None
    cdp_url: str | None = None
    credentials: Credentials | None = None
    # User-perspective exploration settings
    business_context: str | None = None   # e.g. "Job board platform for AI-era job seekers"
    user_persona: str = "new_user"        # new_user | returning_user | power_user | admin


class TaskRecord(BaseModel):
    task_id: str
    url: str
    status: str = "pending"  # pending | running | completed | failed | cancelled
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    steps_done: int = 0
    max_steps: int = 100
    result: dict | None = None
    bug_counts: dict | None = None  # {"critical": n, "high": n, "medium": n, "low": n}
    test_summary: dict | None = None  # {"total": n, "passed": n, "failed": n, "pass_rate": "n/n"}


# ---------------------------------------------------------------------------
# Pydantic models – bug report
# ---------------------------------------------------------------------------
class Bug(BaseModel):
    id: str                          # e.g. BUG-001
    severity: str                    # Critical | High | Medium | Low
    category: str                    # Security | Functional | Validation | UI | Performance | Business Logic | Session | Accessibility | Configuration
    title: str
    description: str
    url: str | None = None
    steps_to_reproduce: list[str] = []
    expected: str | None = None
    actual: str | None = None
    evidence: str | None = None      # error message, observed value, screenshot description
    fix_suggestion: str | None = None  # concrete fix recommendation


class BugReport(BaseModel):
    task_id: str
    target_url: str
    generated_at: float
    total_bugs: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    bugs: list[Bug] = []             # sorted: Critical first, then High, Medium, Low
    summary: str | None = None


# ---------------------------------------------------------------------------
# Pydantic models – scenario record (business logic flows)
# ---------------------------------------------------------------------------
class UserAction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    step: int = 0
    action_type: str = "navigate"   # navigate | click | fill | select | assert | wait
    element_description: str | None = None   # human-readable, e.g. "Search input box"
    selector: str | None = None              # xpath or css selector
    value: str | None = None                 # for fill / select actions
    expected_result: str | None = None       # what should happen after this action


class Scenario(BaseModel):
    id: str                   # e.g. SCN-001
    name: str                 # e.g. "Search for a job and view details"
    description: str
    category: str             # Core Feature | Navigation | Form | Search | Auth | Business Logic
    priority: str             # High | Medium | Low
    preconditions: list[str] = []
    steps: list[UserAction] = []
    expected_outcome: str | None = None


class ScenarioRecord(BaseModel):
    task_id: str
    target_url: str
    generated_at: float
    app_description: str | None = None      # what the app does
    core_user_flows: list[str] = []         # high-level list of main user flows
    scenarios: list[Scenario] = []
    total_scenarios: int = 0


# ---------------------------------------------------------------------------
# Pydantic models – test execution results
# ---------------------------------------------------------------------------
class TestCaseResult(BaseModel):
    name: str
    status: str        # passed | failed | error | skipped
    duration_seconds: float = 0.0
    error_message: str | None = None
    video_url: str | None = None   # relative URL to video: /tasks/{id}/videos/{name}.webm


class TestResults(BaseModel):
    task_id: str
    ran_at: float
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    pass_rate: float | str = 0.0
    test_cases: list[TestCaseResult] = []
    raw_output: str | None = None


# ---------------------------------------------------------------------------
# Pydantic models – feature record
# ---------------------------------------------------------------------------
class InteractiveElement(BaseModel):
    type: str  # e.g. button, link, input, select …
    text: str | None = None
    selector: str | None = None
    attributes: dict | None = None
    page_url: str | None = None
    is_locked: bool = False  # True if element is covered by an overlay (e.g. subscription wall)


class FormField(BaseModel):
    field_type: str  # text, email, password, checkbox …
    name: str | None = None
    label: str | None = None
    placeholder: str | None = None
    xpath: str | None = None
    input_value: str | None = None  # the value that was entered during exploration


class FormWorkflow(BaseModel):
    form_url: str | None = None
    fields: list[FormField] = []
    submit_button: str | None = None
    result: str | None = None


class NavigationPath(BaseModel):
    from_url: str | None = None
    to_url: str | None = None
    trigger_action: str | None = None
    element_tag: str | None = None
    element_text: str | None = None
    element_xpath: str | None = None
    element_attributes: dict | None = None


class PageInfo(BaseModel):
    url: str
    title: str | None = None
    interactive_elements: list[InteractiveElement] = []


class FeatureRecord(BaseModel):
    task_id: str
    target_url: str
    pages: list[PageInfo] = []
    navigation_paths: list[NavigationPath] = []
    form_workflows: list[FormWorkflow] = []
    errors: list[str] = []
    summary: str | None = None


# ---------------------------------------------------------------------------
# Pydantic models – DOM snapshot (collected post-exploration via Playwright)
# ---------------------------------------------------------------------------
class DOMElementInfo(BaseModel):
    tag: str
    text: str | None = None
    xpath: str | None = None
    href: str | None = None
    name: str | None = None
    id: str | None = None
    type: str | None = None
    placeholder: str | None = None
    aria_label: str | None = None
    role: str | None = None
    label_text: str | None = None
    form_xpath: str | None = None
    is_locked: bool = False  # True if element is covered by an overlay (e.g. subscription wall)


class FormInfo(BaseModel):
    xpath: str | None = None
    action: str | None = None
    method: str | None = None
    fields: list[DOMElementInfo] = []
    submit_buttons: list[DOMElementInfo] = []


class DOMSnapshot(BaseModel):
    url: str
    title: str | None = None
    links: list[DOMElementInfo] = []
    buttons: list[DOMElementInfo] = []
    forms: list[FormInfo] = []
    standalone_inputs: list[DOMElementInfo] = []
    selects: list[DOMElementInfo] = []  # standalone <select> elements outside forms


# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
_tasks: dict[str, TaskRecord] = {}
_asyncio_tasks: dict[str, asyncio.Task] = {}

# ---------------------------------------------------------------------------
# Agent prompt
# ---------------------------------------------------------------------------
AGENT_PROMPT_TEMPLATE = """\
You are a senior QA engineer simulating a REAL USER exploring {url}. \
Your mission has THREE phases: first understand the business, then exercise core user flows, then hunt for bugs. \
This order is critical — do NOT start security testing before you have completed the core user journeys.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCOPE — STAY ON TARGET DOMAIN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The user is testing **{target_etld1}** (and its subdomains). Stay within this \
domain at all times. Do NOT click links or navigate to unrelated external \
sites (e.g. footer "Privacy Policy" links pointing to legal-cdn.com, \
"Powered by" badges, social-media icons, third-party documentation hosts). \
Such pages are noise and pollute the generated test script.

The ONLY exceptions are unavoidable redirects that come back to the target:
  - SSO / OAuth flows (Google / Microsoft / GitHub login → returns to {target_etld1})
  - Payment provider redirects (Stripe / PayPal → returns to {target_etld1})
After authenticating, immediately resume exploration on {target_etld1}.

If you find yourself on a page outside {target_etld1} for any other reason, \
press Back and choose a different in-domain link instead.

{credentials_section}{business_context_section}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 — BUSINESS INTELLIGENCE (first 2-3 steps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Before doing anything else, visit the homepage and answer these in your memory:

[BIZ-INTEL-01] App Type: job board | e-commerce | SaaS | social | marketplace | content/blog | dev tool | other
[BIZ-INTEL-02] Core Value: What is the #1 thing this app helps users DO? (read hero text, H1, tagline)
[BIZ-INTEL-03] Primary User Persona: Who are the target users? What problem does this solve?
[BIZ-INTEL-04] Conversion Goal: What action does the app most want users to take? (sign up, purchase, apply)
[BIZ-INTEL-05] Navigation Map: List ALL top-level navigation items and their purposes.
[BIZ-INTEL-06] Key Entities: What are the main data objects? (jobs, products, posts, orders, users)
[BIZ-INTEL-07] Auth Requirement: What features require login? What is available to guests?
[BIZ-INTEL-08] Core Business Lines: Identify the 3 most important user journeys for this app type.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2 — CORE USER JOURNEY EXECUTION (majority of steps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Execute the primary user journeys you identified. Persona: {user_persona}.

=== DISCOVERY & NAVIGATION ===
[UX-01] Guest entry: What does a first-time visitor see? Click the primary CTA.
[UX-02] Navigate ALL top-level menu items. Record each page's purpose and key content.
[UX-03] Content discovery: Find and browse the main content list (jobs, products, articles, etc.)
[UX-04] Detail page: Open at least one detail/item page. What information is shown?
[UX-05] Search: Find the search interface. Search for a realistic term. Are results relevant?
[UX-06] Filter/Sort: Apply available filters or sort options. Do results update correctly?
[UX-07] Pagination/infinite scroll: If content list has multiple pages, navigate to page 2.
[UX-08] Empty state: Search for something that won't exist (e.g. "xyznonexistent99"). Is the empty state clear?
[UX-09] Footer navigation: Check footer links — privacy policy, terms, contact, social links.
[UX-10] Back navigation: After going deep into a flow, can users easily return?

=== AUTHENTICATION FLOW ===
[AUTH-UX-01] Find the sign-up flow. What information is required? Is the form clear and usable?
[AUTH-UX-02] If credentials provided, complete the login flow. Does it succeed? What happens next?
[AUTH-UX-03] After login, what does the user see first? Is the onboarding or dashboard clear?
[AUTH-UX-04] Explore the authenticated area — what new features are available after login?
[AUTH-UX-05] Find profile/account settings. What can the user configure?

=== CORE FEATURE EXECUTION ===
[CORE-01] Execute the app's #1 core feature end-to-end (as identified in Phase 1).
[CORE-02] Execute the #2 core feature.
[CORE-03] Execute any supporting feature that completes the main user journey.
[CORE-04] Data creation: If the app lets users create data (post a job, add a product, write a post), do it.
[CORE-05] Data persistence: After creating/modifying data, refresh or navigate away. Does it persist?
[CORE-06] Feedback loop: Does the app confirm successful actions with clear messages?
[CORE-07] Error recovery: Trigger a user error. Is the error message helpful and actionable?

=== DOMAIN-SPECIFIC FLOWS ===
[BL-01] JOB BOARDS: Search jobs → filter by location/category → view job details → inspect apply flow
[BL-02] E-COMMERCE: Browse category → view product → add to cart → view cart → begin checkout
[BL-03] SAAS: Create a project/workspace → use the main feature → verify data output
[BL-04] MARKETPLACES: Browse listings → view provider profile → inspect contact/booking flow
[BL-05] CONTENT PLATFORMS: Browse content → read article/post → check related content recommendations
[BL-06] ALL: Find the pricing/plans page. What tiers exist? What features are gated behind paywall?
[BL-07] ALL: Check notification or email preference settings if they exist.
[BL-08] ALL: Find dashboard/analytics view if available. Is data accurate and meaningful?

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3 — TARGETED BUG HUNTING (last portion of steps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Now test the features you ACTUALLY FOUND in Phase 2. Do NOT test hypothetical features.

=== SECURITY (on real discovered forms/inputs) ===
[SEC-01] XSS: In text inputs you found, try: <script>alert('xss')</script>. Appears unescaped?
[SEC-02] SQL Injection: In login/search fields try: ' OR '1'='1. DB errors or unexpected success?
[SEC-03] Auth Bypass: Try to access authenticated URLs directly without logging in.
[SEC-04] IDOR: If URLs have numeric IDs, change the ID. Can you access other users' data?
[SEC-05] Open Redirect: Look for ?redirect=, ?next=, ?return= params. Try https://evil.com.
[SEC-06] CSRF: Do forms you found submit with CSRF tokens?
[SEC-07] Verbose errors: Do error pages leak stack traces, SQL, file paths, or version numbers?
[SEC-08] Hidden routes: Try /admin, /api, /debug, /.env. Accessible without auth?

=== INPUT VALIDATION (on real discovered forms) ===
[VAL-01] Submit each real form with ALL fields empty. Are validation errors clear?
[VAL-02] Email fields: try notanemail, @domain.com, user@. Accepted without error?
[VAL-03] Text fields: enter 500+ characters. Does the app crash or truncate?
[VAL-04] Required fields: enter only whitespace. Accepted as valid?
[VAL-05] Submit button: double-click rapidly. Does it create duplicate records?

=== FUNCTIONAL ===
[FUNC-01] Broken links: any 404/500 pages in navigation you discovered?
[FUNC-02] Non-functional buttons: any buttons with no visible effect?
[FUNC-03] Back-button re-submission: after form submit, does back + refresh re-post?
[FUNC-04] Delete confirmation: if delete exists, is there a confirmation dialog?
[FUNC-05] Loading states: are loading indicators shown for slow operations?

=== BUSINESS LOGIC EDGE CASES ===
[BIZ-01] Can you access restricted/premium features without upgrading?
[BIZ-02] If roles exist, can lower-privilege users perform higher-privilege actions?
[BIZ-03] Multi-step flow: can you jump directly to a later step via URL?
[BIZ-04] Can you apply the same promo/coupon code multiple times?
[BIZ-05] State consistency: perform an action that updates a counter. Does the value update?

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINAL REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
First write a BUSINESS SUMMARY (3-5 lines):
BUSINESS SUMMARY:
App type: [detected type]
Core user journey: [describe the main flow a user completes, step by step]
Key features discovered: [list 3-5 main features found]
Core business lines tested: [what flows you actually exercised]
---

Then for each bug found:
BUG: [severity] [category] [title]
URL: [url where bug was found]
STEPS: [numbered steps to reproduce]
EXPECTED: [what should happen]
ACTUAL: [what actually happened]
EVIDENCE: [exact error message, unexpected value, or visual description]
---

Bug severity levels:
- CRITICAL: Data breach, auth bypass, complete feature broken, data loss
- HIGH: Security vulnerability, major feature malfunction, severe input validation failure
- MEDIUM: Partial feature broken, missing validation, confusing UX that causes errors
- LOW: Minor UI issue, inconsistent formatting, cosmetic defect
"""




# ---------------------------------------------------------------------------
# Helpers – report
# ---------------------------------------------------------------------------
def _build_report(record: TaskRecord) -> dict:
    """Transform stored AgentHistoryList data into a structured report."""
    if record.result is None:
        return {}
    return record.result


# ---------------------------------------------------------------------------
# DOM snapshot collection (sync Playwright, run in thread pool)
# ---------------------------------------------------------------------------
_DOM_EXTRACT_JS = """\
() => {
    function getXPath(el) {
        if (!el || el.nodeType !== 1) return null;
        // Prefer unique id-based path — but skip dynamic framework IDs (el-id-*, v-id-*, etc.)
        if (el.id && !/^(el-id-|v-id-|rc-|ember)[0-9]/.test(el.id)) {
            try {
                const escaped = CSS.escape(el.id);
                if (document.querySelectorAll('#' + escaped).length === 1) {
                    return '//*[@id="' + el.id + '"]';
                }
            } catch(e) {}
        }
        const parts = [];
        let node = el;
        while (node && node.nodeType === 1) {
            let idx = 1;
            let sib = node.previousSibling;
            while (sib) {
                if (sib.nodeType === 1 && sib.tagName === node.tagName) idx++;
                sib = sib.previousSibling;
            }
            parts.unshift(node.tagName.toLowerCase() + '[' + idx + ']');
            node = node.parentNode;
        }
        return '/' + parts.join('/');
    }

    function getLabel(el) {
        if (el.id) {
            const lbl = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
            if (lbl) return lbl.textContent.trim();
        }
        const parent = el.closest('label');
        if (parent) return parent.textContent.trim();
        return null;
    }

    function isBlocked(el) {
        try {
            // 1. Check for mask/lock overlay within the closest card/item container (catches off-screen elements)
            const card = el.closest('[class*="card"], [class*="item"], [class*="job"], li, article');
            if (card) {
                const maskEl = card.querySelector('[class*="mask"], [class*="lock"], [class*="overlay"], [class*="paywall"], [class*="blur"]');
                if (maskEl) {
                    const s = window.getComputedStyle(maskEl);
                    if (s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0') return true;
                }
            }
            // 2. elementFromPoint check for viewport-visible elements
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return false;
            // Skip off-screen elements (elementFromPoint won't work)
            if (rect.top < 0 || rect.bottom > window.innerHeight ||
                rect.left < 0 || rect.right > window.innerWidth) return false;
            const cx = rect.left + rect.width / 2;
            const cy = rect.top + rect.height / 2;
            const top = document.elementFromPoint(cx, cy);
            if (!top) return false;
            return !el.contains(top) && top !== el;
        } catch(e) { return false; }
    }

    function elemInfo(el, formXpath) {
        return {
            tag: el.tagName.toLowerCase(),
            text: (el.textContent || '').trim().substring(0, 200) || null,
            xpath: getXPath(el),
            href: el.getAttribute('href') || null,
            name: el.getAttribute('name') || null,
            id: el.id || null,
            type: el.getAttribute('type') || null,
            placeholder: el.getAttribute('placeholder') || null,
            aria_label: el.getAttribute('aria-label') || null,
            role: el.getAttribute('role') || null,
            label_text: (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA') ? getLabel(el) : null,
            form_xpath: formXpath || null,
            is_locked: isBlocked(el),
        };
    }

    const result = { title: document.title, links: [], buttons: [], forms: [], standalone_inputs: [], selects: [] };

    // Links
    document.querySelectorAll('a[href]').forEach(a => {
        result.links.push(elemInfo(a, null));
    });

    // Buttons (include dropdown toggles and modal triggers via aria attributes)
    document.querySelectorAll('button, [role="button"], input[type="submit"], input[type="button"], [data-toggle], [data-bs-toggle], [aria-haspopup]').forEach(b => {
        result.buttons.push(elemInfo(b, null));
    });

    // Select elements (capture options for better test value generation)
    document.querySelectorAll('select').forEach(sel => {
        const info = elemInfo(sel, null);
        info.options = Array.from(sel.options).map(o => ({ value: o.value, text: o.text }));
        result.selects.push(info);
    });

    // Forms
    document.querySelectorAll('form').forEach(form => {
        const fxp = getXPath(form);
        const fields = [];
        form.querySelectorAll('input, select, textarea').forEach(inp => {
            const t = (inp.getAttribute('type') || '').toLowerCase();
            if (t === 'hidden' || t === 'submit' || t === 'button') return;
            fields.push(elemInfo(inp, fxp));
        });
        const submits = [];
        form.querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"]').forEach(s => {
            submits.push(elemInfo(s, fxp));
        });
        result.forms.push({
            xpath: fxp,
            action: form.getAttribute('action') || null,
            method: (form.getAttribute('method') || 'GET').toUpperCase(),
            fields: fields,
            submit_buttons: submits,
        });
    });

    // Standalone inputs (not inside a form)
    document.querySelectorAll('input, select, textarea').forEach(inp => {
        if (inp.closest('form')) return;
        const t = (inp.getAttribute('type') || '').toLowerCase();
        if (t === 'hidden') return;
        result.standalone_inputs.push(elemInfo(inp, null));
    });

    return result;
}
"""

_MAX_SNAPSHOT_PAGES = 10
_MAX_SNAPSHOT_WORKERS = 3


def _collect_single_snapshot(url: str, headless: bool, cdp_url: str | None = None) -> DOMSnapshot | None:
    """Collect DOM snapshot from a single URL using sync Playwright."""
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            if cdp_url:
                browser = p.chromium.connect_over_cdp(cdp_url)
                try:
                    page = browser.contexts[0].new_page()
                except IndexError:
                    page = browser.new_page()
            else:
                browser = p.chromium.launch(headless=headless)
                page = browser.new_page()
            try:
                try:
                    response = page.goto(url, wait_until="networkidle", timeout=30000)
                except Exception:
                    # networkidle can time out on sites with persistent connections;
                    # fall back to domcontentloaded which is more lenient.
                    logger.warning("networkidle timed out for %s, retrying with domcontentloaded", url)
                    response = page.goto(url, wait_until="domcontentloaded", timeout=30000)

                # Check for auth redirect or error
                if response and response.status in (401, 403):
                    logger.info("Skipping %s: HTTP %d", url, response.status)
                    return None

                final_url = page.url
                final_parsed = urlparse(final_url)
                if final_parsed.path and any(
                    seg in final_parsed.path.lower()
                    for seg in ("/login", "/signin", "/auth")
                ):
                    orig_parsed = urlparse(url)
                    if orig_parsed.path.lower() != final_parsed.path.lower():
                        logger.info(
                            "Skipping %s: redirected to login %s", url, final_url
                        )
                        return None

                raw = page.evaluate(_DOM_EXTRACT_JS)

                # Build selects — strip unknown 'options' key from DOMElementInfo
                select_infos = []
                for sel_raw in raw.get("selects", []):
                    sel_data = {k: v for k, v in sel_raw.items() if k != "options"}
                    select_infos.append(DOMElementInfo(**sel_data))

                return DOMSnapshot(
                    url=final_url,
                    title=raw.get("title"),
                    links=[DOMElementInfo(**lnk) for lnk in raw.get("links", [])],
                    buttons=[DOMElementInfo(**btn) for btn in raw.get("buttons", [])],
                    forms=[
                        FormInfo(
                            xpath=f.get("xpath"),
                            action=f.get("action"),
                            method=f.get("method"),
                            fields=[DOMElementInfo(**fld) for fld in f.get("fields", [])],
                            submit_buttons=[
                                DOMElementInfo(**sb) for sb in f.get("submit_buttons", [])
                            ],
                        )
                        for f in raw.get("forms", [])
                    ],
                    standalone_inputs=[
                        DOMElementInfo(**si) for si in raw.get("standalone_inputs", [])
                    ],
                    selects=select_infos,
                )
            finally:
                browser.close()
    except Exception:
        logger.exception("Failed to collect DOM snapshot for %s", url)
        return None


def _collect_dom_snapshots_sync(
    page_urls: list[str], headless: bool, cdp_url: str | None = None
) -> dict[str, DOMSnapshot]:
    """Collect DOM snapshots for multiple URLs using a thread pool."""
    urls = page_urls[:_MAX_SNAPSHOT_PAGES]
    results: dict[str, DOMSnapshot] = {}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_MAX_SNAPSHOT_WORKERS
    ) as pool:
        future_to_url = {
            pool.submit(_collect_single_snapshot, u, headless, cdp_url): u for u in urls
        }
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                snap = future.result()
                if snap is not None:
                    results[url] = snap
            except Exception:
                logger.exception("Snapshot future failed for %s", url)

    logger.info("Collected DOM snapshots for %d/%d pages", len(results), len(urls))
    return results


# ---------------------------------------------------------------------------
# Enrichment functions (merge DOM snapshots into feature record)
# ---------------------------------------------------------------------------
def _find_snapshot(url: str, snapshots: dict[str, DOMSnapshot]) -> DOMSnapshot | None:
    """Find a snapshot by URL, trying exact match then path match."""
    if url in snapshots:
        return snapshots[url]
    parsed = urlparse(url)
    for snap_url, snap in snapshots.items():
        snap_parsed = urlparse(snap_url)
        if parsed.path == snap_parsed.path and parsed.netloc == snap_parsed.netloc:
            return snap
    return None


def _enrich_navigation_paths(
    nav_paths: list[NavigationPath],
    snapshots: dict[str, DOMSnapshot],
) -> None:
    """Enrich navigation paths with real DOM element data from snapshots."""
    for nav in nav_paths:
        if not nav.from_url:
            continue
        snap = _find_snapshot(nav.from_url, snapshots)
        if not snap:
            continue

        # Try to match by href
        to_parsed = urlparse(nav.to_url or "")
        to_path = to_parsed.path

        matched: DOMElementInfo | None = None

        # 1. Exact href pathname match in links
        for link in snap.links:
            if not link.href:
                continue
            link_parsed = urlparse(link.href)
            if link_parsed.path == to_path:
                matched = link
                break

        # 2. Fuzzy text match for SPAs
        if not matched and to_path:
            # Extract last meaningful segment: /affiliate → "affiliate"
            segments = [s for s in to_path.strip("/").split("/") if s]
            if segments:
                search_term = segments[-1].lower().replace("-", " ").replace("_", " ")
                # Search links first, then buttons
                for elem in [*snap.links, *snap.buttons]:
                    if elem.text and search_term in elem.text.lower():
                        matched = elem
                        break

        if matched:
            nav.element_tag = matched.tag
            nav.element_text = matched.text
            nav.element_xpath = matched.xpath
            attrs = {}
            if matched.href:
                attrs["href"] = matched.href
            if matched.id:
                attrs["id"] = matched.id
            if matched.aria_label:
                attrs["aria-label"] = matched.aria_label
            if matched.role:
                attrs["role"] = matched.role
            nav.element_attributes = attrs if attrs else None


def _enrich_form_workflows(
    form_workflows: list[FormWorkflow],
    snapshots: dict[str, DOMSnapshot],
) -> None:
    """Enrich form workflows with real DOM field data from snapshots."""
    for fw in form_workflows:
        if not fw.form_url:
            continue
        snap = _find_snapshot(fw.form_url, snapshots)
        if not snap:
            continue

        if not snap.forms:
            # Try standalone inputs if no forms found
            if snap.standalone_inputs and fw.fields:
                for i, field in enumerate(fw.fields):
                    if i < len(snap.standalone_inputs):
                        si = snap.standalone_inputs[i]
                        field.name = si.name or field.name
                        field.field_type = si.type or field.field_type
                        field.placeholder = si.placeholder or field.placeholder
                        field.xpath = si.xpath or field.xpath
                        field.label = si.label_text or si.aria_label or field.label
            continue

        # Find best matching form by field count
        best_form: FormInfo | None = None
        best_diff = float("inf")
        for form in snap.forms:
            diff = abs(len(form.fields) - len(fw.fields))
            if diff < best_diff:
                best_diff = diff
                best_form = form

        if not best_form:
            continue

        # Map fields by index order
        for i, field in enumerate(fw.fields):
            if i < len(best_form.fields):
                dom_field = best_form.fields[i]
                field.name = dom_field.name or field.name
                field.field_type = dom_field.type or field.field_type
                field.placeholder = dom_field.placeholder or field.placeholder
                candidate_xpath = dom_field.xpath or field.xpath
                # Strip dynamic framework IDs — they change per session; prefer placeholder/name
                if candidate_xpath and re.search(
                    r'/\*\[@id="(el-id-|v-id-|rc-)\d', candidate_xpath
                ):
                    if dom_field.placeholder or dom_field.name:
                        candidate_xpath = None  # stable selectors available; drop dynamic xpath
                field.xpath = candidate_xpath
                field.label = (
                    dom_field.label_text
                    or dom_field.aria_label
                    or dom_field.placeholder
                    or field.label
                )

        # Update submit button with real text (skip browser_use numeric indices)
        if best_form.submit_buttons:
            sb = best_form.submit_buttons[0]
            real_text = sb.text or sb.aria_label
            if real_text and not str(real_text).isdigit():
                fw.submit_button = real_text
            elif fw.submit_button and str(fw.submit_button).isdigit():
                # Current value is a numeric index from browser_use — try other buttons
                for btn in best_form.submit_buttons:
                    alt = btn.text or btn.aria_label
                    if alt and not str(alt).isdigit():
                        fw.submit_button = alt
                        break


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------
def _extract_feature_record(
    task_id: str,
    url: str,
    report: dict,
    dom_snapshots: dict[str, DOMSnapshot] | None = None,
) -> FeatureRecord:
    """Build a FeatureRecord from a completed agent report."""

    # --- Pages ----------------------------------------------------------
    pages: list[PageInfo] = []
    page_elements_map: dict[str, list[InteractiveElement]] = {}

    # Titles that are browser_use internal placeholders, not real page titles
    _BOGUS_TITLES = {"Initial Actions", "about:blank", "", "Empty Tab"}
    # URLs to skip entirely
    _SKIP_URLS = {"about:blank", "about:srcdoc", ""}

    for pv in report.get("pages_visited", []):
        page_url = pv.get("url", "")
        if page_url in _SKIP_URLS:
            continue
        raw_title = pv.get("title")
        title = raw_title if raw_title and raw_title not in _BOGUS_TITLES else None
        pages.append(PageInfo(url=page_url, title=title))
        page_elements_map[page_url] = []

    # --- Interactive elements -------------------------------------------
    for elem in report.get("interacted_elements", []):
        if not isinstance(elem, dict):
            continue

        ie_elem = elem.get("interacted_element")
        tag = ""
        text = None
        selector = None
        attributes = {}
        page_url = None

        if isinstance(ie_elem, dict):
            tag = ie_elem.get("node_name", "") or ie_elem.get("tag_name", "")
            text = ie_elem.get("ax_name", None) or ie_elem.get("text", None)
            selector = ie_elem.get("x_path", None) or ie_elem.get("xpath", None)
            attributes = ie_elem.get("attributes", {})

        # Determine element type from action keys; also extract text from action data
        action_keys = [k for k in elem if k not in ("interacted_element",)]
        if action_keys:
            first_action = action_keys[0]
            if first_action == "click":
                tag = tag or "button"
            elif first_action in ("input_text", "input"):
                tag = tag or "input"
            elif first_action in ("go_to_url", "navigate"):
                tag = tag or "link"
                # Use the URL from the navigate/go_to_url action as text
                if not text:
                    action_val = elem.get(first_action)
                    if isinstance(action_val, dict):
                        text = action_val.get("url")
                    elif isinstance(action_val, str):
                        text = action_val
            elif first_action == "scroll_down":
                tag = tag or "scroll"
            elif first_action == "scroll_up":
                tag = tag or "scroll"
            elif first_action in ("extract_content", "extract_page_content"):
                tag = tag or "content_extraction"
            elif first_action == "done":
                continue  # skip "done" actions, they are not interactive elements

        # Skip elements with no useful information at all
        if (tag or "unknown") == "unknown" and not text and not selector:
            continue

        ie = InteractiveElement(
            type=tag or "unknown",
            text=text,
            selector=selector,
            attributes=attributes if attributes else None,
            page_url=page_url,
        )

        # Attach to first matching page or leave unattached
        if page_elements_map:
            first_page_url = list(page_elements_map.keys())[0]
            page_elements_map[first_page_url].append(ie)

    # Merge elements back into pages
    for page in pages:
        page.interactive_elements = page_elements_map.get(page.url, [])

    # --- Build a step-indexed lookup of interacted elements ---------------
    # model_actions() returns a flat list; we need to map step transitions
    # to their corresponding interacted element info.
    # Build a map: (step_index) -> list of interacted element dicts
    step_elements: dict[int, list[dict]] = {}
    elem_idx = 0
    all_elems = report.get("interacted_elements", [])
    for step in report.get("steps", []):
        step_num = step.get("step", 0)
        n_actions = len(step.get("actions", []))
        step_elements[step_num] = all_elems[elem_idx : elem_idx + n_actions]
        elem_idx += n_actions

    # Build step_url lookup: step_number -> url
    step_url_map: dict[int, str | None] = {}
    for step in report.get("steps", []):
        step_url_map[step.get("step", 0)] = step.get("url")

    # --- Navigation paths (deduplicated, skip about:blank) ----------------
    nav_paths: list[NavigationPath] = []
    seen_nav = set()
    for st in report.get("state_transitions", []):
        from_url = st.get("from_url", "")
        to_url = st.get("to_url", "")
        if from_url in _SKIP_URLS or to_url in _SKIP_URLS:
            continue
        nav_key = (from_url, to_url)
        if nav_key in seen_nav:
            continue
        seen_nav.add(nav_key)

        # Try to find the element that triggered this transition
        elem_tag = None
        elem_text = None
        elem_xpath = None
        elem_attrs = None

        # Find which step caused this transition by matching URLs
        for step in report.get("steps", []):
            s_num = step.get("step", 0)
            s_url = step.get("url")
            if s_url == from_url:
                for ie in step_elements.get(s_num, []):
                    if not isinstance(ie, dict):
                        continue
                    ie_elem = ie.get("interacted_element")
                    if isinstance(ie_elem, dict):
                        elem_tag = ie_elem.get("node_name") or ie_elem.get("tag_name")
                        elem_text = ie_elem.get("ax_name") or ie_elem.get("text")
                        elem_xpath = ie_elem.get("x_path") or ie_elem.get("xpath")
                        elem_attrs = ie_elem.get("attributes")
                        if elem_tag:
                            break
                if elem_tag:
                    break

        nav_paths.append(
            NavigationPath(
                from_url=from_url,
                to_url=to_url,
                trigger_action=st.get("action"),
                element_tag=elem_tag,
                element_text=elem_text,
                element_xpath=elem_xpath,
                element_attributes=elem_attrs,
            )
        )

    # --- Form workflows -------------------------------------------------
    form_workflows: list[FormWorkflow] = []
    current_form: dict | None = None

    for step in report.get("steps", []):
        actions = step.get("actions", [])
        s_num = step.get("step", 0)
        s_elems = step_elements.get(s_num, [])
        for action_idx, action in enumerate(actions):
            # Lookup the interacted element for this action
            ie_info = s_elems[action_idx] if action_idx < len(s_elems) else None
            ie_elem = ie_info.get("interacted_element") if isinstance(ie_info, dict) else None

            if "input" in action:
                # Start or continue a form
                if current_form is None:
                    current_form = {
                        "form_url": step.get("url"),
                        "fields": [],
                        "submit_button": None,
                        "result": None,
                    }
                input_data = action["input"]

                # Extract real element info
                field_xpath = None
                field_placeholder = None
                field_name = None
                field_type = "text"
                field_label = None
                input_value = None

                if isinstance(ie_elem, dict):
                    field_xpath = ie_elem.get("x_path") or ie_elem.get("xpath")
                    attrs = ie_elem.get("attributes", {})
                    if isinstance(attrs, dict):
                        field_placeholder = attrs.get("placeholder")
                        field_name = attrs.get("name")
                        field_type = attrs.get("type", "text")
                        field_label = attrs.get("aria-label") or ie_elem.get("ax_name") or ie_elem.get("text")

                if isinstance(input_data, dict):
                    input_value = input_data.get("text")
                    if not field_name:
                        field_name = str(input_data.get("index", ""))

                field = FormField(
                    field_type=field_type,
                    name=field_name,
                    label=field_label,
                    placeholder=field_placeholder,
                    xpath=field_xpath,
                    input_value=input_value,
                )
                current_form["fields"].append(field)

            elif "click" in action and current_form is not None:
                # Treat click after inputs as form submission
                click_data = action["click"]
                if isinstance(click_data, dict):
                    current_form["submit_button"] = str(
                        click_data.get("index", "submit")
                    )
                else:
                    current_form["submit_button"] = "submit"

                # Check results for this step
                results = step.get("results", [])
                if results:
                    first_result = results[0]
                    if isinstance(first_result, dict):
                        current_form["result"] = first_result.get(
                            "extracted_content", None
                        )

                form_workflows.append(
                    FormWorkflow(
                        form_url=current_form["form_url"],
                        fields=[
                            FormField(**f) if isinstance(f, dict) else f
                            for f in current_form["fields"]
                        ],
                        submit_button=current_form["submit_button"],
                        result=current_form["result"],
                    )
                )
                current_form = None

    # Flush any pending form without submission
    if current_form is not None:
        form_workflows.append(
            FormWorkflow(
                form_url=current_form["form_url"],
                fields=[
                    FormField(**f) if isinstance(f, dict) else f
                    for f in current_form["fields"]
                ],
                submit_button=current_form.get("submit_button"),
                result=current_form.get("result"),
            )
        )

    # --- Errors ---------------------------------------------------------
    errors = [str(e) for e in report.get("errors", []) if e]

    # --- Summary --------------------------------------------------------
    extracted = report.get("extracted_content", [])
    final_output = report.get("final_output", None)
    summary_parts = []
    if final_output:
        summary_parts.append(str(final_output))
    elif extracted:
        summary_parts.append(" | ".join(str(c) for c in extracted[:5]))
    summary = summary_parts[0] if summary_parts else None

    # --- DOM snapshot enrichment ----------------------------------------
    if dom_snapshots:
        _enrich_navigation_paths(nav_paths, dom_snapshots)
        _enrich_form_workflows(form_workflows, dom_snapshots)

        # Supplement missing page titles from snapshots
        for page in pages:
            if not page.title:
                snap = _find_snapshot(page.url, dom_snapshots)
                if snap and snap.title:
                    page.title = snap.title

        # Rebuild interactive_elements from snapshot data
        for page in pages:
            snap = _find_snapshot(page.url, dom_snapshots)
            if not snap:
                continue
            enriched: list[InteractiveElement] = []
            for link in snap.links:
                enriched.append(
                    InteractiveElement(
                        type="link",
                        text=link.text,
                        selector=link.xpath,
                        attributes={"href": link.href} if link.href else None,
                        page_url=page.url,
                        is_locked=link.is_locked,
                    )
                )
            for btn in snap.buttons:
                enriched.append(
                    InteractiveElement(
                        type="button",
                        text=btn.text,
                        selector=btn.xpath,
                        attributes={
                            k: v
                            for k, v in {
                                "id": btn.id,
                                "role": btn.role,
                                "aria-label": btn.aria_label,
                            }.items()
                            if v
                        }
                        or None,
                        page_url=page.url,
                        is_locked=btn.is_locked,
                    )
                )
            for form in snap.forms:
                for field in form.fields:
                    enriched.append(
                        InteractiveElement(
                            type="input",
                            text=field.label_text or field.placeholder,
                            selector=field.xpath,
                            attributes={
                                k: v
                                for k, v in {
                                    "name": field.name,
                                    "type": field.type,
                                    "placeholder": field.placeholder,
                                }.items()
                                if v
                            }
                            or None,
                            page_url=page.url,
                            is_locked=field.is_locked,
                        )
                    )
            for si in snap.standalone_inputs:
                enriched.append(
                    InteractiveElement(
                        type="input",
                        text=si.label_text or si.placeholder,
                        selector=si.xpath,
                        attributes={
                            k: v
                            for k, v in {
                                "name": si.name,
                                "type": si.type,
                                "placeholder": si.placeholder,
                            }.items()
                            if v
                        }
                        or None,
                        page_url=page.url,
                        is_locked=si.is_locked,
                    )
                )
            if enriched:
                page.interactive_elements = enriched

    return FeatureRecord(
        task_id=task_id,
        target_url=url,
        pages=pages,
        navigation_paths=nav_paths,
        form_workflows=form_workflows,
        errors=errors,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Test generation
# ---------------------------------------------------------------------------
TEST_GEN_PROMPT = """\
You are a senior QA engineer. Given the following JSON feature record (enriched with real DOM data: \
xpaths, element text, attributes) and a scenario record (business logic flows), generate a \
professional pytest + Playwright test script covering all the dimensions below.

The feature record contains REAL DOM selectors collected directly from the pages. \
Use the provided selectors exactly — do NOT guess or fabricate selectors.

=== FIXTURE ===
Use EXACTLY this fixture (do NOT change it):
{page_fixture}

=== CONSOLE ERROR MONITORING ===
At the top of each test function, set up console error monitoring:
```python
console_errors = []
page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
```
At the END of each test, assert no critical JS errors:
```python
critical = [e for e in console_errors if "error" in e.lower() and "favicon" not in e.lower()]
assert len(critical) == 0, f"Console errors: {{critical}}"
```

=== PAGE TESTS (test_page_<index>) ===
- `page.goto(url)`, `page.wait_for_load_state("networkidle")`
- If title known: `expect(page).to_have_title(re.compile("<substring>"), timeout=10000)`
- Else: `response = page.goto(url); assert response.ok`
- Include console error check
- IMPORTANT: Do NOT include API/docs/backend endpoints (e.g. `/api/`, `/api-docs`, `/swagger`, `/openapi.json`, `/graphql`) in page smoke tests — these are backend routes that legitimately return non-HTML 4xx responses. Only test URLs that render actual web pages with HTML content.
- For any non-page URL you must test (e.g. `/robots.txt`, `/sitemap.xml`): use `response = page.request.get(url)` and assert `response.status < 500` (not `response.ok`) since 4xx is acceptable for some utility paths.

=== NAVIGATION TESTS (test_nav_<index>) ===
- `page.goto(from_url)`, `page.wait_for_load_state("networkidle")`
- Locate and click the trigger element using priority order:
  1. `element_xpath` → `page.locator("xpath=<element_xpath>").first.click()`
  2. `element_attributes.href` → `page.locator("a[href='<pathname>']").first.click()` (use pathname only)
  3. `element_text` → `page.get_by_text("<element_text>", exact=False).first.click()`
- `page.wait_for_load_state("networkidle")`
- Assert `expect(page).to_have_url(re.compile("<path_substring>"), timeout=10000)`
- Include console error check

=== FORM TESTS (test_form_<index>) ===
- `page.goto(form_url)`, `page.wait_for_load_state("networkidle")`
- Fill each field using this PRIORITY ORDER:
  1. If `placeholder` is available: `page.get_by_placeholder("<placeholder>").fill("<input_value>")` — MOST STABLE
  2. Elif `name` attribute: `page.locator("input[name='<name>']").first.fill("<input_value>")`
  3. Elif `xpath` (only if it does NOT contain "el-id-", "v-id-", or other dynamic framework IDs): `page.locator("xpath=<xpath>").fill("<input_value>")`
  4. Elif `type` is email/password/text: `page.locator("input[type='<type>']").nth(<index>).fill("<input_value>")`
- Click submit: `page.get_by_role("button", name="<submit_button>", exact=False).first.click()`
- `page.wait_for_load_state("networkidle")`
- Assert the submit response (check for error message or URL change)
- Include console error check

=== USER JOURNEY TESTS (test_journey_<name>) — HIGHEST PRIORITY ===
Generate end-to-end user journey tests that simulate a real user completing a full business flow.
Each journey test covers multiple pages/steps in sequence.

Use the navigation_paths and form_workflows from the feature record to construct realistic flows.
Prioritize the following journey types based on app type:

- test_journey_discovery: homepage -> browse main content list -> open a detail page
  ```python
  def test_journey_discovery(page):
      # User discovers and explores main content: homepage -> list -> detail
      page.goto(BASE_URL)
      page.wait_for_load_state("networkidle")
      assert len(page.locator("a, button").all()) > 3, "Page has no interactive elements"
      # Navigate to main content section (use real nav link from feature record)
      # ... click into first item, verify detail page loads
  ```

- test_journey_search_and_filter: search -> apply filter -> verify results change
  Only generate if a search interface was discovered.

- test_journey_auth_gate: attempt protected feature as guest -> verify redirect to login
  Only generate if authenticated pages were discovered.

- test_journey_core_feature: complete the app's primary feature end-to-end
  This is the most important journey. Use the scenario record to reconstruct the steps.

RULES for journey tests:
- Each journey must span at least 2 pages/steps
- Use realistic test data (not placeholder "test" values)
- Assert meaningful outcomes at each stage (URL changed, content appeared, etc.)
- Add `timeout=8000` to all click() calls
- Use try/except with pytest.skip() for optional steps

=== SCENARIO TESTS (test_scenario_<index>) — MOST IMPORTANT ===
- Add a docstring with the scenario name, category, and expected outcome.
- Start with `page.goto(precondition_url)` and `page.wait_for_load_state("networkidle")`
- Handle locked vs unlocked elements:
  - LOCKED (is_locked=true): Do NOT click. Assert overlay exists:
    `assert page.locator("[class*='mask'], [class*='lock'], [class*='overlay']").first.is_visible()`
  - UNLOCKED (is_locked=false): Generate normal interaction steps.
- Execute each step:
  - "navigate": `page.goto(value)` then `page.wait_for_load_state("networkidle")`
  - "click" for BUTTONS: ALWAYS use `page.get_by_role("button", name="<text>", exact=False).first.click(timeout=8000)` — NEVER use `page.locator("xpath=//button[text()='X']")` (fragile exact text match fails with whitespace/icons)
  - "click" for LINKS: Vue/React SPAs render navigation as `<a>` but may not have role="link". Use a try/except with SHORT TIMEOUT to prevent hanging:
    ```python
    try:
        page.get_by_role("link", name="<text>", exact=False).first.click(timeout=8000)
    except Exception:
        try:
            page.locator("a:has-text('<text>'), button:has-text('<text>')").first.click(timeout=8000)
        except Exception:
            pytest.skip("Link '<text>' not found on page — scenario may be inapplicable")
    ```
    CRITICAL: ALWAYS add `timeout=8000` (8 seconds) to all click() calls in scenario tests to prevent hanging for missing elements.
  - "fill": use `page.get_by_placeholder("<placeholder>").fill("<value>")` when placeholder is available, else `page.locator("input[name='<name>']").first.fill("<value>")`
  - "select": `page.locator("xpath=<selector>").select_option("<value>")`
  - "assert": meaningful Playwright assertion based on expected_result
  - "wait": `page.wait_for_load_state("networkidle")`
- Add final assertion for expected_outcome
- Include console error check
- NEVER use `page.go_back()` in SPA apps — instead navigate directly with `page.goto(url)` to ensure reliable state
- For elements with CSS animations that may not be stable, use `page.locator("...").get_attribute("href")` to verify links exist WITHOUT clicking them if clicking is unreliable
- Use button text labels from the feature record exactly as discovered — do NOT guess "Sign In" if the actual button says "login"
- NEVER assert on dynamic content with hardcoded values like timestamps ("9 mins ago"), counts, or live data — use regex patterns instead: `re.search(r'\\d+ min', text)`
- NEVER use `javascript:history.back()` as a page URL for navigation — always use actual https:// URLs
- For auth-protected routes in SPAs: do NOT assert `"auth/login" in page.url` — SPAs may keep the URL but hide the content.
  For protected route redirect tests, check the ABSENCE of privileged content AND the presence of the login form:
  ```python
  body_text = page.inner_text("body").lower()
  assert "admin dashboard" not in body_text, "Protected content visible without auth"
  # Check for login form indicators (use OR to handle different button/link text variations)
  has_login_indicators = ("sign in" in body_text or "login" in body_text or
      page.locator("input[type='password']").count() > 0)
  assert has_login_indicators, "No login form or redirect detected for protected route"
  ```
- CREDENTIALS RULE: Test scenarios that require logging in with valid credentials (e.g. "Successful Login", "Happy Path Registration") CANNOT be run reliably because we don't have real test account credentials.
  For such scenarios, generate the test with this pattern:
  ```python
  # Submit credentials and check the FORM WORKED (no crash/500 error) — not whether login succeeded
  page.get_by_placeholder("Enter Email").fill("test@example.com")
  page.get_by_placeholder("Enter Password").fill("TestPassword123!")
  page.get_by_role("button", name="SIGN IN", exact=False).first.click()
  page.wait_for_timeout(1000)
  page.wait_for_load_state("networkidle")
  # The form must not crash the browser (500 server error) — invalid credentials returning error is acceptable
  body_text = page.inner_text("body")
  assert len(body_text.strip()) > 50, "Page crashed or went blank after submitting form"
  # Server must not return 500 Internal Server Error
  assert "500" not in page.title() and "internal server error" not in body_text.lower(), "Server error on form submission"
  # Do NOT assert: assert not has_error (we expect errors with fake credentials)
  # Do NOT assert: assert page.url != login_url (login will fail with fake credentials — that's expected)
  ```
  NEVER assert `"dashboard" in body_lower` or `assert not has_error` after submitting fake credentials — both will always fail.
- REGISTRATION RULE: Registration forms on modern sites often require email verification (OTP/code). You CANNOT complete registration in an automated test. For registration scenario tests, only assert that:
  1. The form submission doesn't crash (body has content, no 500 error)
  2. The page shows SOME next step (verification prompt, success, or error — all acceptable)
  ```python
  page.get_by_placeholder("Enter Email").fill("test@example.com")
  page.get_by_placeholder("Enter Password").fill("TestPassword123!")
  page.get_by_role("button", name="SIGN UP", exact=False).first.click()
  page.wait_for_timeout(1000)
  page.wait_for_load_state("networkidle")
  body_text = page.inner_text("body")
  assert len(body_text.strip()) > 50, "Page crashed or went blank after form submission"
  # Do NOT assert "registration successful" — email verification is required
  # Do NOT assert the URL changed — SPA may stay on same page for verification step
  ```
- FORM VALIDATION TIMING: After clicking submit on a form, always add `page.wait_for_timeout(1000)` before checking for validation errors, to allow async validation to render:
  ```python
  page.get_by_role("button", name="SIGN IN", exact=False).first.click()
  page.wait_for_timeout(1000)  # wait for Vue/React validation to render
  has_error = page.locator(".el-form-item__error, [role='alert']").count() > 0
  assert has_error or page.url == form_url
  ```
- NEVER assert `.is_disabled()` on form submit buttons — most modern frameworks (ElementUI, React, Vue) do NOT disable the submit button. They show validation errors when clicked instead. If a scenario says "button disabled with empty fields", test it by checking for validation errors AFTER clicking, not by asserting the button is disabled before clicking.

=== MOBILE VIEWPORT TEST (test_mobile_layout) ===
Generate ONE test that checks the site on mobile width (375px):
```python
def test_mobile_layout(page):
    page.set_viewport_size({{"width": 375, "height": 812}})
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Assert no horizontal scroll overflow
    has_overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
    assert not has_overflow, "Page has horizontal overflow on mobile (375px width)"
    # Reset viewport
    page.set_viewport_size({{"width": 1280, "height": 720}})
```

=== BOUNDARY VALUE FORM TESTS (test_form_boundary_<index>) ===
For the FIRST form workflow only, generate ONE parametrized boundary value test:
```python
@pytest.mark.parametrize("email,password,expect_error", [
    ("", "", True),                                          # empty fields
    ("notanemail", "pass", True),                            # invalid email
    ("a" * 300 + "@x.com", "pass", True),                   # too long email
    ("<script>alert(1)</script>@x.com", "pass", True),       # XSS attempt
    ("  ", "  ", True),                                      # whitespace only
])
def test_form_boundary_login(page, email, password, expect_error):
    '''Parametrized boundary value test for login form.'''
    page.goto("<form_url>")
    page.wait_for_load_state("networkidle")
    # Use get_by_placeholder (stable) if placeholder exists, else get_by_role or locator(xpath=)
    page.get_by_placeholder("<email_placeholder_or_label>").fill(email)
    page.get_by_placeholder("<password_placeholder_or_label>").fill(password)
    page.get_by_role("button", name="<submit_button>", exact=False).first.click()
    page.wait_for_load_state("networkidle")
    current_url = page.url
    has_error = False
    try:
        has_error = page.locator("[role='alert'], .error, .el-form-item__error").first.is_visible()
    except Exception:
        has_error = False
    if expect_error:
        assert has_error or current_url == "<form_url>", f"Expected error but none for email={{email}}, password={{password}}"
    else:
        assert not has_error and current_url != "<form_url>", f"No error expected but found for email={{email}}, password={{password}}"
```
Replace `<form_url>`, `<email_placeholder_or_label>`, `<password_placeholder_or_label>`, `<submit_button>` with real values from the form workflow data.
IMPORTANT: Use `get_by_placeholder()` when placeholder is available — NEVER use dynamic framework IDs (el-id-*, v-id-*, rc-*).
IMPORTANT: For the error-check assertion, use: `.el-form-item__error` (ElementUI), `[role="alert"]`, or `.error-message` — DO NOT search for hardcoded text like "required".
The correct assertion pattern when `expect_error=True` is:
    has_error = page.locator(".el-form-item__error, [role='alert']").count() > 0
    assert has_error or current_url == form_url, f"Expected error for {{email!r}}"

=== NETWORK ERROR MONITORING (test_no_broken_links) ===
Generate ONE test that intercepts all network responses and checks for 4xx/5xx errors on key assets:
```python
def test_no_broken_links(page):
    '''Verify main pages have no 5xx server errors; no broken JS/CSS assets (4xx).'''
    failed_requests = []
    def capture(r):
        # Only care about same-domain requests
        if "<base_domain>" in r.url and r.status >= 400:
            failed_requests.append((r.url, r.status))
    page.on("response", capture)
    for url in [<list of page urls>]:
        page.goto(url)
        page.wait_for_load_state("networkidle")
    # 5xx are always failures
    server_errors = [(u, s) for u, s in failed_requests if s >= 500]
    assert len(server_errors) == 0, f"Server errors (5xx): {{server_errors}}"
    # 4xx on JS/CSS/font assets means broken resources
    broken_assets = [(u, s) for u, s in failed_requests if 400 <= s < 500
                     and any(u.endswith(ext) for ext in ('.js', '.css', '.woff', '.woff2', '.ttf', '.png', '.jpg', '.svg'))]
    assert len(broken_assets) == 0, f"Broken static assets (4xx): {{broken_assets[:5]}}"
```

=== ACCESSIBILITY SMOKE TEST (test_accessibility_basics) ===
Generate ONE accessibility smoke test covering structural and ARIA accessibility (NOT image alt text — that is covered by test_image_accessibility):
```python
def test_accessibility_basics(page):
    '''Structural accessibility: buttons/links have names, page has landmarks, inputs have labels.'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Buttons must have accessible names (text content or aria-label)
    buttons_without_name = page.evaluate(
        "Array.from(document.querySelectorAll('button, [role=\"button\"]'))"
        ".filter(b => !b.textContent.trim() && !b.getAttribute('aria-label') && !b.getAttribute('title')).length"
    )
    assert buttons_without_name == 0, f"{{buttons_without_name}} button(s) have no accessible name"
    # Links without accessible text (excluding icon-only links that have aria-label)
    links_without_text = page.evaluate(
        "Array.from(document.querySelectorAll('a[href]'))"
        ".filter(a => !a.textContent.trim() && !a.getAttribute('aria-label') && !a.querySelector('img[alt]')).length"
    )
    if links_without_text > 0:
        import warnings
        warnings.warn(f"{{links_without_text}} link(s) have no accessible text (possible icon-only links without aria-label)")
    # Page should have at least one landmark role for screen reader navigation
    has_landmark = page.evaluate(
        "document.querySelector('main, [role=\"main\"], header, nav, footer, [role=\"navigation\"]') !== null"
    )
    if not has_landmark:
        import warnings
        warnings.warn("Page has no ARIA landmark roles (main, nav, header, footer) — recommended for screen reader navigation")
    # Form inputs should have associated labels
    inputs_without_label = page.evaluate(
        "Array.from(document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset])'))"
        ".filter(inp => !inp.getAttribute('aria-label') && !inp.getAttribute('placeholder') && "
        "(!inp.id || !document.querySelector('label[for=' + JSON.stringify(inp.id) + ']'))).length"
    )
    if inputs_without_label > 0:
        import warnings
        warnings.warn(f"{{inputs_without_label}} input(s) may lack labels — verify with screen reader")
```

=== KEYBOARD NAVIGATION TEST (test_keyboard_navigation) ===
Generate ONE keyboard navigation test:
```python
def test_keyboard_navigation(page):
    '''Verify the page is keyboard-accessible: Tab moves focus, Enter/Space trigger buttons.'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Tab through the first 5 focusable elements and record them
    focused_elements = []
    for _ in range(5):
        page.keyboard.press("Tab")
        focused = page.evaluate("document.activeElement ? document.activeElement.tagName : 'NONE'")
        focused_elements.append(focused)
    # At least one focusable element must exist
    assert any(e not in ("BODY", "NONE") for e in focused_elements), \
        f"No focusable elements found via Tab key: {{focused_elements}}"
```

=== DEEP LINK TEST (test_deep_link_reload) ===
Generate tests that verify pages render correctly when navigated directly (not via SPA routing):
```python
def test_deep_link_reload(page):
    '''Verify direct navigation to each page URL renders the page correctly (deep link support).'''
    urls_to_test = [<list of non-root page URLs>]
    for url in urls_to_test:
        response = page.goto(url)
        page.wait_for_load_state("networkidle")
        # Must return 200 (not redirect to login unless auth required)
        if response:
            assert response.status < 400, f"Deep link {{url}} returned HTTP {{response.status}}"
        # Page must have a non-empty body
        body_text = page.inner_text("body")
        assert len(body_text.strip()) > 50, f"Deep link {{url}} has empty/minimal body"
```

=== PERFORMANCE TEST (test_page_performance) ===
Generate ONE performance test that measures page load timing using Navigation Timing API:
```python
def test_page_performance(page):
    '''Verify key pages load within acceptable time thresholds.'''
    base_url = "<base_url>"
    page.goto(base_url)
    page.wait_for_load_state("networkidle")
    timing = page.evaluate(
        "() => {{ const nav = performance.getEntriesByType('navigation')[0];"
        " if (nav) {{ return {{domContentLoaded: Math.round(nav.domContentLoadedEventEnd),"
        " load: Math.round(nav.loadEventEnd), ttfb: Math.round(nav.responseStart)}}; }}"
        " const t = performance.timing;"
        " return {{domContentLoaded: t.domContentLoadedEventEnd - t.navigationStart,"
        " load: t.loadEventEnd - t.navigationStart,"
        " ttfb: t.responseStart - t.navigationStart}}; }}"
    )
    # Only check if timing is non-zero (page fully loaded) — use warnings (not hard assert) for network variability
    import warnings
    if timing["load"] > 0:
        if timing["ttfb"] >= 5000:
            warnings.warn(f"TTFB too slow: {{timing['ttfb']}}ms (threshold: 5000ms)")
        if timing["domContentLoaded"] >= 10000:
            warnings.warn(f"DOMContentLoaded too slow: {{timing['domContentLoaded']}}ms (threshold: 10000ms)")
        if timing["load"] >= 30000:
            warnings.warn(f"Page load too slow: {{timing['load']}}ms (threshold: 30000ms)")
```

=== SEO / META TAGS TEST (test_seo_meta_tags) ===
Generate ONE SEO smoke test that verifies essential meta tags exist:
```python
def test_seo_meta_tags(page):
    '''Verify essential SEO meta tags are present on the main page.'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Title must not be empty
    title = page.title()
    assert len(title.strip()) > 0, "Page title is empty"
    assert len(title) <= 70, f"Page title too long for SEO ({{len(title)}} chars > 70): {{title!r}}"
    # Meta description should exist
    meta_desc = page.evaluate(
        "document.querySelector('meta[name=\"description\"]')?.getAttribute('content') || ''"
    )
    # Meta description is strongly recommended (not hard fail — SPAs may inject it late)
    if not meta_desc.strip():
        import warnings
        warnings.warn("Missing meta[name='description'] tag — recommended for SEO")
    # og:title should exist for social sharing (recommended, not required)
    og_title = page.evaluate(
        "document.querySelector('meta[property=\"og:title\"]')?.getAttribute('content') || ''"
    )
    if not og_title:
        import warnings
        warnings.warn("Missing og:title meta tag (recommended for social sharing)")
    # viewport meta must exist for mobile rendering
    viewport_meta = page.evaluate(
        "document.querySelector('meta[name=\"viewport\"]')?.getAttribute('content') || ''"
    )
    assert "width=device-width" in viewport_meta, f"Viewport meta missing/malformed: {{viewport_meta!r}}"
```

=== LOCAL STORAGE / SESSION PERSISTENCE TEST (test_storage_persistence) ===
Generate ONE test verifying client-side storage behavior:
```python
def test_storage_persistence(page):
    '''Verify localStorage and sessionStorage are accessible and do not throw errors.'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Check that localStorage is available (not blocked)
    local_storage_ok = page.evaluate(
        "() => {{ try {{ localStorage.setItem('__test__', '1');"
        " const v = localStorage.getItem('__test__');"
        " localStorage.removeItem('__test__'); return v === '1';"
        " }} catch(e) {{ return false; }} }}"
    )
    assert local_storage_ok, "localStorage is not accessible or throws an error"
    # Check sessionStorage is available
    session_storage_ok = page.evaluate(
        "() => {{ try {{ sessionStorage.setItem('__test__', '1');"
        " const v = sessionStorage.getItem('__test__');"
        " sessionStorage.removeItem('__test__'); return v === '1';"
        " }} catch(e) {{ return false; }} }}"
    )
    assert session_storage_ok, "sessionStorage is not accessible or throws an error"
    # After reload, localStorage should persist but sessionStorage persists within session
    page.reload()
    page.wait_for_load_state("networkidle")
    # No errors thrown during reload
    page.evaluate("() => localStorage.length")  # should not throw
```

=== SECURITY BASICS TEST (test_security_basics) ===
Generate ONE security smoke test that checks basic security headers and HTTPS:
```python
def test_security_basics(page):
    '''Verify basic security: HTTPS, Content-Security-Policy header, no mixed content.'''
    responses = {{}}
    def capture_response(r):
        if "<base_domain>" in r.url and r.url not in responses:
            responses[r.url] = r
    page.on("response", capture_response)
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Must use HTTPS
    assert page.url.startswith("https://"), f"Page not served over HTTPS: {{page.url}}"
    # No mixed content (HTTP resources on HTTPS page)
    mixed_content = page.evaluate(
        "() => {{ const resources = performance.getEntriesByType('resource');"
        " return resources.filter(r => r.name.startsWith('http://')).map(r => r.name); }}"
    )
    assert len(mixed_content) == 0, f"Mixed content (HTTP on HTTPS page): {{mixed_content[:3]}}"
```

=== 404 ERROR PAGE TEST (test_404_error_page) ===
Generate ONE test that verifies 404 pages render gracefully (not a blank page or 500):
```python
def test_404_error_page(page):
    '''Verify that a non-existent URL renders a graceful 404 page, not a blank or broken page.'''
    nonexistent_url = "<base_url>/this-page-definitely-does-not-exist-xyz123"
    response = page.goto(nonexistent_url)
    page.wait_for_load_state("domcontentloaded")
    # Should be 404 or redirect (not 500 server error)
    if response:
        assert response.status != 500, f"Server returned 500 for missing page: {{response.status}}"
    # Page body must have content (not blank/empty)
    body_text = page.inner_text("body")
    assert len(body_text.strip()) > 20, f"404 page appears empty — body has less than 20 chars"
    # Must not show an unhandled exception stack trace
    assert "Traceback" not in body_text, "404 page exposes a Python stack trace"
    assert "SyntaxError" not in body_text and "TypeError" not in body_text, "404 page exposes JS errors"
```

=== COOKIE SECURITY TEST (test_cookie_security) ===
Generate ONE test that checks authentication cookies use proper security attributes:
```python
def test_cookie_security(page):
    '''Verify that session/auth cookies have Secure and HttpOnly attributes set.'''
    page.goto("<login_url>")
    page.wait_for_load_state("networkidle")
    # Fill login form with test credentials (use dummy data — we check cookies, not auth success)
    page.get_by_placeholder("<email_placeholder>").fill("test@example.com")
    page.get_by_placeholder("<password_placeholder>").fill("TestPassword123!")
    page.get_by_role("button", name="<submit_button>", exact=False).first.click()
    page.wait_for_load_state("networkidle")
    # Check all cookies for security attributes
    cookies = page.context.cookies()
    session_cookies = [c for c in cookies if any(k in c.get("name", "").lower()
                       for k in ("session", "token", "auth", "jwt", "access", "refresh", "sid"))]
    for cookie in session_cookies:
        # Secure flag must be set for production HTTPS sites
        assert cookie.get("secure", False), f"Session cookie '{{cookie['name']}}' missing Secure flag"
        # SameSite should be Strict or Lax (not None without Secure)
        samesite = cookie.get("sameSite", "")
        assert samesite in ("Strict", "Lax"), f"Cookie '{{cookie['name']}}' has insecure SameSite: {{samesite!r}}"
    # If no session cookies found yet, that's OK (login may have failed with test creds)
```

=== HTTP SECURITY HEADERS TEST (test_http_security_headers) ===
Generate ONE test that verifies important HTTP security response headers are present:
```python
def test_http_security_headers(page):
    '''Verify HTTP security headers: X-Content-Type-Options, X-Frame-Options, and CSP are set.'''
    response = page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    if response is None:
        return  # Cannot check headers without response
    headers = {{k.lower(): v for k, v in response.all_headers().items()}}
    # X-Content-Type-Options prevents MIME sniffing
    xcto = headers.get("x-content-type-options", "")
    assert "nosniff" in xcto.lower() or xcto == "", \
        f"X-Content-Type-Options should be 'nosniff', got: {{xcto!r}}"
    # Check for CSP or X-Frame-Options (at least one should be present for security-conscious sites)
    has_security_header = (
        "content-security-policy" in headers
        or "x-frame-options" in headers
        or "strict-transport-security" in headers
    )
    if not has_security_header:
        import warnings
        warnings.warn("No CSP, X-Frame-Options, or HSTS header found — recommended for production security")
```

=== IMAGE ACCESSIBILITY TEST (test_image_accessibility) ===
Generate ONE test that checks all visible images have non-empty alt text:
```python
def test_image_accessibility(page):
    '''Verify all visible images have descriptive alt attributes (not empty, not missing).'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Find images missing alt attribute entirely
    imgs_without_alt = page.evaluate(
        "() => {{ return Array.from(document.querySelectorAll('img:not([alt])'))."
        "filter(el => el.offsetParent !== null).map(el => el.src.split('/').pop()); }}"
    )
    assert len(imgs_without_alt) == 0, \
        f"{{len(imgs_without_alt)}} visible image(s) missing alt attribute: {{imgs_without_alt[:5]}}"
    # Find images with empty alt="" that are NOT purely decorative (i.e., have a src)
    imgs_empty_alt = page.evaluate(
        "() => {{ return Array.from(document.querySelectorAll('img[alt]'))"
        ".filter(el => el.getAttribute('alt') === '' && el.offsetParent !== null"
        " && el.src && !el.src.includes('blank'))"
        ".map(el => el.src.split('/').pop()); }}"
    )
    if imgs_empty_alt:
        import warnings
        warnings.warn(f"{{len(imgs_empty_alt)}} image(s) have empty alt — verify they are decorative: {{imgs_empty_alt[:3]}}")
```

=== BROWSER BACK BUTTON TEST (test_browser_back_navigation) ===
Generate ONE test that verifies the browser back button works correctly for SPA navigation.
Use the KNOWN discovered pages from the feature record for second_url — do NOT rely on discovering `<a href>` at runtime (SPAs use router-link or button-based navigation that won't appear as `<a href>`).
```python
def test_browser_back_navigation(page):
    '''Verify browser back button restores previous page after SPA navigation.'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    initial_url = page.url
    # Use a known second page URL from the feature record (not a runtime link discovery)
    second_url = "<second_page_url_from_feature_record>"  # e.g. "https://example.com/auth/login"
    if second_url == "<second_page_url_from_feature_record>" or not second_url:
        import pytest
        pytest.skip("No second page URL available from feature record")
    page.goto(second_url)
    page.wait_for_load_state("networkidle")
    url_at_second = page.url
    # If initial and second landed on the same URL (SPA auth redirect), skip
    if url_at_second == initial_url:
        import pytest
        pytest.skip(f"Initial URL and second URL both resolved to {{initial_url}} — SPA redirects all to same page, cannot test back navigation")
    # Go back
    page.go_back()
    page.wait_for_load_state("networkidle")
    url_after_back = page.url
    # Page should still render on the same domain (not blank, not error)
    body_text = page.inner_text("body")
    assert len(body_text.strip()) > 50, "Page body appears blank after back navigation"
    # Either URL changed (navigated back) OR we're back at initial (also success for SPAs)
    # For SPA apps that redirect (e.g. homepage → login), going back from login may re-redirect to login
    # So we just check: page didn't crash and we're still on the same domain
    base_domain = "<base_domain>"  # e.g. "example-target.com"
    assert base_domain in url_after_back, f"Back navigation left the domain: {{url_after_back}}"
    # Page must still have content
    assert len(body_text.strip()) > 50, "Page body appears blank after back navigation"
```
IMPORTANT: Replace `<second_page_url_from_feature_record>` with an actual URL from the pages[] list in the feature record (e.g. a login page, about page, etc.) — NOT a placeholder.
Replace `<base_domain>` with the actual domain (e.g. "example-target.com") — NOT a placeholder.

=== FAVICON TEST (test_favicon_accessible) ===
Generate ONE test verifying the favicon is accessible:
```python
def test_favicon_accessible(page):
    '''Verify the site favicon is accessible (returns a valid response).'''
    import urllib.parse
    base = "<base_url>".rstrip("/")
    # Check link[rel="icon"] or link[rel="shortcut icon"]
    page.goto(base)
    page.wait_for_load_state("domcontentloaded")
    favicon_href = page.evaluate(
        "document.querySelector('link[rel~=\"icon\"]')?.getAttribute('href') || '/favicon.ico'"
    )
    # Resolve relative hrefs
    if favicon_href.startswith("/"):
        favicon_url = base + favicon_href
    elif favicon_href.startswith("http"):
        favicon_url = favicon_href
    else:
        favicon_url = base + "/" + favicon_href
    response = page.request.get(favicon_url)
    assert response.status < 400, f"Favicon not accessible ({{favicon_url}}): HTTP {{response.status}}"
```

=== FORM AUTOCOMPLETE TEST (test_form_autocomplete_attributes) ===
Generate ONE test verifying login/register forms have proper autocomplete attributes for password managers:
```python
def test_form_autocomplete_attributes(page):
    '''Verify login form inputs have autocomplete attributes for browser password managers.'''
    page.goto("<login_url>")
    page.wait_for_load_state("networkidle")
    # Email/username input should have autocomplete="email" or "username"
    email_autocomplete = page.evaluate(
        "document.querySelector('input[type=\"email\"], input[placeholder*=\"mail\" i], input[name*=\"email\" i]')?.getAttribute('autocomplete') || ''"
    )
    # Password input should have autocomplete="current-password"
    pass_autocomplete = page.evaluate(
        "document.querySelector('input[type=\"password\"]')?.getAttribute('autocomplete') || ''"
    )
    # Soft warnings (not hard failures) since many frameworks omit these
    if not email_autocomplete:
        import warnings
        warnings.warn("Login email field missing autocomplete attribute — hinders password manager UX")
    if not pass_autocomplete:
        import warnings
        warnings.warn("Login password field missing autocomplete='current-password' — hinders password manager UX")
    # Soft warning: autocomplete="off" on login forms is a UX bug (breaks password managers, violates WCAG 1.3.5)
    # Not a hard failure since some sites disable it intentionally, but it should be flagged
    if email_autocomplete == "off":
        import warnings
        warnings.warn("Login email field has autocomplete='off' — breaks password managers (WCAG 1.3.5 violation)")
    if pass_autocomplete == "off":
        import warnings
        warnings.warn("Login password field has autocomplete='off' — breaks password managers (WCAG 1.3.5 violation)")
```

=== CRITICAL CODE STRUCTURE RULES ===
- EVERY test function body MUST be indented by exactly 4 spaces — never 0 spaces, never 2 or 3 spaces.
- NEVER put `page.*`, `assert`, `try:`, `if `, `for `, or any statement at module level (0 indent) EXCEPT for: `import`, `def`, `class`, `@decorator`, and top-level constants.
- ALL interaction code (`page.goto`, `page.locator`, `page.fill`, etc.) MUST be INSIDE a `def test_*` function with 4-space indentation.
- EVERY boundary/form test MUST begin with `page.goto(url)` and `page.wait_for_load_state("networkidle")` as the FIRST two statements inside the function body, before any element interaction.
- `@pytest.mark.parametrize` decorator arguments MUST only be primitive values (strings, bools, numbers). NEVER call `page.*` inside decorator arguments.
- NEVER mix CSS and text selectors with comma (a[href='/blog'], text=Blog is INVALID)
- NEVER use `text=Foo` pseudo-selector inside `page.click()`
- Always use `.first` when multiple elements might match
- Add `import re` at the top
- Add `import pytest` at the top
- Use `timeout=10000` on all `expect()` and `page.wait_for_url()` calls
- Output ONLY valid Python code, NO markdown fences, NO explanation

Feature Record:
{feature_json}

=== ROBOTS.TXT AND SITEMAP TEST (test_seo_crawlability) ===
Generate ONE test that verifies robots.txt and sitemap.xml are accessible:
```python
def test_seo_crawlability(page):
    '''Verify robots.txt is accessible and sitemap.xml is referenced or accessible.'''
    import urllib.parse
    base = "<base_url>".rstrip("/")
    # robots.txt must be accessible (200 or 404 is OK, 500 is not)
    robots_resp = page.goto(f"{{base}}/robots.txt")
    page.wait_for_load_state("domcontentloaded")
    if robots_resp:
        assert robots_resp.status < 500, f"robots.txt returned server error: {{robots_resp.status}}"
    # If robots.txt exists (200), it should have Disallow or Allow rules
    if robots_resp and robots_resp.status == 200:
        content = page.inner_text("body") or page.content()
        assert "User-agent" in content or "Disallow" in content or "Allow" in content or "Sitemap" in content, \
            "robots.txt exists but has no recognizable directives"
```

=== STRUCTURED DATA TEST (test_structured_data) ===
Generate ONE test that checks for JSON-LD or schema.org structured data on the homepage:
```python
def test_structured_data(page):
    '''Verify structured data (JSON-LD or schema.org microdata) is present for SEO.'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Check for JSON-LD scripts (use filter to avoid quote escaping in CSS selector)
    json_ld_count = page.evaluate(
        "Array.from(document.scripts).filter(s => s.type === 'application/ld+json').length"
    )
    # Check for schema.org itemtype attributes (microdata)
    microdata_count = page.evaluate(
        "document.querySelectorAll('[itemtype]').length"
    )
    has_structured_data = json_ld_count > 0 or microdata_count > 0
    if not has_structured_data:
        import warnings
        warnings.warn(f"No structured data found (JSON-LD or schema.org microdata) — helps search engines understand content")
    elif json_ld_count > 0:
        # Validate JSON-LD is valid JSON
        import json as _json
        scripts = page.evaluate(
            "Array.from(document.scripts).filter(s => s.type === 'application/ld+json').map(s => s.textContent)"
        )
        for script_text in scripts:
            try:
                _json.loads(script_text)
            except Exception as e:
                assert False, f"Invalid JSON-LD: {{e}} — content: {{script_text[:200]}}"
```

=== TABLET VIEWPORT TEST (test_tablet_layout) ===
Generate ONE test that checks the site on tablet width (768px):
```python
def test_tablet_layout(page):
    '''Verify the site renders correctly on tablet width (768px) — no overflow, key elements visible.'''
    page.set_viewport_size({{"width": 768, "height": 1024}})
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # No horizontal scroll overflow
    has_overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
    assert not has_overflow, "Page has horizontal overflow on tablet (768px width)"
    # Key navigation must still be visible or accessible via hamburger menu
    body_text = page.inner_text("body")
    assert len(body_text.strip()) > 50, "Page appears blank on tablet viewport"
    # Reset
    page.set_viewport_size({{"width": 1280, "height": 720}})
```

=== OPEN REDIRECT TEST (test_open_redirect) ===
IF the feature record shows any URL with ?redirect=, ?next=, ?url=, ?return=, ?goto= parameters, generate ONE security test:
```python
def test_open_redirect(page):
    '''Verify the app does not allow open redirects via URL parameters.'''
    import urllib.parse
    base = "<base_url>".rstrip("/")
    # Test common redirect parameter names with an external URL
    external = "https://evil.example.com"
    params_to_test = ["redirect", "next", "url", "return", "goto", "returnUrl"]
    for param in params_to_test:
        test_url = f"{{base}}/?{{param}}={{urllib.parse.quote(external, safe='')}}"
        response = page.goto(test_url)
        page.wait_for_load_state("domcontentloaded")
        # Parse current URL to check DOMAIN (not the query string which will contain "evil.example.com")
        current_url = page.url
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(current_url)
        current_domain = parsed.netloc
        # The site must NOT have redirected to the external domain
        assert "evil.example.com" not in current_domain, \
            f"Open redirect via ?{{param}}: was redirected to external domain {{current_domain}}"
        # Should stay on the base domain (not a blank page or error)
        base_domain = "<base_domain>"  # e.g. "example-target.com"
        assert base_domain in current_domain, \
            f"Potential open redirect via ?{{param}}: left base domain, now at {{current_domain}}"
```
Only generate this test if redirect-parameter URLs were found in the feature record. Skip it if no such URLs exist.

=== CSRF PROTECTION TEST (test_form_csrf_protection) ===
Generate ONE test to verify forms have CSRF protection (hidden token, SameSite cookie, or custom header):
```python
def test_form_csrf_protection(page):
    '''Verify login/register forms include CSRF protection (token field or SameSite cookies).'''
    page.goto("<login_url>")
    page.wait_for_load_state("networkidle")
    # Check for hidden CSRF token input
    csrf_input = page.evaluate(
        "document.querySelector('input[name*=\"csrf\" i], input[name*=\"token\" i], "
        "input[name=\"_token\"], input[name=\"authenticity_token\"]')?.value || ''"
    )
    # Check for SameSite cookie protection
    cookies = page.context.cookies()
    session_cookies = [c for c in cookies if any(k in c['name'].lower() for k in ['sess', 'token', 'auth', 'jwt'])]
    has_samesite = any(c.get('sameSite', '').lower() in ('strict', 'lax') for c in session_cookies)
    # Check for X-CSRF-Token or X-Requested-With meta tags
    csrf_meta = page.evaluate(
        "document.querySelector('meta[name=\"csrf-token\"], meta[name=\"_csrf\"]')?.getAttribute('content') || ''"
    )
    has_csrf_protection = bool(csrf_input) or has_samesite or bool(csrf_meta)
    if not has_csrf_protection:
        import warnings
        warnings.warn("No CSRF protection detected (no hidden CSRF token, no SameSite cookie, no CSRF meta tag) — forms may be vulnerable to cross-site request forgery")
```

=== PWA MANIFEST TEST (test_pwa_manifest) ===
Generate ONE test to check Progressive Web App (PWA) manifest:
```python
def test_pwa_manifest(page):
    '''Verify PWA manifest.json is accessible and contains required fields.'''
    import json as _json
    base = "<base_url>".rstrip("/")
    page.goto(base)
    page.wait_for_load_state("networkidle")
    # Check for manifest link tag
    manifest_href = page.evaluate(
        "document.querySelector('link[rel=\"manifest\"]')?.getAttribute('href') || ''"
    )
    if not manifest_href:
        import warnings
        warnings.warn("No <link rel='manifest'> found — site is not configured as a PWA")
        return
    manifest_url = manifest_href if manifest_href.startswith("http") else base + manifest_href
    response = page.request.get(manifest_url)
    assert response.status < 400, f"manifest.json not accessible: HTTP {{response.status}}"
    try:
        manifest = response.json()
        required_fields = ["name", "icons"]
        missing = [f for f in required_fields if f not in manifest]
        if missing:
            import warnings
            warnings.warn(f"PWA manifest missing fields: {{missing}}")
    except Exception as e:
        import warnings
        warnings.warn(f"PWA manifest.json is not valid JSON: {{e}}")
```

=== MIXED CONTENT TEST (test_mixed_content) ===
Generate ONE test that checks for HTTP resources on an HTTPS site (mixed content):
```python
def test_mixed_content(page):
    '''Verify no HTTP (insecure) resources are loaded on the HTTPS site.'''
    http_resources = []
    def capture_request(request):
        if request.url.startswith("http://") and not request.url.startswith("http://localhost"):
            http_resources.append(request.url)
    page.on("request", capture_request)
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Filter out common false positives
    filtered = [u for u in http_resources if not any(x in u for x in ["localhost", "127.0.0.1", "analytics", "tracking"])]
    if filtered:
        import warnings
        warnings.warn(f"Mixed content: {{len(filtered)}} HTTP resource(s) loaded on HTTPS page: {{filtered[:3]}}")
```

=== COOKIE CONSENT TEST (test_cookie_consent_banner) ===
Generate ONE test that checks for GDPR/CCPA cookie consent banner:
```python
def test_cookie_consent_banner(page):
    '''Check for cookie consent / GDPR banner on first visit (no prior cookies).'''
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Common selectors for cookie banners
    banner_selectors = [
        "[id*='cookie']", "[class*='cookie']", "[id*='consent']", "[class*='consent']",
        "[id*='gdpr']", "[class*='gdpr']", "[id*='ccpa']", "[class*='ccpa']",
        "[aria-label*='cookie' i]", "[data-testid*='cookie']",
    ]
    has_banner = False
    for sel in banner_selectors:
        try:
            if page.locator(sel).first.is_visible(timeout=1000):
                has_banner = True
                break
        except Exception:
            continue
    import warnings
    if not has_banner:
        warnings.warn("No cookie consent banner detected — may be required for GDPR/CCPA compliance")
    # Test passes either way (presence is good; absence is a warning)
```

=== EXTERNAL LINKS TEST (test_external_links_open_new_tab) ===
Generate ONE test verifying that external links open in a new tab (security + UX):
```python
def test_external_links_open_new_tab(page):
    '''Verify external links have target="_blank" and rel="noopener noreferrer" for security.'''
    from urllib.parse import urlparse as _up
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    base_domain = _up("<base_url>").netloc
    external_links = page.locator("a[href]").all()
    issues = []
    for link in external_links[:30]:  # check first 30 links
        try:
            href = link.get_attribute("href") or ""
            if not href.startswith("http"):
                continue
            parsed = _up(href)
            if parsed.netloc and base_domain not in parsed.netloc:
                target = link.get_attribute("target") or ""
                rel = link.get_attribute("rel") or ""
                if target != "_blank":
                    issues.append(f"External link missing target=_blank: {{href}}")
                elif "noopener" not in rel:
                    issues.append(f"External link missing rel=noopener: {{href}}")
        except Exception:
            continue
    import warnings
    for issue in issues[:5]:
        warnings.warn(issue)
    # Soft check: warn about issues rather than failing (not all sites follow this)
```

=== ROBOTS AND SITEMAP TEST (test_robots_sitemap) ===
Generate ONE test that checks robots.txt and sitemap.xml exist and are valid:
```python
def test_robots_sitemap(page):
    '''Verify robots.txt and sitemap.xml exist and are accessible.'''
    from urllib.parse import urlparse as _up
    base = _up("<base_url>").scheme + "://" + _up("<base_url>").netloc
    # Check robots.txt
    robots_resp = page.request.get(base + "/robots.txt")
    assert robots_resp.status < 400, f"robots.txt returned {{robots_resp.status}}"
    robots_text = robots_resp.text()
    assert len(robots_text.strip()) > 0, "robots.txt is empty"
    # Check sitemap (if referenced in robots.txt or at default location)
    sitemap_url = base + "/sitemap.xml"
    if "sitemap" in robots_text.lower():
        import re as _re
        m = _re.search('Sitemap:\\s*(\\S+)', robots_text, _re.IGNORECASE)
        if m:
            sitemap_url = m.group(1).strip()
    sitemap_resp = page.request.get(sitemap_url)
    import warnings
    if sitemap_resp.status >= 400:
        warnings.warn(f"Sitemap not found at {{sitemap_url}} (status {{sitemap_resp.status}})")
    else:
        sitemap_text = sitemap_resp.text()
        if "<urlset" not in sitemap_text and "<sitemapindex" not in sitemap_text:
            warnings.warn("sitemap.xml exists but doesn't look like valid XML sitemap")
```

=== CONTENT SECURITY POLICY TEST (test_content_security_policy) ===
Generate ONE test that checks for Content-Security-Policy header:
```python
def test_content_security_policy(page):
    '''Verify Content-Security-Policy header is present and not overly permissive.'''
    import warnings
    response = page.request.get("<base_url>")
    headers = response.headers
    csp = headers.get("content-security-policy", "") or headers.get("content-security-policy-report-only", "")
    if not csp:
        warnings.warn("No Content-Security-Policy header found — XSS protection may be insufficient")
        return
    # Check for unsafe-inline in script-src (dangerous)
    if "script-src" in csp and "unsafe-inline" in csp:
        warnings.warn("CSP allows unsafe-inline scripts — reduces XSS protection")
    # Check for wildcard in script-src
    if "script-src *" in csp or "default-src *" in csp:
        warnings.warn("CSP uses wildcard (*) in script-src — very permissive")
    # Soft check: warn only, don't fail (CSP misconfiguration is a warning, not a blocker)
```

=== HTML LANG ATTRIBUTE TEST (test_html_lang_attribute) ===
Generate ONE test that checks the `lang` attribute on the `<html>` element (WCAG 3.1.1):
```python
def test_html_lang_attribute(page):
    '''Verify <html> element has a lang attribute for screen reader compatibility (WCAG 3.1.1).'''
    import warnings
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    lang = page.evaluate("document.documentElement.getAttribute('lang')")
    if not lang:
        warnings.warn("Missing lang attribute on <html> element — screen readers cannot determine language (WCAG 3.1.1 violation)")
    elif len(lang.strip()) < 2:
        warnings.warn(f"lang attribute is too short ({{lang!r}}) — expected a valid BCP47 language code like 'en' or 'en-US'")
```

=== CANONICAL URL TEST (test_canonical_url) ===
Generate ONE test that checks for canonical URL meta tag (SEO):
```python
def test_canonical_url(page):
    '''Verify main page has a canonical URL tag to prevent duplicate content issues.'''
    import warnings
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    canonical = page.evaluate("(document.querySelector('link[rel=\"canonical\"]') || {{}}).href || null")
    if not canonical:
        warnings.warn("No <link rel='canonical'> found — may cause duplicate content SEO issues")
    else:
        from urllib.parse import urlparse as _up
        parsed = _up(canonical)
        if not parsed.scheme or not parsed.netloc:
            warnings.warn(f"canonical URL is not absolute: {{canonical!r}}")
```

=== SOCIAL META TAGS TEST (test_social_meta_tags_extended) ===
Generate ONE test that checks for social sharing meta tags (og:image, twitter:card):
```python
def test_social_meta_tags_extended(page):
    '''Verify Open Graph and Twitter Card meta tags are present for social sharing.'''
    import warnings
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    og_image = page.evaluate("document.querySelector('meta[property=\"og:image\"]')?.getAttribute('content')")
    twitter_card = page.evaluate("document.querySelector('meta[name=\"twitter:card\"]')?.getAttribute('content')")
    og_description = page.evaluate("document.querySelector('meta[property=\"og:description\"]')?.getAttribute('content')")
    if not og_image:
        warnings.warn("Missing og:image meta tag — social link previews will have no image")
    if not twitter_card:
        warnings.warn("Missing twitter:card meta tag — Twitter/X link previews may be broken")
    if not og_description:
        warnings.warn("Missing og:description meta tag — social link previews may have no description")
```

=== LINK TEXT QUALITY TEST (test_link_text_quality) ===
Generate ONE test that checks for non-descriptive link text (WCAG 2.4.4):
```python
def test_link_text_quality(page):
    '''Verify links have descriptive text (not just "click here" or "read more") — WCAG 2.4.4.'''
    import warnings
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    bad_link_texts = ["click here", "here", "read more", "more", "link", "this", "details"]
    links = page.locator("a").all()
    vague_links = []
    for link in links[:50]:
        try:
            text = (link.inner_text() or "").strip().lower()
            if text in bad_link_texts:
                href = link.get_attribute("href") or ""
                vague_links.append(f"'{{text}}' (href={{href[:60]}})")
        except Exception:
            continue
    if vague_links:
        warnings.warn(f"Non-descriptive link text found (WCAG 2.4.4): {{vague_links[:3]}}")
```

=== SKIP NAVIGATION LINK TEST (test_skip_navigation_link) ===
Generate ONE test that checks for a "skip to main content" link (WCAG 2.4.1):
```python
def test_skip_navigation_link(page):
    '''Verify a "skip to main content" or "skip navigation" link exists (WCAG 2.4.1).'''
    import warnings
    page.goto("<base_url>")
    page.wait_for_load_state("networkidle")
    # Skip links are often hidden until focused — check both visible and hidden
    skip_link_texts = ["skip", "skip to", "skip navigation", "skip to main", "jump to content"]
    skip_link_found = page.evaluate(
        "() => {{ const links = Array.from(document.querySelectorAll('a'));"
        " return links.some(a => a.textContent.toLowerCase().includes('skip')"
        " || (a.getAttribute('href') || '').includes('main')"
        " || (a.getAttribute('href') || '').includes('content')); }}"
    )
    if not skip_link_found:
        warnings.warn("No 'skip to main content' link found — keyboard users must tab through all navigation on every page (WCAG 2.4.1)")
```

=== FORM PLACEHOLDER LABEL TEST (test_form_placeholder_label) ===
Generate ONE test that checks forms don't rely solely on placeholder as label (WCAG 1.3.1):
```python
def test_form_placeholder_label(page):
    '''Verify form inputs have proper labels, not just placeholders (WCAG 1.3.1).'''
    import warnings
    page.goto("<base_url>/auth/login")
    page.wait_for_load_state("networkidle")
    issues = page.evaluate(
        "() => {{ const inputs = Array.from(document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button])'))"
        ".filter(el => el.offsetParent !== null);"
        " return inputs.filter(el => {{"
        "   const id = el.getAttribute('id');"
        "   const hasLabel = id && document.querySelector('label[for=\"' + id + '\"]');"
        "   const hasAriaLabel = el.getAttribute('aria-label');"
        "   const hasAriaLabelledby = el.getAttribute('aria-labelledby');"
        "   return !hasLabel && !hasAriaLabel && !hasAriaLabelledby;"
        " }}).map(el => el.name || el.id || el.type); }}"
    )
    if issues:
        warnings.warn(f"{{len(issues)}} form input(s) have no label (only placeholder): {{issues[:3]}} — screen readers rely on labels (WCAG 1.3.1)")
```

Scenario Record (business logic flows — use these to generate test_scenario_* tests):
{scenario_json}
"""


def _replace_dynamic_xpaths(code: str, feature_record: "FeatureRecord") -> str:
    """Replace dynamic framework IDs (el-id-*, v-id-*) with stable placeholder/name selectors.

    LLM-generated tests often use xpaths like //*[@id="el-id-4389-5"] which are
    Vue/ElementUI dynamic IDs that change every browser session. This function
    replaces them with stable get_by_placeholder() calls from the feature record.
    """
    # Build map: el-id-XXXX-N -> stable selector
    id_to_stable: dict[str, str] = {}
    for wf in getattr(feature_record, "form_workflows", []):
        for field in getattr(wf, "fields", []):
            xpath = getattr(field, "xpath", None) or ""
            m = re.search(r'@id="([^"]+)"', xpath)
            if m and re.search(r'^(el-id-|v-id-|rc-)\d', m.group(1)):
                id_val = m.group(1)
                if id_val not in id_to_stable:
                    placeholder = getattr(field, "placeholder", None)
                    name = getattr(field, "name", None)
                    if placeholder:
                        id_to_stable[id_val] = f'get_by_placeholder("{placeholder}")'
                    elif name and not str(name).isdigit():
                        id_to_stable[id_val] = f'locator("input[name=\'{name}\']").first'

    # Replace: page.locator("xpath=//*[@id=\"el-id-...\"]") → page.get_by_placeholder(...)
    for id_val, stable in id_to_stable.items():
        find_str = f'page.locator("xpath=//*[@id=\\"{id_val}\\"]")'
        code = code.replace(find_str, f"page.{stable}")

    return code


def _fix_module_level_page_calls(code: str) -> str:
    """Move module-level page.* calls back into the enclosing test function.

    LLMs sometimes generate test function bodies that accidentally end up at
    module level (0-indentation) instead of being indented inside the def block.
    This function detects that pattern and adds the required 4-space indent.
    """
    lines = code.split('\n')
    in_test = False
    decorator_depth = 0  # Tracks open parens inside a @decorator(...) call
    result = []

    for line in lines:
        stripped = line.strip()
        leading = len(line) - len(line.lstrip(' \t'))

        # Decorator at module level starts a new section
        if stripped.startswith('@') and leading == 0:
            in_test = False
            decorator_depth = stripped.count('(') - stripped.count(')')
            result.append(line)
            continue

        # Continue tracking parentheses inside a multi-line decorator
        if decorator_depth > 0 and leading == 0:
            decorator_depth += stripped.count('(') - stripped.count(')')
            result.append(line)
            continue

        # def at module level
        if re.match(r'^def \w+\(', line):
            in_test = line.startswith('def test_')
            decorator_depth = 0
            result.append(line)
            continue

        # class at module level → exit test context
        if re.match(r'^class \w+', line):
            in_test = False
            result.append(line)
            continue

        # Module-level non-empty code while inside a test function → fix indent
        if in_test and leading == 0 and stripped and decorator_depth == 0:
            result.append('    ' + line)
            continue

        result.append(line)

    return '\n'.join(result)


def _strip_page_fixture(code: str) -> str:
    """Remove any @pytest.fixture / def page() block the LLM generated.
    The `page` fixture is now defined in conftest.py with video recording support."""
    import ast
    lines = code.split("\n")
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect start of a page fixture: @pytest.fixture ... def page(
        if "@pytest.fixture" in line:
            # Look ahead for 'def page(' within next 3 lines
            lookahead = "\n".join(lines[i:i+4])
            if re.search(r"def page\s*\(", lookahead):
                # Skip the decorator line(s) and the function body
                # Find where the function ends (next non-indented line after def)
                # Skip decorator(s)
                while i < len(lines) and (lines[i].strip().startswith("@") or lines[i].strip() == ""):
                    i += 1
                # Skip def line
                if i < len(lines) and re.match(r"\s*def page\s*\(", lines[i]):
                    i += 1
                    # Skip body (indented lines)
                    while i < len(lines) and (lines[i].startswith("    ") or lines[i].strip() == ""):
                        i += 1
                continue
        result.append(line)
        i += 1
    return "\n".join(result)


def _deduplicate_test_functions(code: str) -> str:
    """Remove duplicate top-level function definitions, keeping only the first occurrence."""
    lines = code.split('\n')
    seen_funcs: set[str] = set()
    result: list[str] = []
    skip_until_next_top_def = False
    i = 0
    while i < len(lines):
        line = lines[i]
        # Top-level def or async def
        m = re.match(r'^(?:async )?def (test_\w+)\s*\(', line)
        if m:
            fname = m.group(1)
            if fname in seen_funcs:
                skip_until_next_top_def = True
                i += 1
                continue
            else:
                seen_funcs.add(fname)
                skip_until_next_top_def = False
        elif skip_until_next_top_def:
            # Skip lines until we hit another top-level definition or decorator
            if re.match(r'^(?:def |async def |class |@pytest\.|@\w)', line):
                skip_until_next_top_def = False
            else:
                i += 1
                continue
        result.append(line)
        i += 1
    return '\n'.join(result)


def _dedup_parametrize_decorators(code: str) -> str:
    """Remove duplicate consecutive @pytest.mark.parametrize decorators before the same function.

    LLMs sometimes generate two identical (or similar) @pytest.mark.parametrize blocks
    before a single test function. This keeps only the LAST one (most complete).
    """
    lines = code.split('\n')
    result: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect the start of a @pytest.mark.parametrize block
        if line.strip().startswith("@pytest.mark.parametrize"):
            # Collect this entire decorator block (may span multiple lines due to the list)
            deco_block: list[str] = []
            j = i
            paren_depth = 0
            while j < len(lines):
                deco_block.append(lines[j])
                paren_depth += lines[j].count('(') - lines[j].count(')')
                j += 1
                if paren_depth <= 0:
                    break
            # After the block, skip empty lines and check for another parametrize block
            while j < len(lines) and lines[j].strip() == '':
                j += 1
            # If followed by another @pytest.mark.parametrize, skip the FIRST block (this one)
            if j < len(lines) and lines[j].strip().startswith("@pytest.mark.parametrize"):
                # Skip this deco_block — the next one will be kept
                logger.info("Removed duplicate @pytest.mark.parametrize block")
                i = len(deco_block) + i  # advance past this block
                continue
            else:
                # No duplicate — keep this block
                result.extend(deco_block)
                i += len(deco_block)
                continue
        result.append(line)
        i += 1
    return '\n'.join(result)


def _fix_missing_parametrize(code: str) -> str:
    """Fix parametrize decorator issues — forward scan to track decorator blocks.

    1. Add missing @pytest.mark.parametrize to test_form_boundary_* with extra params
    2. Remove @pytest.mark.parametrize from non-boundary tests (scenario tests, etc.)
    """
    _DEFAULT_PARAMS = [
        "@pytest.mark.parametrize(\"email,password,expect_error\", [",
        "    (\"\", \"\", True),",
        "    (\"notanemail\", \"pass\", True),",
        "    (\"a\" * 300 + \"@x.com\", \"pass\", True),",
        "    (\"<script>alert(1)</script>@x.com\", \"pass\", True),",
        "    (\"  \", \"  \", True),",
        "])",
    ]

    lines = code.split('\n')
    result: list[str] = []
    i = 0
    # pending_parametrize_block: list of lines that form a @pytest.mark.parametrize block
    # waiting to be attached to the next `def test_*` function
    pending_parametrize: list[str] = []

    while i < len(lines):
        line = lines[i]

        # Collect a @pytest.mark.parametrize decorator block
        if line.strip().startswith("@pytest.mark.parametrize"):
            block: list[str] = []
            depth = 0
            j = i
            while j < len(lines):
                block.append(lines[j])
                depth += lines[j].count('(') - lines[j].count(')')
                j += 1
                if depth <= 0:
                    break
            pending_parametrize = block
            i = j
            continue

        # Detect a test function definition
        func_m = re.match(r'^def (test_\w+)\s*\(([^)]*)\)', line)
        if func_m:
            func_name = func_m.group(1)
            params = [p.strip() for p in func_m.group(2).split(',') if p.strip()]
            extra_params = [p for p in params if p != 'page']
            is_boundary = func_name.startswith("test_form_boundary_")

            if is_boundary and extra_params:
                # Boundary test: must have parametrize
                if not pending_parametrize:
                    # Add default parametrize
                    result.extend(_DEFAULT_PARAMS)
                    logger.info("Added missing @pytest.mark.parametrize to %s", func_name)
                else:
                    # Use the pending parametrize block
                    result.extend(pending_parametrize)
                pending_parametrize = []
            elif not extra_params:
                # Non-parametrized test: must NOT have parametrize
                if pending_parametrize:
                    logger.info("Removed spurious @pytest.mark.parametrize from %s", func_name)
                    pending_parametrize = []
            else:
                # Has extra params but not a boundary test — keep any pending decorator
                if pending_parametrize:
                    result.extend(pending_parametrize)
                    pending_parametrize = []

        elif line.strip().startswith("@") and not line.strip().startswith("@pytest.mark.parametrize"):
            # Other decorator — flush any pending parametrize before it
            if pending_parametrize:
                result.extend(pending_parametrize)
                pending_parametrize = []

        result.append(line)
        i += 1

    return '\n'.join(result)


_TEST_GEN_MAX_ELEMENTS_PER_PAGE = 200


def _etld1_for_url(url: str | None) -> str | None:
    """Extract eTLD+1 (e.g. https://app.example.com/x → "example.com").

    Uses a last-two-labels heuristic, which is correct for the common gTLDs
    (.com/.org/.net/.io/.ai/.co/...) but not for compound public suffixes like
    .co.uk. That's a known limitation; we don't take a `tldextract` dep for
    such an edge case in the test-gen path.
    """
    if not url:
        return None
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower().lstrip(".")
        if not host:
            return None
        if host.startswith("www."):
            host = host[4:]
        labels = host.split(".")
        if len(labels) < 2:
            return host
        return ".".join(labels[-2:])
    except Exception:
        return None


def _is_same_etld1(url: str | None, target_etld1: str | None) -> bool:
    if not target_etld1:
        return True
    return _etld1_for_url(url) == target_etld1


def _trim_feature_for_llm(
    feature_record: FeatureRecord,
    max_elements_per_page: int = _TEST_GEN_MAX_ELEMENTS_PER_PAGE,
) -> FeatureRecord:
    """Return a copy of `feature_record` filtered + capped for LLM consumption.

    Two transformations:
    1. Drop off-domain pages / navigation paths / form workflows. The user
       submitted target_url to be tested — pages on other eTLD+1s are noise
       (an "Learn more" link to iana.org bloats the record and produces tests
       that don't apply to the target).
    2. Cap each remaining page's interactive_elements (sites like
       iana.org/protocols produce 6000+ elements on one page, exploding the
       prompt past Azure's 272k token limit). Prefer high-signal element types
       (form inputs, buttons) over the long tail of plain links.

    Saved feature_record on disk is unchanged for debugging; only the LLM call
    sees the trimmed copy.
    """
    target_etld1 = _etld1_for_url(feature_record.target_url)

    type_priority = {
        "input": 0, "select": 0, "textarea": 0, "checkbox": 0, "radio": 0,
        "button": 1, "submit": 1,
        "link": 2, "a": 2,
    }
    trimmed_pages: list[PageInfo] = []
    for page in feature_record.pages:
        if not _is_same_etld1(page.url, target_etld1):
            continue
        elems = list(page.interactive_elements)
        if len(elems) > max_elements_per_page:
            elems.sort(key=lambda e: type_priority.get((e.type or "").lower(), 3))
            elems = elems[:max_elements_per_page]
        trimmed_pages.append(page.model_copy(update={"interactive_elements": elems}))

    trimmed_navs = [
        nav for nav in feature_record.navigation_paths
        if _is_same_etld1(nav.from_url, target_etld1)
        or _is_same_etld1(nav.to_url, target_etld1)
    ]
    trimmed_forms = [
        fw for fw in feature_record.form_workflows
        if _is_same_etld1(fw.form_url, target_etld1)
    ]

    return feature_record.model_copy(update={
        "pages": trimmed_pages,
        "navigation_paths": trimmed_navs,
        "form_workflows": trimmed_forms,
    })


async def _generate_test_script(
    feature_record: FeatureRecord,
    llm_model: str,
    cdp_url: str | None = None,
    scenario_record: ScenarioRecord | None = None,
) -> str:
    """Use the LLM to generate a pytest + Playwright test script."""
    from browser_use import ChatAzureOpenAI
    from browser_use.llm.messages import SystemMessage, UserMessage

    llm = ChatAzureOpenAI(
        model=llm_model,
        max_completion_tokens=32768,
    )

    trimmed = _trim_feature_for_llm(feature_record)
    original_total = sum(len(p.interactive_elements) for p in feature_record.pages)
    trimmed_total = sum(len(p.interactive_elements) for p in trimmed.pages)
    if trimmed_total < original_total:
        logger.info(
            "Trimmed feature_record for LLM: %d → %d interactive elements (cap %d/page)",
            original_total, trimmed_total, _TEST_GEN_MAX_ELEMENTS_PER_PAGE,
        )

    feature_json = trimmed.model_dump_json(indent=2)
    scenario_json = scenario_record.model_dump_json(indent=2) if scenario_record else '{"scenarios": []}'

    # The `page` fixture is now defined in conftest.py (with video recording).
    # Tell the LLM about the fixture signature so it knows how to use it,
    # but CRITICAL: DO NOT redefine it in the test file.
    if cdp_url:
        page_fixture = '''\
# NOTE: `page` fixture is defined in conftest.py — DO NOT redefine it here.
# It provides a Playwright page connected via CDP, with video recording enabled.
# Signature: def page(request) -> Page'''
    else:
        page_fixture = '''\
# NOTE: `page` fixture is defined in conftest.py — DO NOT redefine it here.
# It provides a function-scoped Playwright Chromium page with:
#   - viewport 1280x720
#   - video recording enabled (saved to output/videos/{task_id}/)
#   - automatic rename of video to test name after each test
# Signature: def page(request) -> Page'''

    messages = [
        SystemMessage(
            content="You are an expert QA test engineer. Output ONLY valid Python code, no markdown."
        ),
        UserMessage(content=TEST_GEN_PROMPT.format(
            feature_json=feature_json,
            scenario_json=scenario_json,
            page_fixture=page_fixture,
        )),
    ]

    result = await llm.ainvoke(messages)
    code = result.completion

    # Strip markdown code fences if present
    code = re.sub(r"^```(?:python)?\s*\n", "", code, flags=re.MULTILINE)
    code = re.sub(r"\n```\s*$", "", code, flags=re.MULTILINE)
    code = code.strip()

    # Always ensure required imports are present (LLMs sometimes omit them)
    _playwright_import = "from playwright.sync_api import expect, sync_playwright"
    if "sync_playwright" in code and _playwright_import not in code:
        lines = code.split("\n")
        insert_at = 0
        for i, ln in enumerate(lines):
            if ln.startswith("import ") or ln.startswith("from "):
                insert_at = i + 1
            elif ln.strip() and not ln.startswith("#"):
                break
        lines.insert(insert_at, _playwright_import)
        code = "\n".join(lines)
    # Ensure 'import warnings' is present if warnings.warn is used
    if "warnings.warn" in code and "import warnings" not in code:
        code = "import warnings\n" + code

    # Normalize indentation: LLMs sometimes mix 3-space and 4-space indentation.
    # Convert any 3-space-per-level indentation to standard 4-space.
    fixed_lines = []
    for line in code.split("\n"):
        stripped = line.lstrip(" ")
        leading = len(line) - len(stripped)
        if leading > 0 and leading % 3 == 0 and leading % 4 != 0:
            indent_level = leading // 3
            line = "    " * indent_level + stripped
        fixed_lines.append(line)
    code = "\n".join(fixed_lines)

    # Replace dynamic framework IDs (el-id-*, v-id-*) with stable placeholder-based selectors
    code = _replace_dynamic_xpaths(code, feature_record)

    # Fix module-level page.* calls that escaped function scope (LLM indentation bug)
    code = _fix_module_level_page_calls(code)

    # Remove any `page` fixture the LLM may have generated — it's now in conftest.py
    code = _strip_page_fixture(code)

    # Remove duplicate test function definitions (LLM sometimes emits same function twice)
    code = _deduplicate_test_functions(code)

    # Fix missing/duplicate/misplaced @pytest.mark.parametrize decorators
    code = _fix_missing_parametrize(code)

    # Deduplicate consecutive @pytest.mark.parametrize blocks for the same function
    code = _dedup_parametrize_decorators(code)

    # Validate syntax — if broken, try autopep8 then stub-out broken sections
    try:
        compile(code, "<generated>", "exec")
    except SyntaxError as se:
        logger.warning("Generated test code has syntax error at line %s: %s", se.lineno, se.msg)
        fixed_code = code
        # Try autopep8 first (fixes indentation issues)
        try:
            import autopep8
            fixed_code = autopep8.fix_code(code, options={"aggressive": 1, "max_line_length": 120})
            compile(fixed_code, "<generated>", "exec")
            code = fixed_code
            logger.info("autopep8 fixed syntax error in generated test code")
        except Exception:
            # Last resort: stub out only the function containing the syntax error
            if se.lineno:
                lines = code.split("\n")
                err_line = se.lineno - 1  # 0-indexed
                # Find the enclosing def test_* function
                func_start = err_line
                while func_start > 0 and not re.match(r'^(?:async )?def test_', lines[func_start]):
                    func_start -= 1
                if func_start < err_line and re.match(r'^(?:async )?def test_', lines[func_start]):
                    # Find function signature
                    func_sig = lines[func_start]
                    func_name_match = re.match(r'^(?:async )?def (test_\w+)\s*\(', func_sig)
                    if func_name_match:
                        # Find end of this function
                        func_end = err_line + 1
                        while func_end < len(lines) and (lines[func_end].startswith("    ") or not lines[func_end].strip()):
                            func_end += 1
                        # Replace function body with a skip stub
                        stub = f"{func_sig}\n    import pytest\n    pytest.skip('Test code had syntax error at generation time — check server logs')"
                        lines[func_start:func_end] = stub.split("\n")
                        fixed_code = "\n".join(lines)
                        try:
                            compile(fixed_code, "<generated>", "exec")
                            code = fixed_code
                            logger.info("Stubbed out syntactically-broken function %s", func_name_match.group(1))
                        except Exception:
                            pass  # Keep original even if still broken — will fail at collection

    # Try autopep8 for final formatting cleanup (best-effort)
    try:
        import autopep8
        code = autopep8.fix_code(code, options={"aggressive": 1, "max_line_length": 120})
    except Exception:
        pass  # autopep8 not installed or failed — use raw code

    return code


def _make_conftest(task_id: str, auth_state_path: str | None = None) -> str:
    """Generate conftest.py with video recording and screenshot-on-failure support.

    If auth_state_path is provided, every test context will load the captured
    cookies + localStorage so tests run as an authenticated user.
    """
    # Use absolute path to avoid issues when pytest runs from output/tests/ directory
    abs_auth_state = str(Path(auth_state_path).resolve()) if auth_state_path else None
    auth_state_line = (
        f'AUTH_STATE = r"{abs_auth_state}"'
        if abs_auth_state
        else 'AUTH_STATE = None  # no auth state — tests run as guest'
    )
    auth_context_kwarg = (
        '\n            storage_state=AUTH_STATE,'
        if auth_state_path
        else ''
    )
    return f'''\
"""
Auto-generated conftest.py for testing_web_ui_service.
Provides: function-scoped page fixture with video recording + auth state, screenshot-on-failure.
"""
import re
import pytest
from pathlib import Path
from playwright.sync_api import sync_playwright

TASK_ID = "{task_id}"
{auth_state_line}
VIDEOS_DIR = Path(__file__).parent.parent / "videos" / TASK_ID
VIDEOS_DIR.mkdir(parents=True, exist_ok=True)


def _safe_name(raw: str) -> str:
    return re.sub(r"[^\\w\\-]", "_", raw)[:100]


@pytest.fixture
def page(request):
    """Function-scoped page fixture.

    Each test gets a fresh isolated browser context that:
    - Loads auth state (cookies + localStorage) from the CDP browser session if available
    - Records video to output/videos/{{TASK_ID}}/{{test_name}}.webm
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx_kwargs = dict(
            viewport={{"width": 1280, "height": 720}},
            record_video_dir=str(VIDEOS_DIR),
            record_video_size={{"width": 1280, "height": 720}},{auth_context_kwarg}
        )
        context = browser.new_context(**ctx_kwargs)
        pg = context.new_page()
        yield pg
        video = pg.video          # capture reference BEFORE context closes
        context.close()
        browser.close()
        # Rename UUID video file to test name for easy lookup
        if video:
            try:
                src = Path(video.path())
                target = VIDEOS_DIR / f"{{_safe_name(request.node.name)}}.webm"
                if src.exists() and src != target:
                    src.rename(target)
            except Exception:
                pass


@pytest.fixture(autouse=True)
def screenshot_on_failure(request, page):
    """Capture a PNG screenshot when a test fails."""
    yield
    if request.node.rep_call is not None and request.node.rep_call.failed:
        shots_dir = Path(__file__).parent / "screenshots"
        shots_dir.mkdir(exist_ok=True)
        safe = _safe_name(request.node.name)
        try:
            page.screenshot(path=str(shots_dir / f"{{safe}}.png"), full_page=True)
        except Exception:
            pass


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)
'''


# ---------------------------------------------------------------------------
# Test auto-execution
# ---------------------------------------------------------------------------
async def _run_generated_tests(task_id: str, test_path: Path) -> TestResults:
    """Run the generated pytest file and parse the results."""
    results = TestResults(task_id=task_id, ran_at=time.time())

    try:
        cmd = [
            sys.executable, "-m", "pytest",
            str(test_path),
            "-p", "no:seleniumbase",
            "-p", "no:playwright",
            "--tb=short",
            "--no-header",
            "-v",          # verbose: one line per test
            "--timeout=60",  # per-test timeout (requires pytest-timeout)
            "-n", "4",     # parallel execution with 4 workers (requires pytest-xdist)
            "--reruns", "2",  # retry flaky tests up to 2 times (requires pytest-rerunfailures)
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1200)
        except asyncio.TimeoutError:
            proc.kill()
            results.raw_output = "TIMEOUT: Test run exceeded 20 minutes"
            return results

        output = stdout.decode("utf-8", errors="replace")
        results.raw_output = output
        logger.info("Test auto-run output for task %s (last 500 chars):\n%s", task_id, output[-500:])

        # Parse per-test results from verbose output lines like:
        #   test_foo.py::test_page_0 PASSED [  8%]
        #   test_foo.py::test_nav_0 FAILED [  16%]
        for line in output.splitlines():
            for status in ("PASSED", "FAILED", "ERROR", "SKIPPED"):
                if f" {status}" in line and "::" in line:
                    name = line.split("::")[1].split()[0] if "::" in line else line
                    duration = 0.0
                    dur_match = re.search(r"(\d+\.\d+)s", line)
                    if dur_match:
                        duration = float(dur_match.group(1))
                    error_msg = None
                    if status in ("FAILED", "ERROR"):
                        # Extract brief error from next lines (best-effort)
                        pass
                    results.test_cases.append(TestCaseResult(
                        name=name,
                        status=status.lower(),
                        duration_seconds=duration,
                        error_message=error_msg,
                    ))
                    break

        # Parse summary line — pytest order varies: "2 failed, 32 passed, 1 skipped in 183.68s"
        # Use individual searches so order doesn't matter
        summary_line_match = re.search(r"=+ ([\d\w ,]+) in (\d+\.?\d*)s", output)
        if summary_line_match:
            summary_line = summary_line_match.group(1)
            results.duration_seconds = float(summary_line_match.group(2))
            def _extract(label: str) -> int:
                m = re.search(r"(\d+) " + label, summary_line)
                return int(m.group(1)) if m else 0
            results.passed = _extract("passed")
            results.failed = _extract("failed")
            results.errors = _extract("error")
            results.skipped = _extract("skipped")
            results.total = results.passed + results.failed + results.errors + results.skipped
            results.pass_rate = results.passed / results.total if results.total > 0 else 0.0

        # Link recorded videos to test cases by matching file name to test name
        video_dir = VIDEOS_DIR / task_id
        if video_dir.exists():
            # Build lookup: safe_name -> video_url
            video_map: dict[str, str] = {}
            for vf in video_dir.glob("*.webm"):
                video_map[vf.stem] = f"/tasks/{task_id}/videos/{vf.name}"
            if video_map:
                for tc in results.test_cases:
                    safe = re.sub(r"[^\w\-]", "_", tc.name)[:100]
                    if safe in video_map:
                        tc.video_url = video_map[safe]

    except Exception:
        logger.exception("Failed to run tests for task %s", task_id)
        results.raw_output = "Exception during test execution — see server logs"

    return results


# ---------------------------------------------------------------------------
# Bug extraction
# ---------------------------------------------------------------------------
BUG_EXTRACT_PROMPT = """\
You are a senior QA lead analyzing the output of an automated web exploration agent and test run results.

Your job: identify ALL bugs, issues, and potential improvements from the evidence provided.

MANDATORY: You MUST always output at least these categories of bugs if evidence suggests them:
1. ACCESSIBILITY: If images have no alt text, buttons have no label, etc.
2. VALIDATION: If form inputs accept invalid values without error (email, password strength, etc.)
3. SECURITY: If no HTTPS enforcement, no rate limiting signs, autocomplete="off" missing on passwords
4. UI: If page layout issues on mobile, broken links, missing loading states
5. FUNCTIONAL: If navigation fails, form submission doesn't work as expected

INFERENCE RULES (always infer these if evidence supports):
- Agent injected security payloads without visible error → Validation bug: "No client-side input sanitization feedback"
- Agent noted login with invalid credentials → Check if error message reveals whether email exists (Security bug)
- Agent explored pages successfully → At minimum note: no rate limiting evidence, autocomplete on password fields (Low Security)
- Test failures → extract the failure cause as a Functional or UI bug
- Form submit without navigation → Validation or Functional issue
- `page.go_back()` behavior → Navigation consistency issue (Low UI)

IMPORTANT rules:
- severity: exactly one of "Critical", "High", "Medium", "Low"
- category: exactly one of "Security", "Functional", "Validation", "UI", "Performance", "Business Logic", "Session", "Accessibility", "Configuration"
- steps_to_reproduce: list of strings, minimum 2 steps
- evidence: specific observation, element, or behavior seen
- fix_suggestion: MANDATORY — never leave null, always provide a concrete fix (e.g. "Add Content-Security-Policy header in nginx.conf", "Set autocomplete='current-password' on password input", "Add aria-label attribute to button")
- DO NOT return empty array unless you truly found zero observations — always extract at minimum 2-3 LOW bugs
- Output ONLY valid JSON array, no markdown, no explanation

JSON schema for each bug:
{{
  "severity": "Critical|High|Medium|Low",
  "category": "Security|Functional|Validation|UI|Performance|Business Logic|Session|Accessibility|Configuration",
  "title": "concise title (max 80 chars)",
  "description": "detailed description including context and impact",
  "url": "full URL where bug was found or null",
  "steps_to_reproduce": ["step 1", "step 2", "..."],
  "expected": "what the correct behavior should be",
  "actual": "what actually happened",
  "evidence": "EXACT error message, unexpected value, or precise UI observation",
  "fix_suggestion": "REQUIRED: concrete, actionable fix recommendation — specify exact code change, config header, HTML attribute, or design pattern to resolve this bug"
}}

Agent output to analyze:
{agent_output}
"""


_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


async def _extract_bug_report(task_id: str, target_url: str, agent_output: str, llm_model: str) -> BugReport:
    """Use LLM to parse agent output into a structured BugReport sorted by severity."""
    from browser_use import ChatAzureOpenAI
    from browser_use.llm.messages import SystemMessage, UserMessage

    report = BugReport(
        task_id=task_id,
        target_url=target_url,
        generated_at=time.time(),
    )

    if not agent_output or not agent_output.strip():
        return report

    # Use gpt-5.4-mini for structured JSON output (codex/o-series models waste tokens on thinking)
    bug_model = llm_model
    if "codex" in llm_model.lower() or "o3" in llm_model.lower() or "o1" in llm_model.lower():
        bug_model = "gpt-5.4-mini"
    llm = ChatAzureOpenAI(model=bug_model, max_completion_tokens=8192)
    messages = [
        SystemMessage(content="You are a precise JSON extractor. Output only valid JSON."),
        UserMessage(content=BUG_EXTRACT_PROMPT.format(agent_output=agent_output[:40000])),
    ]

    try:
        result = await llm.ainvoke(messages)
        raw = result.completion.strip()
        raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
        raw = re.sub(r"\n?```\s*$", "", raw)
        # Fix trailing commas
        raw = re.sub(r",(\s*[}\]])", r"\1", raw)

        # Attempt to recover truncated JSON arrays by closing them
        if not raw.endswith("]"):
            # Find last complete object (ends with })
            last_close = raw.rfind("}")
            if last_close > 0:
                raw = raw[: last_close + 1] + "]"

        try:
            bugs_data = json.loads(raw)
        except json.JSONDecodeError:
            # Try extracting any complete JSON objects manually
            import re as _re
            objects = _re.findall(r"\{[^{}]*\}", raw, _re.DOTALL)
            bugs_data = []
            for obj in objects:
                try:
                    bugs_data.append(json.loads(obj))
                except json.JSONDecodeError:
                    pass

        if not isinstance(bugs_data, list):
            logger.warning("Bug extraction returned non-list JSON for task %s", task_id)
            return report

        bugs: list[Bug] = []
        for i, item in enumerate(bugs_data):
            if not isinstance(item, dict):
                continue
            severity = item.get("severity", "Low")
            if severity not in _SEVERITY_ORDER:
                severity = "Low"
            _VALID_CATEGORIES = {
                "Security", "Functional", "Validation", "UI", "Performance",
                "Business Logic", "Session", "Accessibility", "Configuration",
            }
            category = item.get("category", "Functional")
            if category not in _VALID_CATEGORIES:
                category = "Functional"
            bugs.append(Bug(
                id=f"BUG-{i + 1:03d}",
                severity=severity,
                category=category,
                title=item.get("title", "Untitled bug"),
                description=item.get("description", ""),
                url=item.get("url"),
                steps_to_reproduce=item.get("steps_to_reproduce") or [],
                expected=item.get("expected"),
                actual=item.get("actual"),
                evidence=item.get("evidence"),
            ))

        # Sort by severity: Critical → High → Medium → Low
        bugs.sort(key=lambda b: _SEVERITY_ORDER.get(b.severity, 99))

        report.bugs = bugs
        report.total_bugs = len(bugs)
        report.critical_count = sum(1 for b in bugs if b.severity == "Critical")
        report.high_count = sum(1 for b in bugs if b.severity == "High")
        report.medium_count = sum(1 for b in bugs if b.severity == "Medium")
        report.low_count = sum(1 for b in bugs if b.severity == "Low")
        report.summary = (
            f"{report.total_bugs} bugs found: "
            f"{report.critical_count} Critical, {report.high_count} High, "
            f"{report.medium_count} Medium, {report.low_count} Low"
        )
    except Exception:
        logger.exception("Bug extraction LLM call failed for task %s", task_id)

    return report


# ---------------------------------------------------------------------------
# File persistence
# ---------------------------------------------------------------------------
SCENARIO_EXTRACT_PROMPT = """\
You are a senior QA analyst. Your job is to analyze a web application exploration session and extract \
structured business logic scenarios that can be turned into automated functional tests.

You will receive:
1. APP CONTEXT — the target URL and a summary of pages visited
2. AGENT STEPS — what the AI agent observed, thought, and did during exploration
3. DOM ELEMENTS — interactive elements found on each page (buttons, inputs, links, forms)

Your task:
1. First, write a short description of what this web application does (1-2 sentences).
2. List the core user flows you can infer from the page structure and agent observations.
3. Generate as many concrete test scenarios as possible — focus on FUNCTIONAL and BUSINESS LOGIC tests, not security tests.

For each scenario, provide actionable steps with real selectors from the DOM ELEMENTS section when available.

IMPORTANT — Locked vs Available elements:
- In DOM ELEMENTS, each element has an `is_locked` flag.
- `is_locked: true` means the element is covered by an overlay (e.g. subscription paywall) and CANNOT be clicked by the current user.
- `is_locked: false` means the element is freely accessible.
- For locked elements: do NOT generate click/fill steps. Instead generate an `assert` step that verifies the lock overlay exists (i.e. the element is NOT directly interactable).
- For unlocked elements: generate normal interaction steps.
- Scenarios for locked features should be categorized as "Business Logic" and describe the paywall behavior.

Scenario categories:
- Core Feature: main functionality (search, view, apply, submit) — only for unlocked elements
- Navigation: moving between pages and sections
- Form: filling and submitting forms with validation
- Search: search/filter/sort functionality
- Auth: login, logout, session behavior
- Business Logic: paywall gates, subscription limits, role restrictions
- Error State: empty results, 404 pages, validation error display
- Pagination: list pagination if available
- Filter/Sort: filter/sort controls on list pages

CRITICAL CONSTRAINT: Generate scenarios ONLY for pages and features that were ACTUALLY VISITED by the agent and appear in the AGENT STEPS and DOM ELEMENTS data. Do NOT invent scenarios for pages or features that don't appear in the provided data — for example, if no job board page was visited, do NOT generate a "search for a job" scenario. If no premium/paywall page was visited, do NOT generate a paywall scenario.

IMPORTANT — Generate only these scenario types that are SUPPORTED BY ACTUAL OBSERVATIONS:
1. Happy path scenario for each ACTUALLY VISITED page's core feature
2. Form validation scenario (submit with invalid/empty inputs) — ONLY if a form was found in DOM ELEMENTS
3. Session state scenario (if auth/login page was visited: verify protected page redirects unauthenticated users)
4. Navigation scenario — ONLY between pages that were ACTUALLY VISITED
5. Input boundary scenario — ONLY for forms found in the actual DOM ELEMENTS
6. If NO features were found beyond the login page, generate ONLY auth-related scenarios (login, validation, redirect)

Priority:
- High: core functionality without which the app is unusable
- Medium: important but not blocking
- Low: nice-to-have, edge cases

Output ONLY a valid JSON object (no markdown fences) with this exact structure:
{{
  "app_description": "...",
  "core_user_flows": ["flow 1", "flow 2", ...],
  "scenarios": [
    {{
      "id": "SCN-001",
      "name": "...",
      "description": "...",
      "category": "Core Feature",
      "priority": "High",
      "preconditions": ["User is logged in", "..."],
      "steps": [
        {{
          "step": 1,
          "action_type": "navigate",
          "element_description": null,
          "selector": null,
          "value": "https://example.com/dashboard",
          "expected_result": "Dashboard page loads"
        }},
        {{
          "step": 2,
          "action_type": "click",
          "element_description": "Remote Only filter button",
          "selector": "button",
          "value": null,
          "expected_result": "Job list filters to remote jobs only"
        }},
        {{
          "step": 3,
          "action_type": "assert",
          "element_description": "Job list",
          "selector": null,
          "value": null,
          "expected_result": "At least one job card is visible"
        }}
      ],
      "expected_outcome": "..."
    }}
  ]
}}

APP CONTEXT:
Target URL: {target_url}
Pages visited: {pages_summary}

AGENT STEPS:
{agent_steps}

DOM ELEMENTS PER PAGE:
{dom_summary}
"""


async def _extract_scenario_record(
    task_id: str,
    target_url: str,
    report: dict,
    feature_record: "FeatureRecord",
    llm_model: str,
) -> "ScenarioRecord":
    """Use LLM to extract business logic scenarios from the agent report and DOM data."""
    import time as _time
    from browser_use import ChatAzureOpenAI
    from browser_use.llm.messages import SystemMessage, UserMessage

    # For codex-mini (extended thinking model), use gpt-5.4-mini as fallback for better instruction following
    # Codex-mini uses thinking tokens that consume budget before emitting actual JSON scenarios
    scenario_model = llm_model
    if "codex" in llm_model.lower() or "o3" in llm_model.lower() or "o1" in llm_model.lower():
        scenario_model = "gpt-5.4-mini"
    llm = ChatAzureOpenAI(model=scenario_model, max_completion_tokens=8192)

    # Build pages summary
    pages_summary = ", ".join(p.url for p in feature_record.pages) or target_url

    # Build agent steps text (thinking + goal + results)
    step_lines = []
    for step in report.get("steps", []):
        n = step.get("step", "?")
        thinking = step.get("thinking") or ""
        goal = step.get("next_goal") or ""
        results = [
            r.get("extracted_content") or r.get("error", "")
            for r in step.get("results", [])
            if isinstance(r, dict)
        ]
        result_text = " | ".join(r for r in results if r)
        line = f"[Step {n}]"
        if goal:
            line += f" Goal: {goal}"
        if thinking:
            line += f" | Thinking: {thinking[:200]}"
        if result_text:
            line += f" | Result: {result_text[:200]}"
        step_lines.append(line)
    agent_steps = "\n".join(step_lines[:60]) or "No steps recorded"

    # Build DOM summary per page
    dom_parts = []
    for page in feature_record.pages:
        elems = page.interactive_elements
        if not elems:
            continue
        lines = [f"Page: {page.url}"]
        for e in elems[:30]:
            desc = f"  [{e.type}]"
            if e.is_locked:
                desc += " [LOCKED - subscription required, do NOT click]"
            if e.text:
                desc += f" text='{e.text[:60]}'"
            if e.selector:
                desc += f" xpath='{e.selector}'"
            if e.attributes:
                attrs = {k: v for k, v in (e.attributes or {}).items() if v and k in ("href", "type", "name", "placeholder")}
                if attrs:
                    desc += f" attrs={attrs}"
            lines.append(desc)
        dom_parts.append("\n".join(lines))
    dom_summary = "\n\n".join(dom_parts) or "No DOM elements recorded"

    prompt = SCENARIO_EXTRACT_PROMPT.format(
        target_url=target_url,
        pages_summary=pages_summary,
        agent_steps=agent_steps,
        dom_summary=dom_summary[:12000],
    )

    messages = [
        SystemMessage(content=(
            "You are a senior QA analyst. Output ONLY valid JSON — no markdown, no code fences, "
            "no 'thinking' or 'reasoning' fields. Start your response with '{' and end with '}'."
        )),
        UserMessage(content=prompt),
    ]

    result = await llm.ainvoke(messages)
    raw = result.completion.strip()

    # Strip markdown fences if present
    raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```\s*$", "", raw, flags=re.MULTILINE)

    # Some models prepend thinking/reasoning text before the actual JSON — skip to first `{`
    first_brace = raw.find("{")
    if first_brace > 0:
        raw = raw[first_brace:]

    def _clean_json(s: str) -> str:
        """Fix common LLM JSON issues: trailing commas, control chars."""
        # Remove trailing commas before ] or }
        s = re.sub(r",(\s*[}\]])", r"\1", s)
        # Remove control characters that would break JSON
        s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
        return s

    raw = _clean_json(raw)

    data = {}
    try:
        data = json.loads(raw)
        # Some models embed their reasoning in a "thinking" field — remove it (waste of tokens)
        data.pop("thinking", None)
        data.pop("reasoning", None)
        data.pop("chain_of_thought", None)
    except json.JSONDecodeError:
        # Try truncation recovery first: find last complete "}" at the top level
        # (handles JSON cut off mid-string or mid-array)
        raw_truncation_fixed = raw
        # Find the last closing } that could terminate the top-level object
        last_brace = raw.rfind("}")
        if last_brace > 0 and last_brace < len(raw) - 1:
            raw_truncation_fixed = raw[:last_brace + 1]
        try:
            raw_truncation_fixed = _clean_json(raw_truncation_fixed)
            data = json.loads(raw_truncation_fixed)
            logger.info("Truncation recovery succeeded for scenario JSON task %s", task_id)
        except json.JSONDecodeError:
            pass

        if not data:
            # Try json_repair library (handles trailing commas, unquoted keys, truncation, etc.)
            try:
                from json_repair import repair_json
                repaired = repair_json(raw, return_objects=True)
                if isinstance(repaired, dict) and "scenarios" in repaired:
                    data = repaired
                    logger.info("json_repair fixed scenario JSON for task %s: %d scenarios", task_id, len(data.get("scenarios", [])))
                elif isinstance(repaired, list) and repaired and isinstance(repaired[0], dict):
                    # json_repair returned a list — treat as scenarios array directly
                    data = {"scenarios": repaired}
                    logger.info("json_repair returned list, using as scenarios for task %s: %d items", task_id, len(repaired))
                else:
                    raise ValueError(f"repaired JSON missing 'scenarios' key: {type(repaired)}")
            except Exception as repair_err:
                logger.warning("Scenario LLM returned invalid JSON for task %s, repair failed: %s, raw[:200]=%r", task_id, repair_err, raw[:200])
                # Fallback: try a simpler prompt
                try:
                    simple_prompt = (
                        f"List 5 key test scenarios for {target_url} as JSON. "
                        "Pages: " + pages_summary[:500] + "\n"
                        "Output ONLY valid JSON: "
                        '{"scenarios": [{"id": "SCN-001", "name": "...", "description": "...", '
                        '"category": "Core Feature", "priority": "High", "preconditions": [], '
                        '"steps": [{"step": 1, "action_type": "navigate", "element_description": null, '
                        '"selector": null, "value": "' + target_url + '", "expected_result": "Page loads"}], '
                        '"expected_outcome": "..."}]}'
                    )
                    result2 = await llm.ainvoke([
                        SystemMessage(content="Output ONLY valid JSON, no markdown."),
                        UserMessage(content=simple_prompt),
                    ])
                    raw2 = result2.completion.strip()
                    raw2 = re.sub(r"^```(?:json)?\s*\n?", "", raw2)
                    raw2 = re.sub(r"\n?```\s*$", "", raw2)
                    first2 = raw2.find("{")
                    if first2 > 0:
                        raw2 = raw2[first2:]
                    data = json.loads(raw2)
                    logger.info("Scenario fallback prompt succeeded for task %s: %d scenarios", task_id, len(data.get("scenarios", [])))
                except Exception as e:
                    logger.warning("Scenario fallback also failed for task %s: %s", task_id, e)
                    data = {}

    scenarios = []
    for i, s in enumerate(data.get("scenarios", [])):
        steps_raw = []
        for idx_s, a in enumerate(s.get("steps", [])):
            if not isinstance(a, dict):
                continue
            # Coerce step number — LLM sometimes puts action_type in the step field
            raw_step = a.get("step", idx_s + 1)
            if isinstance(raw_step, str):
                try:
                    raw_step = int(raw_step)
                except ValueError:
                    raw_step = idx_s + 1
            action_type = a.get("action_type", "navigate")
            if not isinstance(action_type, str) or not action_type.strip():
                action_type = "navigate"
            try:
                steps_raw.append(UserAction(**{**a, "step": raw_step, "action_type": action_type}))
            except Exception as _ua_err:
                logger.debug("Skipping invalid step %s in scenario %s: %s", idx_s, s.get("id"), _ua_err)
        steps = steps_raw
        scenarios.append(Scenario(
            id=s.get("id", f"SCN-{i+1:03d}"),
            name=s.get("name", f"Scenario {i+1}"),
            description=s.get("description", ""),
            category=s.get("category", "Core Feature"),
            priority=s.get("priority", "Medium"),
            preconditions=s.get("preconditions", []),
            steps=steps,
            expected_outcome=s.get("expected_outcome"),
        ))

    return ScenarioRecord(
        task_id=task_id,
        target_url=target_url,
        generated_at=_time.time(),
        app_description=data.get("app_description"),
        core_user_flows=data.get("core_user_flows", []),
        scenarios=scenarios,
        total_scenarios=len(scenarios),
    )


def _save_scenario_record(record: ScenarioRecord) -> Path:
    SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
    path = SCENARIOS_DIR / f"scenarios_{record.task_id}.json"
    path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
    return path


def _save_feature_record(record: FeatureRecord) -> Path:
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    path = FEATURES_DIR / f"feature_{record.task_id}.json"
    path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
    return path


def _extract_auth_state_sync(task_id: str, cdp_url: str) -> str | None:
    """Connect to existing browser via CDP (sync) and extract storage state including localStorage.
    Runs in a thread to avoid event-loop conflicts with browser_use's Playwright instance.

    example-target.com and many SPAs store auth tokens in localStorage (access_token, refresh_token)
    rather than cookies. Playwright's ctx.storage_state() only captures localStorage for origins
    that were seeded via addInitScript — not from already-navigated pages. We fix this by
    manually reading localStorage from each page and injecting it into the state file.
    """
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(cdp_url)
            contexts = browser.contexts
            if not contexts:
                logger.warning("CDP browser has no contexts — cannot extract auth state")
                return None
            ctx = contexts[0]

            # Collect cookies (same as before)
            cookies = ctx.cookies()

            # Collect localStorage from ALL open pages grouped by origin
            origin_ls: dict[str, list[dict]] = {}
            for page in ctx.pages:
                try:
                    url = page.url
                    if not url.startswith("http"):
                        continue
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    if origin in origin_ls:
                        continue  # already collected for this origin
                    ls_json = page.evaluate(
                        "JSON.stringify(Object.fromEntries(Object.entries(localStorage)))"
                    )
                    ls_dict: dict = json.loads(ls_json) if ls_json else {}
                    if ls_dict:
                        origin_ls[origin] = [{"name": k, "value": str(v)} for k, v in ls_dict.items()]
                        logger.info("Extracted localStorage for %s — %d items", origin, len(ls_dict))
                except Exception as ex:
                    logger.debug("Could not read localStorage from %s: %s", getattr(page, "url", "?"), ex)

            state = {
                "cookies": cookies,
                "origins": [
                    {"origin": origin, "localStorage": items}
                    for origin, items in origin_ls.items()
                ],
            }

            TESTS_DIR.mkdir(parents=True, exist_ok=True)
            state_path = TESTS_DIR / f"auth_state_{task_id}.json"
            state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

            logger.info(
                "Auth state extracted for task %s — %d cookies, %d origins with localStorage → %s",
                task_id, len(cookies), len(origin_ls), state_path,
            )
            return str(state_path)
    except Exception:
        logger.exception("Failed to extract auth state from CDP browser for task %s", task_id)
        return None


async def _extract_auth_state(task_id: str, cdp_url: str) -> str | None:
    """Async wrapper — runs sync extraction in thread to avoid Playwright event-loop conflicts."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _extract_auth_state_sync, task_id, cdp_url)


def _save_test_script(task_id: str, code: str, auth_state_path: str | None = None) -> Path:
    TESTS_DIR.mkdir(parents=True, exist_ok=True)
    path = TESTS_DIR / f"test_{task_id}.py"
    path.write_text(code, encoding="utf-8")
    # Always (re-)write the shared conftest.py in the tests directory
    conftest_path = TESTS_DIR / "conftest.py"
    conftest_path.write_text(_make_conftest(task_id, auth_state_path=auth_state_path), encoding="utf-8")
    VIDEOS_DIR.mkdir(parents=True, exist_ok=True)
    (VIDEOS_DIR / task_id).mkdir(parents=True, exist_ok=True)
    return path


def _save_test_results(results: TestResults) -> Path:
    TEST_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = TEST_RESULTS_DIR / f"results_{results.task_id}.json"
    path.write_text(results.model_dump_json(indent=2), encoding="utf-8")
    return path


def _save_bug_report(report: BugReport) -> Path:
    BUGS_DIR.mkdir(parents=True, exist_ok=True)
    path = BUGS_DIR / f"bugs_{report.task_id}.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------------
async def _run_agent(task_id: str, request: TaskRequest):
    record = _tasks[task_id]
    record.status = "running"
    record.started_at = time.time()

    try:
        from browser_use import Agent, BrowserProfile, ChatAzureOpenAI

        llm = ChatAzureOpenAI(model=request.llm_model, reasoning_effort="medium")

        browser_profile = BrowserProfile(
            headless=request.headless,
            allowed_domains=request.allowed_domains,
            cdp_url=request.cdp_url,
        )

        credentials_section = ""
        if request.credentials:
            credentials_section = (
                "## Credentials\n"
                "If you encounter a login page, use these credentials to authenticate before testing:\n"
                f"- Username / Email: {request.credentials.username}\n"
                f"- Password: {request.credentials.password}\n\n"
            )
        business_context_section = ""
        if request.business_context:
            business_context_section = (
                f"## Business Context\n"
                f"{request.business_context}\n"
                f"Use this context to prioritize which features and flows to test most thoroughly.\n\n"
            )
        user_persona_desc = {
            "new_user": "a first-time visitor who has never used this app before — focus on onboarding, discoverability, and core value delivery",
            "returning_user": "a regular user who knows the app — focus on core workflows, data management, and productivity features",
            "power_user": "an advanced user exploring all features — focus on edge cases, advanced settings, and power features",
            "admin": "an administrator — focus on admin panels, user management, configuration, and privileged operations",
        }.get(request.user_persona, request.user_persona)
        prompt = AGENT_PROMPT_TEMPLATE.format(
            url=request.url,
            target_etld1=_etld1_for_url(request.url) or request.url,
            credentials_section=credentials_section,
            business_context_section=business_context_section,
            user_persona=user_persona_desc,
        )

        async def _on_new_step(_browser_state, _model_output, n_steps: int) -> None:
            # browser_use fires this after each LLM step; expose progress to
            # the /agent/run polling loop so the orchestrator can stream
            # per-step events instead of jumping from 0/N to N-1/N.
            record.steps_done = n_steps

        agent = Agent(
            task=prompt,
            llm=llm,
            browser_profile=browser_profile,
            use_vision=request.use_vision,
            register_new_step_callback=_on_new_step,
        )

        history = await agent.run(max_steps=request.max_steps)

        # Extract auth state immediately after agent finishes (while CDP browser still has session)
        auth_state_path: str | None = None
        if request.cdp_url:
            try:
                loop = asyncio.get_running_loop()
                auth_state_path = await asyncio.wait_for(
                    loop.run_in_executor(None, _extract_auth_state_sync, task_id, request.cdp_url),
                    timeout=30,
                )
            except Exception:
                logger.exception("Auth state extraction failed for task %s — tests will run as guest", task_id)

        # Build structured report from AgentHistoryList
        pages_visited = []
        seen_urls = set()
        urls = history.urls()
        for i, h in enumerate(history.history):
            url = urls[i] if i < len(urls) else None
            title = h.state.title if hasattr(h.state, "title") else None
            if url and url not in seen_urls:
                seen_urls.add(url)
                pages_visited.append({"url": url, "title": title})

        state_transitions = []
        for i in range(1, len(urls)):
            if urls[i] != urls[i - 1]:
                action_desc = None
                h = history.history[i]
                if h.model_output and h.model_output.action:
                    action_desc = str(
                        h.model_output.action[0].model_dump(
                            exclude_none=True, mode="json"
                        )
                    )
                state_transitions.append(
                    {
                        "from_url": urls[i - 1],
                        "to_url": urls[i],
                        "action": action_desc,
                    }
                )

        interacted_elements = history.model_actions()

        errors = [e for e in history.errors() if e is not None]

        steps = []
        for i, h in enumerate(history.history):
            step_info = {
                "step": i + 1,
                "url": urls[i] if i < len(urls) else None,
            }
            if h.model_output:
                step_info["thinking"] = h.model_output.thinking
                step_info["next_goal"] = h.model_output.next_goal
                step_info["memory"] = h.model_output.memory
                step_info["actions"] = [
                    a.model_dump(exclude_none=True, mode="json")
                    for a in h.model_output.action
                ]
            step_info["results"] = [
                r.model_dump(exclude_none=True, mode="json") for r in h.result
            ]
            steps.append(step_info)

        report = {
            "pages_visited": pages_visited,
            "state_transitions": state_transitions,
            "interacted_elements": interacted_elements,
            "errors": errors,
            "steps": steps,
            "extracted_content": history.extracted_content(),
            "final_output": history.final_result(),
            "is_successful": history.is_successful(),
            "is_validated": history.is_validated(),
            "duration_seconds": history.total_duration_seconds(),
        }

        record.result = report
        record.steps_done = len(history.history)

        # --- Post-processing: DOM snapshots + feature extraction + test gen
        try:
            # Collect DOM snapshots from discovered pages
            dom_snapshots: dict[str, DOMSnapshot] = {}
            page_urls = [
                pv["url"]
                for pv in pages_visited
                if pv.get("url") and pv["url"] not in ("about:blank", "about:srcdoc", "")
            ]
            if page_urls:
                try:
                    loop = asyncio.get_running_loop()
                    dom_snapshots = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            _collect_dom_snapshots_sync,
                            page_urls,
                            request.headless,
                            request.cdp_url,
                        ),
                        timeout=120,
                    )
                    logger.info(
                        "DOM snapshots collected: %d pages for task %s",
                        len(dom_snapshots),
                        task_id,
                    )
                except Exception:
                    logger.exception(
                        "DOM snapshot collection failed for task %s (continuing without)",
                        task_id,
                    )

            feature_record = _extract_feature_record(
                task_id, request.url, report, dom_snapshots
            )
            _save_feature_record(feature_record)
            logger.info("Feature record saved for task %s", task_id)

            scenario_record = await _extract_scenario_record(
                task_id, request.url, report, feature_record, request.llm_model
            )
            _save_scenario_record(scenario_record)
            logger.info(
                "Scenario record saved for task %s: %d scenarios",
                task_id,
                scenario_record.total_scenarios,
            )

            test_code = await _generate_test_script(
                feature_record,
                request.llm_model,
                cdp_url=request.cdp_url,
                scenario_record=scenario_record,
            )
            test_path = _save_test_script(task_id, test_code, auth_state_path=auth_state_path)
            logger.info("Test script saved for task %s", task_id)

            # Auto-run generated tests and record results
            try:
                test_results = await _run_generated_tests(task_id, test_path)
                _save_test_results(test_results)
                record.test_summary = {
                    "total": test_results.total,
                    "passed": test_results.passed,
                    "failed": test_results.failed,
                    "errors": test_results.errors,
                    "pass_rate": test_results.pass_rate,
                    "duration_seconds": test_results.duration_seconds,
                }
                logger.info(
                    "Tests executed for task %s: %s (%s)",
                    task_id,
                    test_results.pass_rate,
                    test_results.duration_seconds,
                )
            except Exception:
                logger.exception("Test auto-run failed for task %s", task_id)

        except Exception:
            logger.exception(
                "Post-processing (feature/test gen) failed for task %s",
                task_id,
            )

        # --- Post-processing: bug extraction
        try:
            # `test_results` may not be defined if test gen/run failed — default to None
            test_results = locals().get("test_results", None)

            # Sanitize function for security test payloads that trigger content filters
            _SEC_PAYLOADS = [
                "<script>", "</script>", "onerror=", "onload=", "alert(",
                "' OR '1'='1", "admin'--", "UNION SELECT", "DROP TABLE",
                "javascript:", "<img src=x",
            ]

            def _sanitize(text: str) -> str:
                for payload in _SEC_PAYLOADS:
                    text = text.replace(payload, "[SEC_TEST_PAYLOAD]")
                return text

            # Build agent summary for bug extraction
            # Use final_output (agent's own summary) + step results, sanitized
            agent_output_parts = []
            final_result = report.get("final_output")
            if final_result:
                agent_output_parts.append(f"[Agent Summary]\n{_sanitize(str(final_result))}")

            for step in report.get("steps", []):
                step_num = step.get("step", "?")
                url = step.get("url", "")
                for r in step.get("results", []):
                    if not isinstance(r, dict):
                        continue
                    content = r.get("extracted_content") or ""
                    error = r.get("error") or ""
                    # Skip long stack traces and JSON parse errors (not bug evidence)
                    if error and ("Traceback" in error or "pydantic" in error
                                  or "ValidationError" in error):
                        continue
                    # Sanitize security test payloads that trigger content filters
                    content = _sanitize(content)
                    error = _sanitize(error)
                    if content:
                        agent_output_parts.append(
                            f"[Step {step_num} @ {url}] {content[:500]}"
                        )
                    if error and len(error) < 200:
                        agent_output_parts.append(f"[Step {step_num} error] {error}")

            # Also include test failures and warnings as bug evidence
            if test_results and test_results.total > 0:
                if test_results.failed > 0:
                    agent_output_parts.append(
                        f"\n[Test Failures] {test_results.failed} tests failed out of {test_results.total}:"
                    )
                    for tc in test_results.test_cases:
                        if tc.status in ("failed", "error") and tc.error_message:
                            agent_output_parts.append(
                                f"  - FAIL {tc.name}: {tc.error_message[:200]}"
                            )
                # Extract pytest UserWarnings from raw output (accessibility, security, SEO issues)
                if test_results.raw_output:
                    warning_lines = [
                        line.strip() for line in test_results.raw_output.splitlines()
                        if "UserWarning:" in line or "warnings.warn" in line
                    ]
                    if warning_lines:
                        agent_output_parts.append("\n[Test Warnings from automated checks]:")
                        for w in warning_lines[:20]:
                            agent_output_parts.append(f"  - {w[:200]}")

            # Analyze discovered URLs/pages for security patterns
            if feature_record:
                sec_observations = []
                for page in feature_record.pages:
                    url = page.url or ""
                    # Open redirect: ?redirect=, ?next=, ?url=, ?return= with external URLs
                    import re as _re
                    redir_match = _re.search(r'[?&](?:redirect|next|url|return|goto|returnUrl|returnTo)=https?://', url)
                    if redir_match:
                        sec_observations.append(f"POTENTIAL OPEN REDIRECT: URL parameter with external URL found: {url}")
                    # Admin/privileged paths accessible by agent
                    if _re.search(r'/admin(?:/|$|\?)', url):
                        sec_observations.append(f"ADMIN PAGE ACCESSIBLE: Agent reached admin path: {url}")
                    # User enumeration: /users/N pattern
                    if _re.search(r'/users?/\d+', url):
                        sec_observations.append(f"POTENTIAL USER ENUMERATION: Sequential user ID in URL: {url}")
                    # API keys or tokens in URL
                    if _re.search(r'[?&](?:api_key|token|secret|password|auth)=', url, _re.IGNORECASE):
                        sec_observations.append(f"SENSITIVE DATA IN URL: Auth parameter in URL: {url[:100]}")
                if sec_observations:
                    agent_output_parts.append("\n[Security URL Analysis]:")
                    for obs in sec_observations:
                        agent_output_parts.append(f"  - {obs}")

            agent_output = "\n".join(agent_output_parts)
            bug_report = await _extract_bug_report(task_id, request.url, agent_output, request.llm_model)
            _save_bug_report(bug_report)
            record.bug_counts = {
                "critical": bug_report.critical_count,
                "high": bug_report.high_count,
                "medium": bug_report.medium_count,
                "low": bug_report.low_count,
                "total": bug_report.total_bugs,
            }
            logger.info(
                "Bug report saved for task %s: %s",
                task_id,
                bug_report.summary,
            )
        except Exception:
            logger.exception("Bug extraction failed for task %s", task_id)

        record.status = "completed"

    except asyncio.CancelledError:
        record.status = "cancelled"
    except Exception as e:
        record.status = "failed"
        record.error = str(e)
    finally:
        record.finished_at = time.time()


# ---------------------------------------------------------------------------
# Dashboard helpers
# ---------------------------------------------------------------------------
def _load_disk_tasks() -> list[dict]:
    """Scan output directories to find task IDs that exist on disk but not in memory."""
    disk_tasks: list[dict] = []
    seen = set(_tasks.keys())

    # Collect all known task IDs from any output file
    task_ids: set[str] = set()
    for pattern, prefix in [
        (FEATURES_DIR, "feature_"),
        (TESTS_DIR, "test_"),
        (BUGS_DIR, "bugs_"),
        (SCENARIOS_DIR, "scenarios_"),
    ]:
        for f in pattern.glob("*.json") if pattern == FEATURES_DIR or pattern == BUGS_DIR or pattern == SCENARIOS_DIR else pattern.glob("*.py"):
            stem = f.stem  # e.g. "feature_abc123" or "test_abc123"
            # Strip prefix to get task_id
            for pfx in ("feature_", "test_", "bugs_", "scenarios_", "results_"):
                if stem.startswith(pfx):
                    tid = stem[len(pfx):]
                    if tid not in seen:
                        task_ids.add(tid)
                    break

    for tid in sorted(task_ids):
        entry: dict = {"task_id": tid, "url": "—", "status": "completed", "steps_done": 0, "max_steps": 0, "bug_counts": None, "test_summary": None, "created_at": None}

        # Read feature file for URL and metadata
        feat_path = FEATURES_DIR / f"feature_{tid}.json"
        if feat_path.exists():
            try:
                feat = json.loads(feat_path.read_text(encoding="utf-8"))
                entry["url"] = feat.get("target_url", "—")
                entry["created_at"] = feat.get("generated_at")
            except Exception:
                pass

        # Read test results for pass rate
        res_path = TEST_RESULTS_DIR / f"results_{tid}.json"
        if res_path.exists():
            try:
                res = json.loads(res_path.read_text(encoding="utf-8"))
                total = res.get("total", 0)
                passed = res.get("passed", 0)
                # pass_rate may be stored as float or as "N/M" string
                raw_pr = res.get("pass_rate", 0)
                if isinstance(raw_pr, str):
                    pass_rate = (passed / total) if total > 0 else 0.0
                else:
                    pass_rate = float(raw_pr)
                if total > 0:
                    entry["test_summary"] = {
                        "total": total,
                        "passed": passed,
                        "failed": res.get("failed", 0),
                        "pass_rate": pass_rate,
                    }
            except Exception:
                pass

        # Read bug counts
        bug_path = BUGS_DIR / f"bugs_{tid}.json"
        if bug_path.exists():
            try:
                bugs = json.loads(bug_path.read_text(encoding="utf-8"))
                # top-level fields: total_bugs, critical_count, high_count, medium_count, low_count
                total = bugs.get("total_bugs", 0) or len(bugs.get("bugs", []))
                entry["bug_counts"] = {
                    "total": total,
                    "critical": bugs.get("critical_count", 0),
                    "high": bugs.get("high_count", 0),
                    "medium": bugs.get("medium_count", 0),
                    "low": bugs.get("low_count", 0),
                }
            except Exception:
                pass

        # Check scenarios count
        scen_path = SCENARIOS_DIR / f"scenarios_{tid}.json"
        if scen_path.exists():
            try:
                scen = json.loads(scen_path.read_text(encoding="utf-8"))
                entry["scenarios_count"] = scen.get("total_scenarios", 0)
            except Exception:
                pass

        disk_tasks.append(entry)

    return disk_tasks



# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.post("/agent/run")
async def agent_run(payload: dict):
    """RemoteAgent-compatible endpoint.

    Accepts the orchestrator's ``session_state`` payload, runs a browser
    exploration task, and streams NDJSON progress/artifact events back to the
    calling RemoteAgent — mirroring the protocol used by
    ``testing_api_service``.

    Expected payload shape::

        {
            "session_state": {
                "url": "https://target.com",
                "max_steps": 100,
                "headless": true,
                "llm_model": "gpt-5.4-mini",
                "use_vision": true,
                "business_context": "...",   # optional
                "user_persona": "new_user",  # optional
                "credentials": {"username": "...", "password": "..."}  # optional
            },
            "invocation_id": "...",
            "user_id": "..."
        }

    Event types yielded (NDJSON lines):
        - ``{"type": "log",      "content": "..."}``
        - ``{"type": "progress", "content": "...", "steps_done": n, "max_steps": m}``
        - ``{"type": "artifact", "artifact_type": "web_ui_tests", "name": "...", "content": "..."}``
        - ``{"type": "result",   "task_id": "...", "url": "...", "bug_counts": {...}, ...}``
        - ``{"type": "error",    "content": "..."}``
    """

    async def event_generator():
        # ----------------------------------------------------------------
        # 1. Extract parameters from orchestrator session_state
        # ----------------------------------------------------------------
        session_state = payload.get("session_state", {})
        url = (
            session_state.get("url")
            or session_state.get("target_url")
            or session_state.get("website_url")
        )
        if not url:
            yield json.dumps({"type": "error", "content": "Missing 'url' in session_state"}) + "\n"
            return

        # Build optional Credentials
        creds: Credentials | None = None
        raw_creds = session_state.get("credentials")
        if isinstance(raw_creds, dict) and raw_creds.get("username"):
            creds = Credentials(
                username=raw_creds["username"],
                password=raw_creds.get("password", ""),
            )

        # CDP URL for local Chrome remote debugging (optional)
        cdp_url: str | None = session_state.get("cdp_url")

        request = TaskRequest(
            url=url,
            max_steps=int(session_state.get("max_steps", 100)),
            headless=bool(session_state.get("headless", True)) if not cdp_url else True,
            llm_model=session_state.get("llm_model", os.getenv("OPENAI_MODEL", "gpt-5.4-mini")),
            use_vision=bool(session_state.get("use_vision", True)),
            business_context=session_state.get("business_context"),
            user_persona=session_state.get("user_persona", "new_user"),
            credentials=creds,
            cdp_url=cdp_url,
        )

        # ----------------------------------------------------------------
        # 2. Create task record and start background exploration
        # ----------------------------------------------------------------
        task_id = str(uuid.uuid4())
        record = TaskRecord(
            task_id=task_id,
            url=request.url,
            created_at=time.time(),
            max_steps=request.max_steps,
        )
        _tasks[task_id] = record
        bg = asyncio.create_task(_run_agent(task_id, request))
        _asyncio_tasks[task_id] = bg

        mode_desc = f"via CDP ({cdp_url})" if cdp_url else "headless browser"
        yield json.dumps({
            "type": "log",
            "content": f"[WebUITestingAgent] Task {task_id} started — exploring {url} using {mode_desc}",
        }) + "\n"

        # ----------------------------------------------------------------
        # 3. Poll task state and stream incremental progress
        # ----------------------------------------------------------------
        last_steps = -1
        last_status = "pending"

        while True:
            await asyncio.sleep(3)

            current = _tasks.get(task_id)
            if current is None:
                yield json.dumps({"type": "error", "content": "Task record lost unexpectedly"}) + "\n"
                return

            # Emit step-count change
            if current.steps_done != last_steps:
                last_steps = current.steps_done
                yield json.dumps({
                    "type": "progress",
                    "content": (
                        f"[WebUITestingAgent] Step {current.steps_done}/{current.max_steps} "
                        f"— browser exploring {url}"
                    ),
                    "steps_done": current.steps_done,
                    "max_steps": current.max_steps,
                }) + "\n"

            # Emit status change
            if current.status != last_status:
                last_status = current.status
                yield json.dumps({
                    "type": "log",
                    "content": f"[WebUITestingAgent] Status → {current.status}",
                }) + "\n"

            if current.status in ("completed", "failed", "cancelled"):
                break

        # ----------------------------------------------------------------
        # 4. Handle failure / cancellation
        # ----------------------------------------------------------------
        current = _tasks.get(task_id)
        if not current or current.status != "completed":
            err_msg = (current.error or "Unknown error") if current else "Task missing"
            yield json.dumps({
                "type": "error",
                "content": f"[WebUITestingAgent] Exploration failed: {err_msg}",
            }) + "\n"
            return

        # ----------------------------------------------------------------
        # 5. Read generated artefacts from disk
        # ----------------------------------------------------------------
        test_path = TESTS_DIR / f"test_{task_id}.py"
        bug_path = BUGS_DIR / f"bugs_{task_id}.json"
        feature_path = FEATURES_DIR / f"feature_{task_id}.json"

        test_script = test_path.read_text(encoding="utf-8") if test_path.exists() else ""
        bug_report: dict = {}
        if bug_path.exists():
            try:
                bug_report = json.loads(bug_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to read bug report for task %s", task_id)

        feature_record: dict = {}
        if feature_path.exists():
            try:
                feature_record = json.loads(feature_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to read feature record for task %s", task_id)

        # ----------------------------------------------------------------
        # 6. Emit summary log
        # ----------------------------------------------------------------
        bc = current.bug_counts or {}
        ts = current.test_summary or {}
        yield json.dumps({
            "type": "log",
            "content": (
                f"[WebUITestingAgent] Exploration complete for {url}.\n"
                f"Bugs — Critical: {bc.get('critical', 0)}, High: {bc.get('high', 0)}, "
                f"Medium: {bc.get('medium', 0)}, Low: {bc.get('low', 0)}\n"
                f"Tests — Total: {ts.get('total', 0)}, Passed: {ts.get('passed', 0)}"
            ),
        }) + "\n"

        # ----------------------------------------------------------------
        # 7. Emit artifact event (test script inline — P1 will add R2 upload)
        # ----------------------------------------------------------------
        if test_script:
            yield json.dumps({
                "type": "artifact",
                "artifact_type": "web_ui_tests",
                "name": f"web_ui_test_{task_id}.py",
                "content": test_script,
                "task_id": task_id,
                "url": url,
            }) + "\n"

        # ----------------------------------------------------------------
        # 8. Emit final result event for the orchestrator to consume
        # ----------------------------------------------------------------
        yield json.dumps({
            "type": "result",
            "task_id": task_id,
            "url": url,
            "status": "completed",
            "bug_counts": current.bug_counts,
            "test_summary": current.test_summary,
            "has_tests": bool(test_script),
            "bugs": bug_report.get("bugs", []),
            "feature_summary": {
                "app_type": feature_record.get("app_type"),
                "pages_count": len(feature_record.get("pages", [])),
                "forms_count": len(feature_record.get("forms", [])),
            } if feature_record else None,
        }) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")



@app.get("/tasks/all-with-disk")
async def list_all_tasks_with_disk():
    """Return in-memory tasks merged with disk-only tasks (from previous server runs)."""
    in_memory = [
        {
            "task_id": r.task_id,
            "url": r.url,
            "status": r.status,
            "created_at": r.created_at,
            "steps_done": r.steps_done,
            "max_steps": r.max_steps,
            "bug_counts": r.bug_counts,
            "test_summary": r.test_summary,
            "error": r.error,
            "scenarios_count": None,
        }
        for r in _tasks.values()
    ]
    # Enrich in-memory tasks with scenarios_count from disk
    for t in in_memory:
        sp = SCENARIOS_DIR / f"scenarios_{t['task_id']}.json"
        if sp.exists():
            try:
                d = json.loads(sp.read_text(encoding="utf-8"))
                t["scenarios_count"] = d.get("total_scenarios", 0)
            except Exception:
                pass

    in_memory_ids = {t["task_id"] for t in in_memory}
    disk = [t for t in _load_disk_tasks() if t["task_id"] not in in_memory_ids]
    return in_memory + disk


@app.post("/tasks")
async def create_task(request: TaskRequest):
    task_id = str(uuid.uuid4())
    record = TaskRecord(
        task_id=task_id,
        url=request.url,
        created_at=time.time(),
        max_steps=request.max_steps,
    )
    _tasks[task_id] = record
    bg_task = asyncio.create_task(_run_agent(task_id, request))
    _asyncio_tasks[task_id] = bg_task
    return {"task_id": task_id, "status": "pending"}


@app.get("/tasks")
async def list_tasks():
    return [
        {
            "task_id": r.task_id,
            "url": r.url,
            "status": r.status,
            "created_at": r.created_at,
            "steps_done": r.steps_done,
            "max_steps": r.max_steps,
            "bug_counts": r.bug_counts,
            "test_summary": r.test_summary,
        }
        for r in _tasks.values()
    ]


@app.get("/tasks/{task_id}")
async def get_task(task_id: str):
    record = _tasks.get(task_id)
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "task_id": record.task_id,
        "url": record.url,
        "status": record.status,
        "created_at": record.created_at,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "error": record.error,
        "steps_done": record.steps_done,
        "max_steps": record.max_steps,
        "bug_counts": record.bug_counts,
        "test_summary": record.test_summary,
    }


@app.get("/tasks/{task_id}/report")
async def get_report(task_id: str):
    record = _tasks.get(task_id)
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    if record.status not in ("completed", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Task is still {record.status}. Report not yet available.",
        )
    return _build_report(record)


@app.get("/tasks/{task_id}/features")
async def get_features(task_id: str):
    """Return the feature record JSON for a completed task."""
    record = _tasks.get(task_id)
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    if record.status not in ("completed", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Task is still {record.status}. Features not yet available.",
        )

    # Try to read from disk
    path = FEATURES_DIR / f"feature_{task_id}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))

    # Fallback: extract on the fly from report
    if record.result:
        feature_record = _extract_feature_record(task_id, record.url, record.result)
        return json.loads(feature_record.model_dump_json())

    raise HTTPException(status_code=404, detail="Feature record not available")


@app.get("/tasks/{task_id}/tests", response_class=PlainTextResponse)
async def get_tests(task_id: str):
    """Return the generated pytest script. Falls back to disk for tasks not in memory."""
    record = _tasks.get(task_id)
    if record and record.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail=f"Task is still {record.status}")
    path = TESTS_DIR / f"test_{task_id}.py"
    if path.exists():
        return path.read_text(encoding="utf-8")
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    raise HTTPException(status_code=404, detail="Test script not yet generated")


@app.get("/tasks/{task_id}/scenarios")
async def get_scenarios(task_id: str):
    """Return the scenario record. Falls back to disk for tasks not in memory."""
    record = _tasks.get(task_id)
    if record and record.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail=f"Task is still {record.status}")
    path = SCENARIOS_DIR / f"scenarios_{task_id}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    raise HTTPException(status_code=404, detail="Scenario record not available")


@app.get("/tasks/{task_id}/bugs")
async def get_bugs(task_id: str):
    """Return the bug report. Falls back to disk for tasks not in memory."""
    record = _tasks.get(task_id)
    if record and record.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail=f"Task is still {record.status}")
    path = BUGS_DIR / f"bugs_{task_id}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    raise HTTPException(status_code=404, detail="Bug report not available")


@app.get("/tasks/{task_id}/test-results")
async def get_test_results(task_id: str):
    """Return test execution results. Falls back to disk for tasks not in memory."""
    record = _tasks.get(task_id)
    if record and record.status not in ("completed", "failed"):
        raise HTTPException(status_code=409, detail=f"Task is still {record.status}")
    path = TEST_RESULTS_DIR / f"results_{task_id}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    raise HTTPException(status_code=404, detail="Test results not available")


@app.get("/tasks/{task_id}/videos")
async def list_videos(task_id: str):
    """List all recorded test videos for a task."""
    video_dir = VIDEOS_DIR / task_id
    if not video_dir.exists():
        return {"task_id": task_id, "videos": []}
    videos = [
        {"name": f.stem, "filename": f.name, "url": f"/tasks/{task_id}/videos/{f.name}",
         "size_bytes": f.stat().st_size}
        for f in sorted(video_dir.glob("*.webm"))
    ]
    return {"task_id": task_id, "videos": videos}


@app.get("/tasks/{task_id}/videos/{filename}")
async def get_video(task_id: str, filename: str):
    """Stream a recorded test video file."""
    from fastapi.responses import FileResponse
    # Security: reject path traversal
    if ".." in filename or "/" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = VIDEOS_DIR / task_id / filename
    if not path.exists() or path.suffix != ".webm":
        raise HTTPException(status_code=404, detail="Video not found")
    return FileResponse(str(path), media_type="video/webm", filename=filename)


@app.delete("/tasks/{task_id}")
async def cancel_task(task_id: str):
    record = _tasks.get(task_id)
    if not record:
        raise HTTPException(status_code=404, detail="Task not found")
    if record.status in ("completed", "failed", "cancelled"):
        return {"task_id": task_id, "status": record.status, "detail": "Already finished"}
    bg_task = _asyncio_tasks.get(task_id)
    if bg_task and not bg_task.done():
        bg_task.cancel()
    record.status = "cancelled"
    record.finished_at = time.time()
    return {"task_id": task_id, "status": "cancelled"}
