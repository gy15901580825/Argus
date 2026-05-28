"""Focused per-phase prompts for the browser-use web UI exploration pipeline."""
from __future__ import annotations

from web_ui_phases.state import PhaseState

_PERSONA_MAP = {
    "new_user": "a first-time visitor — focus on onboarding clarity, value proposition, registration",
    "returning_user": "a regular user — focus on core workflows, saved state, notifications",
    "power_user": "an advanced daily user — focus on filters, bulk actions, edge cases, settings",
    "admin": "an administrator — focus on admin panels, user management, privileged operations",
    "experienced_user": "an experienced user — focus on usability gaps, feature completeness",
}

_SHARED_RULES = """\
GLOBAL RULES (apply every step):
- Target domain: {domain}. Stay within {domain} or its subdomains.
- Never click Logout / Sign-out — preserve the authenticated session.
- Cookie / GDPR banners: click Accept immediately — count as 0 steps.
- Subdomains and URL hash changes are WITHIN the domain boundary.
- If clicking navigates OUTSIDE {domain}: record the redirect, then navigate BACK.
- Output format: finish THIS PHASE ONLY with a single JSON block (```json) matching the schema below.
  Do NOT write a cross-phase summary report — Python assembles the final report after all phases complete.
"""

_AUTH_SCHEMA = """\
```json
{{
  "auth_status": "success" | "failed" | "already_logged_in" | "not_required",
  "notes": "<short string, e.g. which flow was used or why it failed>"
}}
```"""

_DISCOVERY_SCHEMA = """\
```json
{{
  "app_type": "<one sentence app description>",
  "features": [
    {{"name": "<feature name>", "url": "<relative or absolute url>", "priority": 1-5}}
  ],
  "forms": [{{"purpose": "<...>", "url": "<...>"}}],
  "total_pages": <int>
}}
```"""

_FEATURES_SCHEMA = """\
```json
{{
  "features_tested": [
    {{
      "name": "<feature name>",
      "status": "pass" | "partial" | "fail",
      "notes": "<what happened>",
      "potential_bugs": [{{"severity": "low|medium|high|critical", "description": "<...>"}}]
    }}
  ]
}}
```"""

_BUG_HUNT_SCHEMA = """\
```json
{{
  "bugs": [
    {{
      "severity": "low" | "medium" | "high" | "critical",
      "category": "FUNC" | "UX" | "PERF" | "SEC" | "A11Y",
      "description": "<what is wrong>",
      "steps": "<how to reproduce>",
      "evidence": "<url, console msg, screenshot step, etc.>"
    }}
  ]
}}
```"""


def _persona_desc(persona: str) -> str:
    return _PERSONA_MAP.get(persona, persona)


def build_auth_prompt(state: PhaseState, max_steps: int) -> str:
    if not state.credentials:
        raise ValueError("Auth phase requires credentials")
    username = state.credentials.get("username", "")
    password = state.credentials.get("password", "")
    rules = _SHARED_RULES.format(domain=state.domain)
    return f"""\
You are a QA tester preparing an authenticated exploration of {state.url}.

PHASE 0 — AUTHENTICATION (budget: {max_steps} steps)
Goal: establish a logged-in session, nothing more.

Steps:
  1. Navigate to {state.url} and CHECK if you are ALREADY logged in.
     Signs of logged-in state: avatar, profile menu, dashboard, absence of a Sign-in button.
     If already logged in: record status and STOP this phase (do not explore).
  2. If not logged in: locate the login entry point and authenticate with
     username='{username}' password='{password}'.

{rules}

Output schema for THIS PHASE ONLY:
{_AUTH_SCHEMA}
"""


def build_discovery_prompt(state: PhaseState, max_steps: int) -> str:
    rules = _SHARED_RULES.format(domain=state.domain)
    prior = state.to_prompt_context()
    return f"""\
You are a QA tester exploring {state.url} as {_persona_desc(state.user_persona)}.

PRIOR PHASES:
{prior}

PHASE 1 — SITE DISCOVERY (budget: {max_steps} steps)
Goal: reconnaissance ONLY. Enumerate the site surface. Do NOT click into individual features yet.

Record:
  - App type / core value proposition (1 sentence)
  - Top navigation items and their URLs
  - Top 5 features worth testing, ranked by user impact
  - Forms visible from the landing area
  - Rough page count reachable from the nav

Move fast. Budget is tight.

{rules}

Output schema for THIS PHASE ONLY:
{_DISCOVERY_SCHEMA}
"""


def build_features_prompt(state: PhaseState, max_steps: int) -> str:
    rules = _SHARED_RULES.format(domain=state.domain)
    features_json = "[]"
    if state.discovery and state.discovery.parsed.get("features"):
        features_json = "\n".join(
            f"  - {f.get('name', '?')} @ {f.get('url', '?')}"
            for f in state.discovery.parsed["features"]
        )
    return f"""\
You are a QA tester as {_persona_desc(state.user_persona)} testing {state.url}.

FEATURES DISCOVERED IN PHASE 1:
{features_json}

PHASE 2 — FEATURE EXERCISE (budget: {max_steps} steps)
Goal: for each discovered feature (in priority order), perform the primary happy-path action.
Record whether it worked, and flag anything that felt broken, slow, or confusing.

Rules:
  - Allocate roughly equal steps per feature.
  - Subscription paywall? Record it as GATED and move on (1 step max).
  - Modal dialog? Test the core action (1 step), then close.
  - Spinner that persists >5 seconds? Record as FUNC-TIMEOUT and move on.
  - If you run out of budget, stop mid-list — do not rush.

{rules}

Output schema for THIS PHASE ONLY:
{_FEATURES_SCHEMA}
"""


def build_bug_hunt_prompt(state: PhaseState, max_steps: int) -> str:
    rules = _SHARED_RULES.format(domain=state.domain)
    prior_features = "\n".join(
        f"  - {f.get('name', '?')}: {f.get('status', '?')} — {f.get('notes', '')}"
        for f in state.feature_results
    ) or "  (none)"
    return f"""\
You are an adversarial QA tester on {state.url}. Your KPI is finding real, reproducible bugs.
Assume this application has at least 5 bugs. Silence (zero bugs) means you did not look hard enough.

PHASE 2 RESULTS:
{prior_features}

PHASE 3 — DEEP BUG HUNTING (budget: {max_steps} steps)
Goal: given the features you already exercised, attack them harder.

Techniques to try (prefer those most relevant to the priority features):
  - Empty / whitespace / very long input into forms
  - Special characters and SQL-like payloads in search boxes
  - Navigate with browser back/forward after state changes
  - Reload mid-flow; check for lost state
  - Network tab: look for 4xx/5xx responses
  - Console: look for JS errors
  - Keyboard-only navigation (Tab, Enter) on 1 critical flow
  - Responsiveness or layout glitches on key pages

Every bug you report MUST include severity, category, reproduction steps, and evidence.

{rules}

Output schema for THIS PHASE ONLY:
{_BUG_HUNT_SCHEMA}
"""
