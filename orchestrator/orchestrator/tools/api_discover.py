#!/usr/bin/env python3
"""
API Discovery Tool (Static + Dynamic)

- Static discovery: HTML/JS parsing, robots/sitemap, common API doc paths, OpenAPI parsing
- Dynamic discovery: Playwright network capture (XHR/Fetch/GraphQL), response samples, HAR export

Usage:
  python api_crawl/api_discover.py --url https://example.com
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright


DEFAULT_COMMON_DOC_PATHS = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
    "/v3/api-docs",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
]

DEFAULT_EXCLUDE_EXTENSIONS = {
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".ico",
    ".webp",
    ".map",
    ".mp4",
    ".mp3",
    ".avi",
    ".pdf",
}

DEFAULT_INCLUDE_PATTERNS = [
    "/api/",
    "/rest/",
    "/graphql",
    "/v1/",
    "/v2/",
    "/v3/",
    ".json",
    "/services/",
]

API_PATTERN_REGEXES = [
    r"fetch\(\s*[\'\"`]([^\'\"`]+)[\'\"`]",
    r"axios\.(get|post|put|delete|patch)\(\s*[\'\"`]([^\'\"`]+)[\'\"`]",
    r"\.open\(\s*[\'\"`][A-Z]+[\'\"`]\s*,\s*[\'\"`]([^\'\"`]+)[\'\"`]",
    r"[\'\"`](/api/[^\'\"`]+)[\'\"`]",
    r"[\'\"`](/v\d+/[^\'\"`]+)[\'\"`]",
    r"[\'\"`](https?://[^\'\"`]+/api/[^\'\"`]+)[\'\"`]",
    r"[\'\"`](/graphql)[\'\"`]",
    r"[\'\"`](/rest/[^\'\"`]+)[\'\"`]",
]

MAX_BODY_CHARS = 2000

SPA_KEYWORDS = [
    "__NEXT_DATA__",
    "data-reactroot",
    "ng-version",
    "webpackJsonp",
    "vite",
    "react",
    "angular",
    "vue",
]

LOGIN_KEYWORDS = ["login", "sign in", "signin", "log in", "登录", "登陆"]

DOC_METHOD_REGEX = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+([^\s'\"`]+)", re.IGNORECASE)


@dataclass
class Endpoint:
    url: str
    method: Optional[str] = None
    path_template: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    body_sample: Optional[Any] = None
    response_sample: Optional[Any] = None
    source: Set[str] = field(default_factory=set)
    evidence: Dict[str, Any] = field(default_factory=dict)
    page: Optional[str] = None
    action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "path_template": self.path_template,
            "params": self.params,
            "body_sample": self.body_sample,
            "response_sample": self.response_sample,
            "source": sorted(self.source),
            "evidence": self.evidence,
            "page": self.page,
            "action": self.action,
        }


@dataclass
class AuthConfig:
    mode: str
    cookie: Optional[str] = None
    jwt: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None
    login_button_text: Optional[str] = None


@dataclass
class SpaDetection:
    detected: bool
    score: float
    threshold: float
    forced: bool
    used_playwright_html: bool
    features: Dict[str, Any]


@dataclass
class DiscoveryResult:
    target_url: str
    timestamp: str
    timeout_seconds: int
    concurrency: int
    auth: Dict[str, Any]
    spa: Dict[str, Any]
    static: Dict[str, Any]
    dynamic: Dict[str, Any]
    endpoints: List[Dict[str, Any]]
    warnings: List[str]
    errors: List[str]


def normalize_path(path: str) -> str:
    parts = []
    for seg in path.split("/"):
        if not seg:
            parts.append(seg)
            continue
        if seg.isdigit():
            parts.append("{id}")
            continue
        if re.match(r"^[0-9a-fA-F-]{8,}$", seg) and "-" in seg:
            parts.append("{id}")
            continue
        if re.match(r"^[0-9a-zA-Z]{12,}$", seg):
            parts.append("{id}")
            continue
        parts.append(seg)
    return "/".join(parts)


def is_static_resource(url: str) -> bool:
    lower = url.lower()
    return any(lower.endswith(ext) for ext in DEFAULT_EXCLUDE_EXTENSIONS)


def is_api_candidate(url: str) -> bool:
    lower = url.lower()
    return any(pattern in lower for pattern in DEFAULT_INCLUDE_PATTERNS)


def get_domain(url: str) -> str:
    return urlparse(url).netloc


def same_origin(base: str, url: str) -> bool:
    return urlparse(base).netloc == urlparse(url).netloc


def extract_links(html: str, base_url: str) -> Set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if not href:
            continue
        if href.startswith("#") or href.startswith("mailto:"):
            continue
        links.add(urljoin(base_url, href))
    return links


def extract_script_urls(html: str, base_url: str) -> Set[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for script in soup.find_all("script", src=True):
        src = script.get("src")
        if src:
            urls.add(urljoin(base_url, src))
    return urls


def extract_inline_scripts(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    scripts = []
    for script in soup.find_all("script"):
        if script.string:
            scripts.append(script.string)
    return scripts


def extract_api_from_text(content: str, base_url: str, domain: str) -> Set[str]:
    endpoints = set()
    for pattern in API_PATTERN_REGEXES:
        for match in re.findall(pattern, content, re.IGNORECASE):
            if isinstance(match, tuple):
                match = match[-1]
            endpoint = match.strip()
            if not endpoint:
                continue
            if endpoint.startswith("http"):
                if domain in endpoint:
                    endpoints.add(endpoint)
            elif endpoint.startswith("/"):
                endpoints.add(urljoin(base_url, endpoint))
    return endpoints


def extract_api_from_docs(content: str, base_url: str, domain: str) -> Set[str]:
    endpoints = set()
    for method, path in DOC_METHOD_REGEX.findall(content):
        if not path:
            continue
        if path.startswith("http"):
            if domain in path:
                endpoints.add(path)
        elif path.startswith("/"):
            endpoints.add(urljoin(base_url, path))
    endpoints.update(extract_api_from_text(content, base_url, domain))
    return endpoints


def detect_spa_features(html: str) -> Tuple[float, Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    text_length = len(text)
    scripts = soup.find_all("script")
    script_count = len(scripts)
    html_length = len(html)
    root_div = soup.find(id=re.compile(r"^(app|root)$", re.IGNORECASE)) is not None
    keyword_hits = sum(1 for k in SPA_KEYWORDS if k.lower() in html.lower())
    script_ratio = script_count / max(1, len(soup.find_all()))

    score = 0.0
    if root_div:
        score += 0.2
    if script_count >= 5:
        score += 0.2
    if text_length < 400:
        score += 0.2
    if script_ratio > 0.25:
        score += 0.2
    if keyword_hits >= 2:
        score += 0.2

    features = {
        "text_length": text_length,
        "html_length": html_length,
        "script_count": script_count,
        "script_ratio": script_ratio,
        "root_div": root_div,
        "keyword_hits": keyword_hits,
    }
    return score, features


def parse_openapi(spec_text: str, base_url: str) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    try:
        spec = json.loads(spec_text)
    except Exception:
        return endpoints

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
            url = urljoin(base_url, path)
            endpoint = Endpoint(
                url=url,
                method=method.upper(),
                path_template=normalize_path(urlparse(url).path),
                params=details.get("parameters"),
                body_sample=details.get("requestBody"),
            )
            endpoint.source.add("openapi")
            endpoint.evidence["openapi_source"] = base_url
            endpoints.append(endpoint)
    return endpoints


def build_endpoint_from_url(url: str, source: str, evidence: Optional[Dict[str, Any]] = None) -> Endpoint:
    parsed = urlparse(url)
    endpoint = Endpoint(
        url=url,
        method=None,
        path_template=normalize_path(parsed.path),
        params=parse_qs(parsed.query) if parsed.query else None,
    )
    endpoint.source.add(source)
    if evidence:
        endpoint.evidence.update(evidence)
    return endpoint


def merge_endpoints(existing: Dict[Tuple[str, Optional[str]], Endpoint], new_ep: Endpoint) -> None:
    key = (new_ep.url, new_ep.method)
    if key not in existing:
        existing[key] = new_ep
        return
    current = existing[key]
    current.source.update(new_ep.source)
    current.evidence.update(new_ep.evidence)
    if not current.params and new_ep.params:
        current.params = new_ep.params
    if not current.body_sample and new_ep.body_sample:
        current.body_sample = new_ep.body_sample
    if not current.response_sample and new_ep.response_sample:
        current.response_sample = new_ep.response_sample
    if not current.page and new_ep.page:
        current.page = new_ep.page
    if not current.action and new_ep.action:
        current.action = new_ep.action


async def fetch_text(client: httpx.AsyncClient, url: str) -> Optional[str]:
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        return None
    return None


def get_base_html(url: str, timeout_seconds: int) -> Optional[str]:
    try:
        resp = requests.get(url, timeout=min(30, timeout_seconds))
        if resp.status_code == 200:
            return resp.text
    except Exception:
        return None
    return None


def get_html_with_playwright(url: str, headless: bool, timeout_seconds: int) -> Optional[str]:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context()
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout_seconds * 1000)
            html = page.content()
            browser.close()
            return html
    except Exception:
        return None


async def static_discovery(
    base_url: str,
    concurrency: int,
    timeout_seconds: int,
    max_pages: int,
    spa_detection: SpaDetection,
) -> Dict[str, Any]:
    domain = get_domain(base_url)
    endpoints: Dict[Tuple[str, Optional[str]], Endpoint] = {}
    script_urls: Set[str] = set()
    crawled_pages: Set[str] = set()
    candidate_pages: List[str] = []
    docs_pages: List[str] = []
    warnings: List[str] = []

    base_html = get_base_html(base_url, timeout_seconds)
    if spa_detection.used_playwright_html:
        base_html = get_html_with_playwright(base_url, headless=True, timeout_seconds=min(60, timeout_seconds))
        if not base_html:
            warnings.append("Failed to render SPA HTML with Playwright; falling back to raw HTML.")
            base_html = get_base_html(base_url, timeout_seconds)

    if not base_html:
        return {
            "endpoints": [],
            "docs": [],
            "openapi": [],
            "crawled_pages": [],
            "script_urls": [],
            "warnings": warnings + ["Failed to fetch base HTML."],
        }

    candidate_pages.append(base_url)
    script_urls.update(extract_script_urls(base_html, base_url))

    inline_scripts = extract_inline_scripts(base_html)
    for script_text in inline_scripts:
        for endpoint_url in extract_api_from_text(script_text, base_url, domain):
            merge_endpoints(endpoints, build_endpoint_from_url(endpoint_url, "static", {"source": "inline_script"}))

    # robots.txt
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        robots_resp = requests.get(robots_url, timeout=10)
        if robots_resp.status_code == 200:
            for line in robots_resp.text.splitlines():
                if line.lower().startswith(("allow:", "disallow:")):
                    path = line.split(":", 1)[-1].strip()
                    if "/api" in path.lower():
                        candidate = urljoin(base_url, path)
                        merge_endpoints(endpoints, build_endpoint_from_url(candidate, "robots"))
    except Exception:
        pass

    # sitemap.xml
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    try:
        sitemap_resp = requests.get(sitemap_url, timeout=10)
        if sitemap_resp.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", sitemap_resp.text)
            for link in urls[: max_pages * 2]:
                if same_origin(base_url, link):
                    candidate_pages.append(link)
    except Exception:
        pass

    # Common doc paths
    docs_found: List[str] = []
    openapi_endpoints: List[Endpoint] = []
    for path in DEFAULT_COMMON_DOC_PATHS:
        doc_url = urljoin(base_url, path)
        try:
            resp = requests.get(doc_url, timeout=10)
            if resp.status_code == 200:
                docs_found.append(doc_url)
                if "/docs" in urlparse(doc_url).path:
                    docs_pages.append(doc_url)
                if "openapi" in path or path.endswith(".json") or "swagger" in path:
                    openapi_endpoints.extend(parse_openapi(resp.text, doc_url))
        except Exception:
            continue

    # Crawl pages (depth-1 style, with concurrency)
    unique_pages: List[str] = []
    for page_url in candidate_pages:
        if len(unique_pages) >= max_pages:
            break
        if not same_origin(base_url, page_url):
            continue
        if page_url in crawled_pages:
            continue
        unique_pages.append(page_url)
        crawled_pages.add(page_url)

    # Expand docs pages (bounded)
    for doc_url in docs_pages:
        if len(unique_pages) >= max_pages:
            break
        if doc_url in crawled_pages:
            continue
        unique_pages.append(doc_url)
        crawled_pages.add(doc_url)

    async with httpx.AsyncClient(timeout=min(30, timeout_seconds)) as client:
        sem = asyncio.Semaphore(concurrency)

        async def process_page(url: str) -> None:
            async with sem:
                html = await fetch_text(client, url)
                if spa_detection.detected and spa_detection.used_playwright_html:
                    rendered = get_html_with_playwright(url, headless=True, timeout_seconds=min(60, timeout_seconds))
                    if rendered:
                        html = rendered
                if not html:
                    return
                script_urls.update(extract_script_urls(html, url))
                for script_text in extract_inline_scripts(html):
                    for endpoint_url in extract_api_from_text(script_text, base_url, domain):
                        merge_endpoints(
                            endpoints,
                            build_endpoint_from_url(endpoint_url, "static", {"source": "inline_script", "page": url}),
                        )

                # Extract API patterns from docs pages
                if "/docs" in urlparse(url).path:
                    for endpoint_url in extract_api_from_docs(html, base_url, domain):
                        merge_endpoints(
                            endpoints,
                            build_endpoint_from_url(endpoint_url, "docs", {"source": "docs_page", "page": url}),
                        )

                # Expand docs links for SPA or content-rich docs
                if "/docs" in urlparse(url).path:
                    for link in extract_links(html, url):
                        if not same_origin(base_url, link):
                            continue
                        if "/docs" not in urlparse(link).path:
                            continue
                        if link in crawled_pages:
                            continue
                        if len(unique_pages) >= max_pages:
                            break
                        unique_pages.append(link)
                        crawled_pages.add(link)

        await asyncio.gather(*[process_page(p) for p in list(unique_pages)])

        # Download JS
        js_urls = [u for u in script_urls if not is_static_resource(u)]

        async def process_js(url: str) -> None:
            async with sem:
                text = await fetch_text(client, url)
                if not text:
                    return
                for endpoint_url in extract_api_from_text(text, base_url, domain):
                    merge_endpoints(
                        endpoints,
                        build_endpoint_from_url(endpoint_url, "static", {"source": "js_bundle", "script": url}),
                    )

        await asyncio.gather(*[process_js(u) for u in js_urls])

    for ep in openapi_endpoints:
        merge_endpoints(endpoints, ep)

    static_candidates = [ep.to_dict() for ep in endpoints.values()]

    return {
        "endpoints": static_candidates,
        "docs": docs_found,
        "openapi": [ep.to_dict() for ep in openapi_endpoints],
        "crawled_pages": unique_pages,
        "script_urls": sorted(script_urls),
        "warnings": warnings,
    }


def login_if_needed(page, auth: AuthConfig) -> Optional[str]:
    if auth.mode != "password" or not auth.username or not auth.password:
        return None

    login_url = auth.login_url
    if login_url:
        page.goto(login_url, wait_until="networkidle")

    # try to find login links if no login_url
    if not login_url:
        links = page.locator("a")
        for i in range(min(10, links.count())):
            text = (links.nth(i).inner_text() or "").lower()
            if any(k in text for k in LOGIN_KEYWORDS):
                links.nth(i).click()
                page.wait_for_timeout(1500)
                break

    # fill username/email and password
    username_selectors = [
        "input[type='email']",
        "input[name*='email' i]",
        "input[name*='user' i]",
        "input[placeholder*='email' i]",
        "input[placeholder*='user' i]",
        "input[type='text']",
    ]
    password_selectors = [
        "input[type='password']",
        "input[name*='pass' i]",
        "input[placeholder*='pass' i]",
    ]

    for sel in username_selectors:
        locator = page.locator(sel)
        if locator.count() > 0:
            try:
                locator.first.fill(auth.username)
                break
            except Exception:
                continue

    for sel in password_selectors:
        locator = page.locator(sel)
        if locator.count() > 0:
            try:
                locator.first.fill(auth.password)
                break
            except Exception:
                continue

    # submit
    button_text = auth.login_button_text or ""
    submit_selectors = [
        "button[type='submit']",
        "input[type='submit']",
    ]
    for sel in submit_selectors:
        btn = page.locator(sel)
        if btn.count() > 0:
            try:
                btn.first.click()
                page.wait_for_timeout(2000)
                return "login_submit"
            except Exception:
                continue

    if button_text:
        btn = page.get_by_role("button", name=re.compile(re.escape(button_text), re.IGNORECASE))
        if btn.count() > 0:
            btn.first.click()
            page.wait_for_timeout(2000)
            return "login_submit"

    # fallback: click by login keyword
    for keyword in LOGIN_KEYWORDS:
        btn = page.get_by_role("button", name=re.compile(keyword, re.IGNORECASE))
        if btn.count() > 0:
            btn.first.click()
            page.wait_for_timeout(2000)
            return "login_submit"

    return None


def dynamic_discovery(
    base_url: str,
    auth: AuthConfig,
    timeout_seconds: int = 60,
    headless: bool = True,
    max_response_chars: Optional[int] = None,
    har_path: Optional[str] = None,
    progress_callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Dynamic API discovery using Playwright.
    
    Args:
        base_url: Target URL to analyze
        auth: Authentication configuration
        timeout_seconds: Page load timeout (default 60)
        headless: Run browser in headless mode (default True)
        max_response_chars: Max chars for response samples (None = no limit)
        har_path: Path to save HAR file (None = don't save)
        progress_callback: Optional callback function for progress updates.
                          Called with (stage: str, message: str, data: dict)
    """
    endpoints: Dict[Tuple[str, Optional[str]], Endpoint] = {}
    errors: List[str] = []
    actions: List[str] = []
    page_action = {"current": "page_load"}
    
    def emit_progress(stage: str, message: str, data: dict = None):
        """Helper to emit progress updates"""
        if progress_callback:
            try:
                progress_callback(stage, message, data or {})
            except Exception:
                pass  # Don't let callback errors break discovery

    def set_action(action: str) -> None:
        page_action["current"] = action
        actions.append(action)

    emit_progress("init", f"Starting dynamic discovery for {base_url}", {"url": base_url})

    with sync_playwright() as p:
        emit_progress("browser", "Launching browser...")
        browser = p.chromium.launch(headless=headless)
        # Only record HAR if har_path is provided
        context_options = {}
        if har_path:
            context_options["record_har_path"] = har_path
        context = browser.new_context(**context_options)

        if auth.mode == "cookie" and auth.cookie:
            context.set_extra_http_headers({"Cookie": auth.cookie})
            emit_progress("auth", "Applied cookie authentication")
        if auth.mode == "jwt" and auth.jwt:
            context.set_extra_http_headers({"Authorization": f"Bearer {auth.jwt}"})
            emit_progress("auth", "Applied JWT authentication")

        page = context.new_page()
        emit_progress("browser", "Browser ready, opening page...")

        def handle_request(request):
            if request.resource_type not in ("xhr", "fetch"):
                return
            url = request.url
            if is_static_resource(url):
                return
            body_sample = None
            try:
                body_sample = request.post_data_json
            except Exception:
                try:
                    raw = request.post_data_buffer
                    if raw:
                        body_sample = raw[:MAX_BODY_CHARS].decode("utf-8", errors="replace")
                except Exception:
                    body_sample = None
            endpoint = Endpoint(
                url=url,
                method=request.method,
                path_template=normalize_path(urlparse(url).path),
                params=parse_qs(urlparse(url).query) if urlparse(url).query else None,
                body_sample=body_sample,
                page=page.url,
                action=page_action["current"],
            )
            endpoint.source.add("dynamic")
            merge_endpoints(endpoints, endpoint)
            # Emit progress for each captured request
            emit_progress("request", f"Captured: {request.method} {url[:80]}", {
                "method": request.method,
                "url": url,
                "total_captured": len(endpoints)
            })

        def handle_response(response):
            try:
                request = response.request
                if request.resource_type not in ("xhr", "fetch"):
                    return
                url = request.url
                if is_static_resource(url):
                    return
                text = response.text()
                # Only truncate if max_response_chars is explicitly set
                if max_response_chars and text and len(text) > max_response_chars:
                    text = text[:max_response_chars]
                endpoint = Endpoint(
                    url=url,
                    method=request.method,
                    path_template=normalize_path(urlparse(url).path),
                    response_sample=text,
                    page=page.url,
                    action=page_action["current"],
                )
                endpoint.source.add("dynamic")
                merge_endpoints(endpoints, endpoint)
            except Exception:
                return

        page.on("request", handle_request)
        page.on("response", handle_response)

        try:
            set_action("page_load")
            emit_progress("navigation", f"Loading page: {base_url}")
            page.goto(base_url, wait_until="networkidle", timeout=timeout_seconds * 1000)
            emit_progress("navigation", "Page loaded successfully")

            login_action = login_if_needed(page, auth)
            if login_action:
                set_action(login_action)
                emit_progress("auth", "Login action performed")

            set_action("scroll")
            emit_progress("interaction", "Scrolling page...")
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(2000)

            # Try clicking a few links/buttons
            set_action("click")
            buttons = page.locator("button")
            button_count = buttons.count()
            emit_progress("interaction", f"Found {button_count} buttons, clicking up to 3...")
            for i in range(min(3, button_count)):
                try:
                    buttons.nth(i).click()
                    emit_progress("interaction", f"Clicked button {i+1}")
                    page.wait_for_timeout(1000)
                except Exception:
                    continue

            links = page.locator("a")
            link_count = links.count()
            emit_progress("interaction", f"Found {link_count} links, clicking up to 3...")
            for i in range(min(3, link_count)):
                try:
                    links.nth(i).click()
                    emit_progress("interaction", f"Clicked link {i+1}")
                    page.wait_for_timeout(1000)
                    page.go_back()
                except Exception:
                    continue

        except Exception as exc:
            errors.append(str(exc))
            emit_progress("error", f"Error during discovery: {exc}")

        emit_progress("cleanup", "Closing browser...")
        context.close()
        browser.close()

    total_endpoints = len(endpoints)
    emit_progress("complete", f"Discovery complete. Found {total_endpoints} API endpoints.", {
        "total_endpoints": total_endpoints,
        "actions": actions
    })

    return {
        "requests": [ep.to_dict() for ep in endpoints.values()],
        "actions": actions,
        "har_path": har_path,  # Will be None if not recording
        "errors": errors,
    }


def build_auth_config(args: argparse.Namespace) -> AuthConfig:
    return AuthConfig(
        mode=args.auth_mode,
        cookie=args.cookie,
        jwt=args.jwt,
        username=args.username,
        password=args.password,
        login_url=args.login_url,
        login_button_text=args.login_button_text,
    )


def detect_spa(base_url: str, threshold: float, forced: bool, use_playwright_html: bool) -> SpaDetection:
    html = get_base_html(base_url, 30)
    if not html:
        return SpaDetection(
            detected=False,
            score=0.0,
            threshold=threshold,
            forced=forced,
            used_playwright_html=False,
            features={},
        )

    score, features = detect_spa_features(html)
    detected = forced or score >= threshold
    used_playwright = use_playwright_html and detected

    return SpaDetection(
        detected=detected,
        score=score,
        threshold=threshold,
        forced=forced,
        used_playwright_html=used_playwright,
        features=features,
    )


def build_output(
    base_url: str,
    timeout_seconds: int,
    concurrency: int,
    auth: AuthConfig,
    spa: SpaDetection,
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
    warnings: List[str],
    errors: List[str],
) -> DiscoveryResult:
    endpoints: Dict[Tuple[str, Optional[str]], Endpoint] = {}

    for item in static_result.get("endpoints", []):
        ep = Endpoint(
            url=item.get("url"),
            method=item.get("method"),
            path_template=item.get("path_template"),
            params=item.get("params"),
            body_sample=item.get("body_sample"),
            response_sample=item.get("response_sample"),
            page=item.get("page"),
            action=item.get("action"),
        )
        ep.source.update(item.get("source", []))
        ep.evidence.update(item.get("evidence", {}))
        merge_endpoints(endpoints, ep)

    for item in dynamic_result.get("requests", []):
        ep = Endpoint(
            url=item.get("url"),
            method=item.get("method"),
            path_template=item.get("path_template"),
            params=item.get("params"),
            body_sample=item.get("body_sample"),
            response_sample=item.get("response_sample"),
            page=item.get("page"),
            action=item.get("action"),
        )
        ep.source.update(item.get("source", []))
        ep.evidence.update(item.get("evidence", {}))
        merge_endpoints(endpoints, ep)

    return DiscoveryResult(
        target_url=base_url,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        timeout_seconds=timeout_seconds,
        concurrency=concurrency,
        auth={
            "mode": auth.mode,
            "login_url": auth.login_url,
            "login_button_text": auth.login_button_text,
        },
        spa={
            "detected": spa.detected,
            "score": spa.score,
            "threshold": spa.threshold,
            "forced": spa.forced,
            "used_playwright_html": spa.used_playwright_html,
            "features": spa.features,
        },
        static=static_result,
        dynamic=dynamic_result,
        endpoints=[ep.to_dict() for ep in endpoints.values()],
        warnings=warnings,
        errors=errors,
    )


def filter_dynamic_requests_by_domain(discovery: Dict[str, Any], domain: str) -> List[Dict[str, Any]]:
    """
    Return only dynamic requests whose netloc ends with the given domain.

    Example:
        filter_dynamic_requests_by_domain(result_dict, "clerk.com")
    """
    if not discovery:
        return []
    dynamic = discovery.get("dynamic", {})
    requests = dynamic.get("requests", [])
    matched = []
    for req in requests:
        url = req.get("url")
        if not url:
            continue
        netloc = urlparse(url).netloc
        if netloc.endswith(domain):
            matched.append(req)
    return matched


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover APIs from a URL (static + dynamic).")
    parser.add_argument("--url", required=True, help="Target URL to analyze")
    parser.add_argument("--output", default="api_discovery_output.json", help="JSON output file")
    parser.add_argument("--har", default="api_discovery_output.har", help="HAR output file")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency for static fetching")
    parser.add_argument("--timeout", type=int, default=600, help="Overall timeout (seconds)")
    parser.add_argument("--max-pages", type=int, default=30, help="Max pages to crawl (static)")
    parser.add_argument("--auth-mode", choices=["none", "cookie", "jwt", "password"], default="none")
    parser.add_argument("--cookie", help="Cookie value for auth-mode=cookie")
    parser.add_argument("--jwt", help="JWT value for auth-mode=jwt")
    parser.add_argument("--username", help="Username/email for auth-mode=password")
    parser.add_argument("--password", help="Password for auth-mode=password")
    parser.add_argument("--login-url", help="Login URL fallback")
    parser.add_argument("--login-button-text", help="Login button text fallback")
    parser.add_argument("--headless", action="store_true", default=True, help="Use headless browser (default: true)")
    parser.add_argument("--no-headless", action="store_false", dest="headless", help="Disable headless mode")
    parser.add_argument("--spa-detect", action="store_true", default=True, help="Enable SPA detection (default: true)")
    parser.add_argument("--no-spa-detect", action="store_false", dest="spa_detect", help="Disable SPA detection")
    parser.add_argument("--spa-threshold", type=float, default=0.6, help="SPA detection threshold")
    parser.add_argument("--force-spa", action="store_true", help="Force SPA mode")
    parser.add_argument("--use-playwright-html", action="store_true", default=True, help="Render HTML via Playwright when SPA (default: true)")
    parser.add_argument("--no-playwright-html", action="store_false", dest="use_playwright_html", help="Disable Playwright HTML rendering")
    parser.add_argument("--max-response-chars", type=int, default=2000, help="Max response sample length")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    base_url = args.url.strip()
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"

    auth = build_auth_config(args)
    if args.spa_detect:
        spa = detect_spa(base_url, args.spa_threshold, args.force_spa, args.use_playwright_html)
    else:
        spa = SpaDetection(
            detected=False,
            score=0.0,
            threshold=args.spa_threshold,
            forced=args.force_spa,
            used_playwright_html=False,
            features={},
        )

    warnings: List[str] = []
    errors: List[str] = []

    try:
        static_result = asyncio.run(
            static_discovery(
                base_url,
                concurrency=args.concurrency,
                timeout_seconds=args.timeout,
                max_pages=args.max_pages,
                spa_detection=spa,
            )
        )
    except Exception as exc:
        static_result = {"endpoints": [], "docs": [], "openapi": [], "warnings": []}
        errors.append(f"Static discovery failed: {exc}")

    try:
        dynamic_result = dynamic_discovery(
            base_url,
            auth,
            timeout_seconds=args.timeout,
            headless=args.headless,
            har_path=args.har,
            max_response_chars=args.max_response_chars,
        )
    except Exception as exc:
        dynamic_result = {"requests": [], "actions": [], "har_path": args.har, "errors": [str(exc)]}
        errors.append(f"Dynamic discovery failed: {exc}")

    result = build_output(
        base_url,
        timeout_seconds=args.timeout,
        concurrency=args.concurrency,
        auth=auth,
        spa=spa,
        static_result=static_result,
        dynamic_result=dynamic_result,
        warnings=warnings + static_result.get("warnings", []) + dynamic_result.get("errors", []),
        errors=errors,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result.__dict__, f, indent=2, ensure_ascii=False)

    print(f"✅ Discovery complete. JSON saved to: {args.output}")
    print(f"✅ HAR saved to: {args.har}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
