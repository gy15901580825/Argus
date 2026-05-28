"""
Unit tests for `ai_crawler` helpers.

We focus on the pure / easily-isolated parts:
  - BrowserManager._extract_base_domain
  - BrowserManager._is_related_domain
  - BrowserManager._update_depth (with a fake page)
  - BrowserManager._handle_response filtering
  - crawl_for_apis early-exit when GOOGLE_API_KEY is missing

Playwright's real browser is never launched — we construct BrowserManager and
poke methods directly or swap attributes.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _extract_base_domain
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.primary.health/", "primary.health"),
        ("https://api.example.com/foo", "example.com"),
        ("https://signin.foo.com/", "foo.com"),
        ("https://bare.example.org/", "bare.example.org"),
        ("https://my.primary.health", "primary.health"),
    ],
)
def test_extract_base_domain(url, expected):
    from ai_crawler import BrowserManager

    mgr = BrowserManager(target_url=url, allowed_domains=[])
    assert mgr.base_domain == expected


# ---------------------------------------------------------------------------
# _is_related_domain
# ---------------------------------------------------------------------------
def test_is_related_domain_allowed_exact_match():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://www.primary.health/", allowed_domains=["www.primary.health"])
    assert mgr._is_related_domain("www.primary.health") is True


def test_is_related_domain_subdomain_of_base_is_accepted_and_cached():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://www.primary.health/", allowed_domains=["www.primary.health"])
    assert mgr._is_related_domain("my.primary.health") is True
    # After discovery it should live in the set
    assert "my.primary.health" in mgr.discovered_domains


def test_is_related_domain_rejects_unrelated():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://www.primary.health/", allowed_domains=["www.primary.health"])
    assert mgr._is_related_domain("evil.com") is False


# ---------------------------------------------------------------------------
# _update_depth
# ---------------------------------------------------------------------------
def test_update_depth_increments_on_new_url():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    # Simulate start: url_depths already has the start URL at depth 0
    mgr.page = SimpleNamespace(url="https://a.com/")
    mgr._update_depth()
    assert mgr.current_depth == 0

    # Move to a new URL — depth should become 1
    mgr.page = SimpleNamespace(url="https://a.com/next")
    mgr._update_depth()
    assert mgr.current_depth == 1
    assert mgr.url_depths["https://a.com/next"] == 1


def test_update_depth_reuses_known_url_depth():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    mgr.url_depths["https://a.com/deep"] = 4
    mgr.current_depth = 9  # stale

    mgr.page = SimpleNamespace(url="https://a.com/deep")
    mgr._update_depth()
    assert mgr.current_depth == 4


# ---------------------------------------------------------------------------
# _handle_response filtering
# ---------------------------------------------------------------------------
def _make_response(method="GET", url="https://a.com/api/users",
                   resource_type="xhr", content_type="application/json",
                   status=200, post_data=None):
    """Build a fake playwright Response object."""
    request = SimpleNamespace(
        method=method,
        url=url,
        resource_type=resource_type,
        post_data=post_data,
    )
    return SimpleNamespace(
        request=request,
        headers={"content-type": content_type},
        status=status,
    )


def test_handle_response_captures_xhr_json_api():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    resp = _make_response(url="https://a.com/api/users")
    mgr._handle_response(resp)

    assert len(mgr.captured_apis) == 1
    api = mgr.captured_apis[0]
    assert api["method"] == "GET"
    assert api["endpoint"] == "/api/users"
    assert api["full_url"] == "https://a.com/api/users"
    assert api["domain"] == "a.com"
    assert api["status"] == 200


def test_handle_response_filters_static_assets():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])

    mgr._handle_response(_make_response(url="https://a.com/style.css", resource_type="stylesheet"))
    mgr._handle_response(_make_response(url="https://a.com/app.js", resource_type="script"))
    mgr._handle_response(_make_response(url="https://a.com/pic.png", resource_type="image"))

    assert mgr.captured_apis == []


def test_handle_response_skips_unrelated_domain():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    resp = _make_response(url="https://evil.com/api/x")
    mgr._handle_response(resp)
    assert mgr.captured_apis == []


def test_handle_response_filters_infra_paths():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    for url in [
        "https://a.com/cdn-cgi/rum",
        "https://a.com/cdn-cgi/trace",
        "https://a.com/.well-known/security.txt",
        "https://a.com/beacon",
        "https://a.com/collect",
    ]:
        mgr._handle_response(_make_response(url=url))
    assert mgr.captured_apis == []


def test_handle_response_dedupes_repeats():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    for _ in range(3):
        mgr._handle_response(_make_response(url="https://a.com/api/items"))

    assert len(mgr.captured_apis) == 1


def test_handle_response_parses_json_post_body():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    resp = _make_response(
        method="POST",
        url="https://a.com/api/login",
        post_data='{"u": "admin", "p": "1"}',
    )
    mgr._handle_response(resp)

    assert len(mgr.captured_apis) == 1
    assert mgr.captured_apis[0]["payload"] == {"u": "admin", "p": "1"}


def test_handle_response_keeps_raw_post_when_not_json():
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    resp = _make_response(
        method="POST",
        url="https://a.com/api/raw",
        post_data="not-json",
    )
    mgr._handle_response(resp)

    assert mgr.captured_apis[0]["payload"] == "not-json"


def test_handle_response_accepts_api_path_on_document_nav():
    """A document-type response is normally ignored, but if the URL path
    looks like an API it should still be captured."""
    from ai_crawler import BrowserManager

    mgr = BrowserManager("https://a.com/", allowed_domains=["a.com"])
    resp = _make_response(
        url="https://a.com/api/v1/health",
        resource_type="document",
        content_type="text/html",
    )
    mgr._handle_response(resp)
    assert len(mgr.captured_apis) == 1


# ---------------------------------------------------------------------------
# crawl_for_apis — early exit without API key
# ---------------------------------------------------------------------------
def test_crawl_for_apis_returns_empty_without_api_key(monkeypatch):
    import ai_crawler

    monkeypatch.setattr(ai_crawler, "GOOGLE_API_KEY", None)
    result = ai_crawler.crawl_for_apis("https://any.example/", max_steps=1, max_depth=1)
    assert result == []


# ---------------------------------------------------------------------------
# crawl_for_apis happy path — no real Playwright / Gemini
# ---------------------------------------------------------------------------
def test_crawl_for_apis_uses_crawler_agent(monkeypatch):
    import ai_crawler

    monkeypatch.setattr(ai_crawler, "GOOGLE_API_KEY", "fake")

    fake_run = MagicMock(return_value=[{"method": "GET", "endpoint": "/x", "domain": "a.com", "status": 200}])

    class _FakeAgent:
        def __init__(self, browser_manager, max_steps=10, use_smart_model=False):
            self.browser = browser_manager
            self.max_steps = max_steps

        def run(self):
            return fake_run()

    with patch.object(ai_crawler, "CrawlerAgent", _FakeAgent):
        apis = ai_crawler.crawl_for_apis("https://a.com/", max_steps=2, max_depth=1)

    assert apis == [{"method": "GET", "endpoint": "/x", "domain": "a.com", "status": 200}]
    fake_run.assert_called_once()
