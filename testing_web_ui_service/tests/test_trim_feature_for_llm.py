"""Tests for `_trim_feature_for_llm()` — caps per-page interactive_elements
so that pathological pages (e.g. iana.org/protocols with 6000+ links) don't
push the test-generation prompt past Azure OpenAI's 272k token limit.
"""
from __future__ import annotations


def _import_server():
    import server
    return server


def _make_record(elements_per_page):
    server = _import_server()
    pages = []
    for i, n in enumerate(elements_per_page):
        pages.append(server.PageInfo(
            url=f"https://ex.com/p{i}",
            title=f"Page {i}",
            interactive_elements=[
                server.InteractiveElement(type="link", text=f"L{j}", selector=f"a:nth-child({j})")
                for j in range(n)
            ],
        ))
    return server.FeatureRecord(
        task_id="t1",
        target_url="https://ex.com/",
        pages=pages,
    )


def test_under_cap_pages_are_unchanged():
    server = _import_server()
    rec = _make_record([5, 10, 50])
    trimmed = server._trim_feature_for_llm(rec, max_elements_per_page=200)
    assert [len(p.interactive_elements) for p in trimmed.pages] == [5, 10, 50]


def test_over_cap_page_is_truncated():
    server = _import_server()
    rec = _make_record([6239, 80])
    trimmed = server._trim_feature_for_llm(rec, max_elements_per_page=200)
    assert [len(p.interactive_elements) for p in trimmed.pages] == [200, 80]


def test_priority_keeps_inputs_and_buttons_over_links():
    server = _import_server()
    page = server.PageInfo(
        url="https://ex.com/form",
        interactive_elements=(
            [server.InteractiveElement(type="link", text=f"L{i}") for i in range(50)]
            + [server.InteractiveElement(type="input", text="email")]
            + [server.InteractiveElement(type="button", text="submit")]
        ),
    )
    rec = server.FeatureRecord(task_id="t", target_url="x", pages=[page])
    trimmed = server._trim_feature_for_llm(rec, max_elements_per_page=2)
    kept_types = sorted(e.type for e in trimmed.pages[0].interactive_elements)
    assert kept_types == ["button", "input"]


def test_original_record_is_not_mutated():
    server = _import_server()
    rec = _make_record([500])
    _ = server._trim_feature_for_llm(rec, max_elements_per_page=10)
    assert len(rec.pages[0].interactive_elements) == 500


def test_etld1_for_url():
    server = _import_server()
    assert server._etld1_for_url("https://example.com/") == "example.com"
    assert server._etld1_for_url("https://app.example.com/x?y=1") == "example.com"
    assert server._etld1_for_url("https://www.example.com") == "example.com"
    assert server._etld1_for_url("https://iana.org/protocols") == "iana.org"
    assert server._etld1_for_url("") is None
    assert server._etld1_for_url(None) is None


def test_filter_drops_offdomain_pages():
    server = _import_server()
    rec = server.FeatureRecord(
        task_id="t1",
        target_url="https://example.com/",
        pages=[
            server.PageInfo(url="https://example.com/", interactive_elements=[]),
            server.PageInfo(url="https://app.example.com/dash", interactive_elements=[]),
            server.PageInfo(url="https://www.iana.org/protocols", interactive_elements=[]),
            server.PageInfo(url="https://account.icann.org/login", interactive_elements=[]),
        ],
    )
    trimmed = server._trim_feature_for_llm(rec)
    assert [p.url for p in trimmed.pages] == [
        "https://example.com/",
        "https://app.example.com/dash",
    ]


def test_filter_drops_offdomain_navs_and_forms():
    server = _import_server()
    rec = server.FeatureRecord(
        task_id="t1",
        target_url="https://example.com/",
        navigation_paths=[
            server.NavigationPath(from_url="https://example.com/", to_url="https://example.com/p"),
            server.NavigationPath(from_url="https://example.com/", to_url="https://iana.org/x"),
            server.NavigationPath(from_url="https://iana.org/x", to_url="https://icann.org/y"),
        ],
        form_workflows=[
            server.FormWorkflow(form_url="https://example.com/login"),
            server.FormWorkflow(form_url="https://account.icann.org/login"),
        ],
    )
    trimmed = server._trim_feature_for_llm(rec)
    assert len(trimmed.navigation_paths) == 2  # both-external dropped
    assert all(
        "iana.org" not in (n.from_url or "") + (n.to_url or "")
        or "example.com" in (n.from_url or "") + (n.to_url or "")
        for n in trimmed.navigation_paths
    )
    assert [f.form_url for f in trimmed.form_workflows] == ["https://example.com/login"]


def test_filter_disabled_when_target_url_blank():
    """Backwards-compat: if target_url is empty, no filtering — only the cap applies."""
    server = _import_server()
    rec = server.FeatureRecord(
        task_id="t1",
        target_url="",
        pages=[
            server.PageInfo(url="https://a.com/", interactive_elements=[]),
            server.PageInfo(url="https://b.org/", interactive_elements=[]),
        ],
    )
    trimmed = server._trim_feature_for_llm(rec)
    assert len(trimmed.pages) == 2
