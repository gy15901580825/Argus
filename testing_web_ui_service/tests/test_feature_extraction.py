"""
Tests for `_extract_feature_record()` — transforms a raw browser_use agent
report into a structured FeatureRecord with pages, navigation paths and
form workflows.
"""
from __future__ import annotations


def _import_server():
    import server
    return server


def test_extract_empty_report_produces_empty_record():
    """A report with no pages/steps yields an empty FeatureRecord."""
    server = _import_server()
    rec = server._extract_feature_record(
        task_id="t1",
        url="https://example.com",
        report={},
    )
    assert rec.task_id == "t1"
    assert rec.target_url == "https://example.com"
    assert rec.pages == []
    assert rec.navigation_paths == []
    assert rec.form_workflows == []
    assert rec.errors == []
    assert rec.summary is None


def test_extract_skips_about_blank_pages():
    """about:blank / empty-URL pages must never make it into the record."""
    server = _import_server()
    report = {
        "pages_visited": [
            {"url": "about:blank", "title": "Empty Tab"},
            {"url": "", "title": ""},
            {"url": "https://ex.com/home", "title": "Home"},
        ]
    }
    rec = server._extract_feature_record("t", "https://ex.com", report)
    urls = [p.url for p in rec.pages]
    assert urls == ["https://ex.com/home"]
    assert rec.pages[0].title == "Home"


def test_extract_strips_bogus_titles():
    """Titles like 'Initial Actions' are browser_use placeholders, not real."""
    server = _import_server()
    report = {
        "pages_visited": [
            {"url": "https://ex.com/a", "title": "Initial Actions"},
            {"url": "https://ex.com/b", "title": "Real Page"},
        ]
    }
    rec = server._extract_feature_record("t", "https://ex.com", report)
    assert rec.pages[0].title is None
    assert rec.pages[1].title == "Real Page"


def test_extract_dedupes_navigation_paths_and_skips_blank():
    server = _import_server()
    report = {
        "pages_visited": [
            {"url": "https://ex.com/a", "title": "A"},
            {"url": "https://ex.com/b", "title": "B"},
        ],
        "state_transitions": [
            {"from_url": "https://ex.com/a", "to_url": "https://ex.com/b", "action": "click"},
            # Duplicate entry — must be de-duplicated
            {"from_url": "https://ex.com/a", "to_url": "https://ex.com/b", "action": "click"},
            # Path involving about:blank — must be skipped entirely
            {"from_url": "about:blank", "to_url": "https://ex.com/a", "action": "nav"},
        ],
    }
    rec = server._extract_feature_record("t", "https://ex.com", report)
    assert len(rec.navigation_paths) == 1
    nav = rec.navigation_paths[0]
    assert nav.from_url == "https://ex.com/a"
    assert nav.to_url == "https://ex.com/b"
    assert nav.trigger_action == "click"


def test_extract_form_workflow_input_then_click_becomes_submission():
    """Input actions followed by a click are bundled into one FormWorkflow."""
    server = _import_server()
    report = {
        "pages_visited": [{"url": "https://ex.com/login", "title": "Login"}],
        "steps": [
            {
                "step": 1,
                "url": "https://ex.com/login",
                "actions": [
                    {"input": {"index": 0, "text": "alice@example.com"}},
                    {"input": {"index": 1, "text": "secret"}},
                    {"click": {"index": 5}},
                ],
                "results": [
                    {"extracted_content": "Logged in"},
                ],
            }
        ],
        "interacted_elements": [
            {
                "input": {"index": 0, "text": "alice@example.com"},
                "interacted_element": {
                    "x_path": "//input[@name='email']",
                    "attributes": {"name": "email", "type": "email", "placeholder": "Email"},
                    "ax_name": "Email",
                },
            },
            {
                "input": {"index": 1, "text": "secret"},
                "interacted_element": {
                    "x_path": "//input[@name='pw']",
                    "attributes": {"name": "pw", "type": "password", "placeholder": "Password"},
                },
            },
            {
                "click": {"index": 5},
                "interacted_element": {
                    "x_path": "//button[@type='submit']",
                    "attributes": {},
                },
            },
        ],
    }
    rec = server._extract_feature_record("t-form", "https://ex.com", report)
    assert len(rec.form_workflows) == 1
    fw = rec.form_workflows[0]
    assert fw.form_url == "https://ex.com/login"
    assert [f.name for f in fw.fields] == ["email", "pw"]
    assert [f.input_value for f in fw.fields] == ["alice@example.com", "secret"]
    assert fw.submit_button == "5"
    assert fw.result == "Logged in"


def test_extract_summary_uses_final_output_when_available():
    server = _import_server()
    report = {
        "pages_visited": [{"url": "https://ex.com/", "title": "Home"}],
        "final_output": "Completed full exploration",
        "extracted_content": ["chunk-a", "chunk-b"],
    }
    rec = server._extract_feature_record("t", "https://ex.com", report)
    assert rec.summary == "Completed full exploration"


def test_extract_summary_falls_back_to_extracted_content():
    server = _import_server()
    report = {
        "pages_visited": [{"url": "https://ex.com/", "title": "Home"}],
        "final_output": None,
        "extracted_content": ["a", "b", "c"],
    }
    rec = server._extract_feature_record("t", "https://ex.com", report)
    assert rec.summary is not None
    assert "a" in rec.summary and "b" in rec.summary


def test_extract_errors_are_stringified_and_filtered():
    server = _import_server()
    report = {
        "pages_visited": [{"url": "https://ex.com/", "title": "Home"}],
        "errors": ["real error", None, "", ValueError("boom")],
    }
    rec = server._extract_feature_record("t", "https://ex.com", report)
    # None and empty strings are filtered out; ValueError instances are coerced
    assert "real error" in rec.errors
    assert any("boom" in e for e in rec.errors)
    assert "" not in rec.errors


def test_find_snapshot_matches_by_path_when_exact_url_missing():
    server = _import_server()
    snap = server.DOMSnapshot(url="https://ex.com/foo?x=1", title="T")
    snaps = {"https://ex.com/foo?x=1": snap}
    # Exact miss but same path+netloc → path fallback kicks in
    hit = server._find_snapshot("https://ex.com/foo", snaps)
    assert hit is snap


def test_find_snapshot_returns_none_when_no_match():
    server = _import_server()
    snap = server.DOMSnapshot(url="https://ex.com/a", title="A")
    hit = server._find_snapshot("https://other.com/a", {"https://ex.com/a": snap})
    assert hit is None


def test_enrich_form_workflow_prefers_snapshot_xpath_but_drops_dynamic_ids():
    """Dynamic framework IDs (el-id-*) must be dropped in favour of
    placeholder/name-based selectors."""
    server = _import_server()
    fw = server.FormWorkflow(
        form_url="https://ex.com/login",
        fields=[server.FormField(field_type="text", name="email", placeholder="Email")],
    )
    snap = server.DOMSnapshot(
        url="https://ex.com/login",
        title="Login",
        forms=[
            server.FormInfo(
                xpath="//form",
                method="POST",
                fields=[
                    server.DOMElementInfo(
                        tag="input",
                        xpath='//*[@id="el-id-1234-5"]',  # dynamic
                        name="email",
                        type="email",
                        placeholder="Email",
                        label_text="E-mail",
                    )
                ],
            )
        ],
    )
    server._enrich_form_workflows([fw], {"https://ex.com/login": snap})
    # Dynamic xpath should be stripped because placeholder/name is available
    assert fw.fields[0].xpath is None
    assert fw.fields[0].name == "email"
    assert fw.fields[0].label == "E-mail"
