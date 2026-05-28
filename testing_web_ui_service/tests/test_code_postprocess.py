"""
Tests for the LLM-output post-processors:
  - _replace_dynamic_xpaths: swap Vue/ElementUI dynamic IDs for stable selectors
  - _fix_module_level_page_calls: re-indent stray body lines inside a test fn
  - _strip_page_fixture: remove any user-generated page() fixture
  - _deduplicate_test_functions: drop duplicate def test_* blocks
  - _dedup_parametrize_decorators: drop an earlier duplicate parametrize
  - _fix_missing_parametrize: add default parametrize to boundary tests
"""
from __future__ import annotations


def _srv():
    import server
    return server


# ---------------------------------------------------------------------------
# _replace_dynamic_xpaths
# ---------------------------------------------------------------------------
def test_replace_dynamic_xpaths_uses_placeholder_when_available():
    server = _srv()
    fw = server.FormWorkflow(
        form_url="https://ex.com/login",
        fields=[
            server.FormField(
                field_type="text",
                name="email",
                placeholder="Enter Email",
                xpath='//*[@id="el-id-1234-5"]',
            )
        ],
    )
    fr = server.FeatureRecord(
        task_id="t",
        target_url="https://ex.com/login",
        form_workflows=[fw],
    )
    code = 'page.locator("xpath=//*[@id=\\"el-id-1234-5\\"]").fill("x")'
    out = server._replace_dynamic_xpaths(code, fr)
    assert 'get_by_placeholder("Enter Email")' in out
    assert "el-id-1234-5" not in out


def test_replace_dynamic_xpaths_prefers_name_when_no_placeholder():
    server = _srv()
    fw = server.FormWorkflow(
        form_url="https://ex.com/login",
        fields=[
            server.FormField(
                field_type="text",
                name="user",
                placeholder=None,
                xpath='//*[@id="v-id-42-0"]',
            )
        ],
    )
    fr = server.FeatureRecord(task_id="t", target_url="x", form_workflows=[fw])
    code = 'page.locator("xpath=//*[@id=\\"v-id-42-0\\"]").click()'
    out = server._replace_dynamic_xpaths(code, fr)
    assert "input[name='user']" in out
    assert "v-id-42-0" not in out


def test_replace_dynamic_xpaths_ignores_stable_ids():
    server = _srv()
    fw = server.FormWorkflow(
        form_url="https://ex.com/login",
        fields=[
            server.FormField(
                field_type="text",
                name="email",
                placeholder="Email",
                xpath='//*[@id="email"]',  # not a dynamic framework ID
            )
        ],
    )
    fr = server.FeatureRecord(task_id="t", target_url="x", form_workflows=[fw])
    original = 'page.locator("xpath=//*[@id=\\"email\\"]").fill("a")'
    assert server._replace_dynamic_xpaths(original, fr) == original


# ---------------------------------------------------------------------------
# _fix_module_level_page_calls
# ---------------------------------------------------------------------------
def test_fix_module_level_page_calls_reindents_stray_body():
    server = _srv()
    bad = (
        "def test_foo(page):\n"
        "    page.goto('https://ex.com')\n"
        "page.wait_for_load_state('networkidle')\n"  # LLM emitted at col 0
        "assert page.title() != ''\n"
    )
    fixed = server._fix_module_level_page_calls(bad)
    lines = fixed.split("\n")
    assert any(line.startswith("    page.wait_for_load_state") for line in lines)
    assert any(line.startswith("    assert page.title") for line in lines)


def test_fix_module_level_leaves_real_module_code_alone():
    server = _srv()
    good = (
        "BASE_URL = 'https://ex.com'\n"
        "\n"
        "def test_foo(page):\n"
        "    page.goto(BASE_URL)\n"
        "\n"
        "def test_bar(page):\n"
        "    page.goto(BASE_URL)\n"
    )
    assert server._fix_module_level_page_calls(good) == good


# ---------------------------------------------------------------------------
# _strip_page_fixture
# ---------------------------------------------------------------------------
def test_strip_page_fixture_removes_duplicate_definition():
    server = _srv()
    code = (
        "import pytest\n"
        "\n"
        "@pytest.fixture\n"
        "def page(request):\n"
        "    from playwright.sync_api import sync_playwright\n"
        "    with sync_playwright() as p:\n"
        "        yield p.chromium.launch().new_page()\n"
        "\n"
        "def test_home(page):\n"
        "    page.goto('https://ex.com')\n"
    )
    out = server._strip_page_fixture(code)
    assert "def page(" not in out
    assert "def test_home(page):" in out
    assert "page.goto" in out


def test_strip_page_fixture_keeps_code_without_fixture():
    server = _srv()
    code = "def test_foo(page):\n    page.goto('/')\n"
    assert server._strip_page_fixture(code) == code


# ---------------------------------------------------------------------------
# _deduplicate_test_functions
# ---------------------------------------------------------------------------
def test_deduplicate_keeps_only_first_occurrence():
    server = _srv()
    code = (
        "def test_dup(page):\n"
        "    page.goto('/1')\n"
        "\n"
        "def test_other(page):\n"
        "    page.goto('/other')\n"
        "\n"
        "def test_dup(page):\n"
        "    page.goto('/2')\n"
    )
    out = server._deduplicate_test_functions(code)
    # Only the first test_dup should survive
    assert out.count("def test_dup(") == 1
    assert "page.goto('/1')" in out
    assert "page.goto('/2')" not in out
    assert "def test_other(" in out


# ---------------------------------------------------------------------------
# _dedup_parametrize_decorators
# ---------------------------------------------------------------------------
def test_dedup_parametrize_keeps_last_block():
    server = _srv()
    code = (
        "@pytest.mark.parametrize('x', [1, 2])\n"
        "\n"
        "@pytest.mark.parametrize('x', [1, 2, 3, 4])\n"
        "def test_multi(page, x):\n"
        "    pass\n"
    )
    out = server._dedup_parametrize_decorators(code)
    assert out.count("@pytest.mark.parametrize") == 1
    assert "1, 2, 3, 4" in out


def test_dedup_parametrize_leaves_single_block_alone():
    server = _srv()
    code = (
        "@pytest.mark.parametrize('x', [1, 2])\n"
        "def test_one(page, x):\n"
        "    pass\n"
    )
    out = server._dedup_parametrize_decorators(code)
    assert out.count("@pytest.mark.parametrize") == 1


# ---------------------------------------------------------------------------
# _fix_missing_parametrize
# ---------------------------------------------------------------------------
def test_fix_missing_parametrize_adds_default_to_boundary_tests():
    server = _srv()
    code = (
        "def test_form_boundary_login(page, email, password, expect_error):\n"
        "    page.goto('https://ex.com/login')\n"
    )
    out = server._fix_missing_parametrize(code)
    assert "@pytest.mark.parametrize" in out
    assert '"email,password,expect_error"' in out
    # Ensure test function body is preserved
    assert "def test_form_boundary_login" in out


def test_fix_missing_parametrize_removes_spurious_decorator():
    server = _srv()
    code = (
        "@pytest.mark.parametrize('x', [1, 2])\n"
        "def test_scenario_one(page):\n"
        "    page.goto('/')\n"
    )
    out = server._fix_missing_parametrize(code)
    # Scenario test has no extra params → parametrize must be stripped
    assert "@pytest.mark.parametrize" not in out
    assert "def test_scenario_one" in out


def test_fix_missing_parametrize_keeps_existing_valid_decorator():
    server = _srv()
    code = (
        '@pytest.mark.parametrize("email,password,expect_error", [("", "", True)])\n'
        "def test_form_boundary_login(page, email, password, expect_error):\n"
        "    page.goto('/')\n"
    )
    out = server._fix_missing_parametrize(code)
    # Should be kept (not duplicated or modified)
    assert out.count("@pytest.mark.parametrize") == 1
    assert '("", "", True)' in out
