"""Unit tests for `server.extract_code_blocks` — a pure parser.

The LLM produces 5 fenced code blocks. This function must recover them using
any of three strategies in order of preference:
  1. <!-- FILE: <name> --> markers (primary, most reliable)
  2. Comment inside the fence (e.g. ``` python\n# conftest.py\n...```)
  3. Positional fallback — first 5 substantial blocks (>=2 newlines)
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Strategy 1 — FILE markers
# ---------------------------------------------------------------------------

def test_extract_with_file_markers_full_set():
    from server import extract_code_blocks

    text = (
        "Some preamble\n"
        "<!-- FILE: conftest.py -->\n"
        "```python\n"
        "import pytest\n"
        "@pytest.fixture\n"
        "def base_url(): return 'http://x'\n"
        "```\n"
        "<!-- FILE: test_functional.py -->\n"
        "```python\n"
        "def test_ok():\n"
        "    assert 1 == 1\n"
        "```\n"
        "<!-- FILE: test_security.py -->\n"
        "```python\n"
        "def test_auth_bypass():\n"
        "    pass\n"
        "```\n"
        "<!-- FILE: requirements.txt -->\n"
        "```text\n"
        "pytest\n"
        "requests\n"
        "```\n"
        "<!-- FILE: README.md -->\n"
        "```markdown\n"
        "# Generated tests\n"
        "Run `pytest`.\n"
        "```\n"
    )
    files = extract_code_blocks(text)

    assert set(files) == {
        "conftest.py", "test_functional.py", "test_security.py",
        "requirements.txt", "README.md",
    }
    assert files["conftest.py"].startswith("import pytest")
    assert "def test_ok" in files["test_functional.py"]
    assert files["requirements.txt"].strip() == "pytest\nrequests"
    # All values end in newline per contract
    for v in files.values():
        assert v.endswith("\n")


def test_extract_with_file_markers_loose_whitespace():
    """Marker regex tolerates spaces and arbitrary language tags."""
    from server import extract_code_blocks

    text = (
        "<!--   FILE:   conftest.py   -->\n"
        "```py\n"
        "x = 1\n"
        "y = 2\n"
        "```\n"
    )
    files = extract_code_blocks(text)
    assert "conftest.py" in files
    assert files["conftest.py"].strip() == "x = 1\ny = 2"


# ---------------------------------------------------------------------------
# Strategy 2 — comment fallback
# ---------------------------------------------------------------------------

def test_extract_with_comment_headers():
    """When no FILE markers, fall back to the `# filename.py` in-block header."""
    from server import extract_code_blocks

    text = (
        "```python\n"
        "# conftest.py\n"
        "import pytest\n"
        "fixture = True\n"
        "```\n"
        "```python\n"
        "# test_functional.py\n"
        "def test_a():\n"
        "    assert True\n"
        "```\n"
        "```python\n"
        "# test_security.py\n"
        "def test_sec():\n"
        "    pass\n"
        "```\n"
    )
    files = extract_code_blocks(text)
    # Must find all three recognized filenames
    assert "conftest.py" in files
    assert "test_functional.py" in files
    assert "test_security.py" in files
    assert "import pytest" in files["conftest.py"]


# ---------------------------------------------------------------------------
# Strategy 3 — positional fallback
# ---------------------------------------------------------------------------

def test_extract_positional_fallback():
    """Plain blocks → mapped positionally to conftest/functional/security/etc."""
    from server import extract_code_blocks

    text = (
        "```python\n"
        "import pytest\n"
        "# fixture definitions below\n"
        "x = 1\n"
        "y = 2\n"
        "```\n"
        "```python\n"
        "def test_a():\n"
        "    assert 1\n"
        "    return None\n"
        "```\n"
        "```python\n"
        "def test_sec():\n"
        "    assert 1\n"
        "    return None\n"
        "```\n"
        "```\n"
        "pytest\n"
        "requests\n"
        "faker\n"
        "```\n"
        "```\n"
        "# README\n"
        "docs here\n"
        "line three\n"
        "```\n"
    )
    files = extract_code_blocks(text)
    # Positional mapping to the 5 expected filenames
    expected = ["conftest.py", "test_functional.py", "test_security.py",
                "requirements.txt", "README.md"]
    for name in expected:
        assert name in files, f"missing {name}"
    assert "import pytest" in files["conftest.py"]


def test_extract_positional_skips_tiny_blocks():
    """Inline code fences with <2 newlines are filtered out."""
    from server import extract_code_blocks

    text = (
        "Here is an inline tiny block:\n"
        "```\nfoo\n```\n"  # 1 newline inside — should be ignored
        "Now the real ones:\n"
        "```python\n"
        "import pytest\n"
        "x = 1\n"
        "y = 2\n"
        "```\n"
        "```python\n"
        "def test_ok():\n"
        "    assert True\n"
        "    return None\n"
        "```\n"
    )
    files = extract_code_blocks(text)
    # The tiny inline block should NOT have become conftest.py
    assert "import pytest" in files["conftest.py"]


def test_extract_empty_text():
    from server import extract_code_blocks
    assert extract_code_blocks("") == {}


def test_extract_no_fenced_blocks():
    from server import extract_code_blocks
    assert extract_code_blocks("Just prose, no code.") == {}
