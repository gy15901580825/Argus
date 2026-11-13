"""The env-isolation fixture in conftest.py: the live rubric tier keeps the shell's Azure settings."""
from __future__ import annotations

from pathlib import Path

pytest_plugins = ["pytester"]

_CONFTEST = Path(__file__).with_name("conftest.py")


def test_rubric_live_gets_no_azure_safe_defaults(pytester, monkeypatch):
    pytester.makeconftest(_CONFTEST.read_text())
    pytester.makeini('[pytest]\nmarkers =\n    rubric_live: live\n    live_skillscan: live\n')
    pytester.makepyfile(
        """
        import os
        import pytest

        @pytest.mark.rubric_live
        def test_live():
            assert os.environ.get("AZURE_API_KEY") == "real-key"
            assert os.environ.get("AZURE_API_BASE") == "https://real.openai.azure.com"
            assert "AZURE_OPENAI_API_KEY" not in os.environ
            assert "AZURE_OPENAI_ENDPOINT" not in os.environ

        def test_offline():
            assert os.environ["AZURE_OPENAI_API_KEY"] == "test"
            assert os.environ["AZURE_OPENAI_ENDPOINT"] == "https://azure.invalid"
            assert "AZURE_API_KEY" not in os.environ
        """
    )
    # The outer fixture injected the safe defaults; the documented Azure command sets only these two.
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.setenv("AZURE_API_KEY", "real-key")
    monkeypatch.setenv("AZURE_API_BASE", "https://real.openai.azure.com")
    monkeypatch.setenv("PYTHONPATH", str(_CONFTEST.parents[1]))  # the copied conftest imports argus
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=2)
