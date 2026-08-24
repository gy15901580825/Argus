"""Tests for `argus-probe coverage`.

The point of this command is that it is free and offline: a prospect must be
able to ask "what do you actually cover?" without paying for a scan. It must
never quietly omit the cells we do not cover.
"""

import json

from click.testing import CliRunner

from argus_probe import api_client
from argus_probe.cmd_coverage import cmd_coverage

FAKE_MANIFEST = {
    "thin_threshold": 2,
    "totals": {"probes_in_library": 3, "probes_run": 0},
    "standards": {
        "owasp-llm-top10": {
            "universe": "closed",
            "cells": [
                {"id": "LLM01", "name": "Prompt Injection", "probes_in_library": 2, "probes_run": 0,
                 "library_status": "thin", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM02", "name": "Sensitive Information Disclosure", "probes_in_library": 1, "probes_run": 0,
                 "library_status": "thin", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM03", "name": "Supply Chain", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM04", "name": "Data and Model Poisoning", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM05", "name": "Improper Output Handling", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM06", "name": "Excessive Agency", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM07", "name": "System Prompt Leakage", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM08", "name": "Vector and Embedding Weaknesses", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM09", "name": "Misinformation", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
                {"id": "LLM10", "name": "Unbounded Consumption", "probes_in_library": 0, "probes_run": 0,
                 "library_status": "absent", "run_status": "not_run", "verdicts": {}},
            ],
        },
        "mitre-atlas": {"universe": "open", "cells": []},
        "nist-ai-rmf": {"universe": "open", "cells": []},
        "eu-ai-act": {"universe": "open", "cells": []},
    },
}


def test_coverage_prints_every_owasp_cell_including_the_empty_ones(monkeypatch):
    """The offline view must show blank cells too — that is the reason this command exists."""
    monkeypatch.setattr(api_client, "get_coverage", lambda api_url, token: FAKE_MANIFEST)

    runner = CliRunner()
    result = runner.invoke(cmd_coverage, ["--token", "t", "--api-url", "http://x"])

    assert result.exit_code == 0, result.output
    assert "LLM10" in result.output
    assert "absent" in result.output


def test_json_flag_emits_the_manifest_verbatim(monkeypatch):
    monkeypatch.setattr(api_client, "get_coverage", lambda api_url, token: FAKE_MANIFEST)

    runner = CliRunner()
    result = runner.invoke(cmd_coverage, ["--token", "t", "--api-url", "http://x", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["totals"]["probes_in_library"] == 3


def test_standard_flag_filters_to_one_table(monkeypatch):
    monkeypatch.setattr(api_client, "get_coverage", lambda api_url, token: FAKE_MANIFEST)

    runner = CliRunner()
    result = runner.invoke(
        cmd_coverage, ["--token", "t", "--api-url", "http://x", "--standard", "owasp-llm-top10"]
    )

    assert result.exit_code == 0, result.output
    assert "owasp-llm-top10" in result.output
    assert "mitre-atlas" not in result.output


def test_standard_flag_filters_the_json_manifest_too(monkeypatch):
    """--json must honour --standard rather than dumping the full manifest — a caller

    scripting against --json has the same reason to filter as an interactive one.
    """
    monkeypatch.setattr(api_client, "get_coverage", lambda api_url, token: FAKE_MANIFEST)

    runner = CliRunner()
    result = runner.invoke(
        cmd_coverage,
        ["--token", "t", "--api-url", "http://x", "--standard", "owasp-llm-top10", "--json"],
    )

    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert list(parsed["standards"].keys()) == ["owasp-llm-top10"]
    assert "mitre-atlas" not in parsed["standards"]


def test_unknown_standard_is_rejected_not_silently_empty(monkeypatch):
    """An unrecognised --standard must error, never silently yield an empty result."""
    monkeypatch.setattr(api_client, "get_coverage", lambda api_url, token: FAKE_MANIFEST)

    runner = CliRunner()
    result = runner.invoke(
        cmd_coverage, ["--token", "t", "--api-url", "http://x", "--standard", "bogus-standard"]
    )

    assert result.exit_code != 0
    assert "bogus-standard" in result.output
