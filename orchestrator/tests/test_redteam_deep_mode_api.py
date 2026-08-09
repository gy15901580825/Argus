"""API-level deep-mode guards.

Deep mode is expensive enough that the failure modes matter more than the happy
path: running it across the whole library would cost ~$65 and abort partway,
leaving a partial report that reads as a broken product rather than a budget limit.
"""

import pytest
from fastapi import HTTPException

from orchestrator.redteam.api import RunRequest, _resolve_request_probe_ids


TARGET = {"kind": "openai_compat", "endpoint_url": "https://x/v1/chat/completions", "model": "m"}


def test_deep_without_any_selection_is_422():
    req = RunRequest(target=TARGET, mode="deep")
    with pytest.raises(HTTPException) as e:
        _resolve_request_probe_ids(req)
    assert e.value.status_code == 422
    assert "explicit probe selection" in e.value.detail


def test_deep_with_explicit_probe_ids_is_allowed():
    req = RunRequest(target=TARGET, mode="deep", probe_ids=["owasp_01_prompt_injection_basic"])
    assert _resolve_request_probe_ids(req) == ["owasp_01_prompt_injection_basic"]


def test_deep_with_a_suite_is_allowed():
    req = RunRequest(target=TARGET, mode="deep", suite="owasp-llm-top10")
    got = _resolve_request_probe_ids(req)
    assert len(got) > 0


def test_static_without_selection_still_means_whole_library():
    """The CLI's --probes all convention must keep working."""
    req = RunRequest(target=TARGET)
    assert req.mode == "static"
    assert len(_resolve_request_probe_ids(req)) > 100


def test_unknown_mode_is_422_and_lists_valid_modes():
    req = RunRequest(target=TARGET, mode="turbo", probe_ids=["x"])
    with pytest.raises(HTTPException) as e:
        _resolve_request_probe_ids(req)
    assert e.value.status_code == 422
    assert "deep" in e.value.detail and "static" in e.value.detail


def test_deep_and_both_selections_is_still_mutually_exclusive():
    req = RunRequest(target=TARGET, mode="deep", suite="owasp-llm-top10", probe_ids=["x"])
    with pytest.raises(HTTPException) as e:
        _resolve_request_probe_ids(req)
    assert e.value.status_code == 422
    assert "mutually exclusive" in e.value.detail


def test_deep_pairs_defaults_to_three():
    assert RunRequest(target=TARGET).deep_pairs == 3
