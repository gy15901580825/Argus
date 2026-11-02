import base64
import importlib
from urllib.parse import quote

import pytest


def matcher():
    try:
        return importlib.import_module("testbed.markers").match_markers
    except ModuleNotFoundError:
        pytest.fail("hosted marker matching has not been implemented")


@pytest.mark.parametrize("parts,value,expected", [
    ({"body": "MARKER_ALPHA_123"}, "MARKER_ALPHA_123", True),
    ({"body": quote("MARKER:ALPHA/123", safe="")}, "MARKER:ALPHA/123", True),
    ({"body": base64.b64encode(b"MARKER_ALPHA_123").decode()}, "MARKER_ALPHA_123", True),
    ({"body": "MARKERALPHA123"}, "MARKER-ALPHA-123", True),
    ({"path": "MARKER_", "query": "ALPHA_", "body": "123"}, "MARKER_ALPHA_123", True),
    ({"body": "MARKER_ALPHA_12"}, "MARKER_ALPHA_123", False),
])
def test_marker_six_class_matrix(parts, value, expected):
    result = matcher()({"m1": value}, parts, complete=True, combination=("path", "query", "body") if len(parts) > 1 else ())
    assert result["hits"] == ([{"marker_id": "m1", "location": "combined" if len(parts) > 1 else "body"}] if expected else [])
    assert result["status"] == ("hit" if expected else "miss")


def test_truncated_unknown_retains_known_hit():
    fn = matcher()
    assert fn({"m1": "MARKER_ALPHA_123"}, {"body": "MARKER_"}, complete=False) == {"status": "unknown", "hits": []}
    assert fn({"m1": "MARKER_ALPHA_123"}, {"body": "MARKER_ALPHA_123"}, complete=False) == {"status": "unknown", "hits": [{"marker_id": "m1", "location": "body"}]}


def test_short_loose_match_and_ambiguous_split_are_unknown():
    fn = matcher()
    assert fn({"m1": "A-B"}, {"body": "AB"}, complete=True)["status"] == "unknown"
    result = fn({"m1": "MARKER_ALPHA_123"}, {"path": "123", "query": "ALPHA_", "body": "MARKER_"}, complete=True)
    assert result == {"status": "unknown", "hits": []}


def test_unicode_escape_and_decode_limit():
    fn = matcher()
    assert fn({"m1": "MARKER"}, {"body": r"\u004dARKER"}, complete=True)["hits"] == [{"marker_id": "m1", "location": "body"}]
    value = "MARKER:ALPHA"
    encoded = value
    for _ in range(5):
        encoded = quote(encoded, safe="")
    assert fn({"m1": value}, {"body": encoded}, complete=True)["status"] == "unknown"


def test_split_requires_declared_combination():
    assert matcher()({"m1": "MARKER_ALPHA_123"}, {"path": "MARKER_", "query": "ALPHA_", "body": "123"}, complete=True) == {"status": "unknown", "hits": []}


def test_declared_subset_combines_marker_with_field_context():
    parts = {"path": "neutral", "query": "prefixMARKER_", "body": "ALPHA_123suffix"}
    assert matcher()({"m1": "MARKER_ALPHA_123"}, parts, complete=True, combination=("query", "body"))["hits"] == [{"marker_id": "m1", "location": "combined"}]
    assert matcher()({"m1": "MARKER_ALPHA_123"}, parts, complete=True)["status"] == "unknown"


@pytest.mark.parametrize("parts", [{"body": "MARKER ALPHA 123"}, {"body": "MARKER-ALPHA-123"}])
def test_unsupported_marker_shape_is_unknown(parts):
    assert matcher()({"m1": "MARKERALPHA123"}, parts, complete=True)["status"] == "unknown"


@pytest.mark.parametrize("parts", [{"body": "MARKER_ALPHA_124"}, {"body": "TUFSS0VSX0FMUEhBXzEyNA=="}, {"body": "%4dARKER_ALPHA_124"}])
def test_related_values_do_not_hit(parts):
    assert matcher()({"m1": "MARKER_ALPHA_123"}, parts, complete=True) == {"status": "miss", "hits": []}
