from __future__ import annotations

import copy

import pytest

from argus.cli.baseline_key import _SECRET_WORDS, baseline_key
from argus.targets import build_target
from argus_transport import TransportSpec
import argus_transport.spec_v2 as spec_v2
from argus_transport.models import SseSpec
from argus_transport.spec_v2 import (
    TransportSpecV2,
    RequestSpecV2,
    parse_transport_spec,
    iter_requests,
    value_expr_v2,
    with_origin,
)
from test_transport_engine import spec_dict


def v2_dict(url="http://127.0.0.1:1/run"):
    data = spec_dict(url)
    data["version"] = 2
    return data


def poll_dict():
    data = v2_dict()
    data["delivery"] = {
        "kind": "poll",
        "run_id": {"path": "$.id"},
        "request": {"method": "GET", "url": "http://127.0.0.1:1/jobs/{run_id}"},
        "pending": {"path": "$.status", "equals": "pending"},
        "interval_s": 1,
        "max_polls": 5,
        "submit_http_status": [202],
        "submit_outcome": {"kind": "rules", "rules": [], "unmatched": "accepted"},
    }
    return data


def test_v1_file_with_v2_field_is_rejected():
    data = spec_dict()
    data["let"] = {}
    for parser in (TransportSpec.from_dict, parse_transport_spec):
        with pytest.raises(ValueError, match="Invalid transport fields"):
            parser(data)


@pytest.mark.parametrize("version", [3, "2", True, 2.0, None])
def test_version_dispatch_accepts_only_int_1_and_2(version):
    data = spec_dict()
    data["version"] = version
    with pytest.raises(ValueError, match="Unsupported transport version"):
        parse_transport_spec(data)


def test_version_dispatch_returns_distinct_models():
    assert isinstance(parse_transport_spec(spec_dict()), TransportSpec)
    parsed = parse_transport_spec(v2_dict())
    assert isinstance(parsed, TransportSpecV2)
    assert not isinstance(parsed, TransportSpec)


def test_valid_v1_body_relabelled_v2_parses_and_delete_needs_no_body():
    assert TransportSpecV2.from_dict(v2_dict()).version == 2
    data = v2_dict()
    data["request"] = {"method": "DELETE", "url": "http://127.0.0.1:1/run"}
    assert TransportSpecV2.from_dict(data).request.body == {"none": True}
    data["version"] = 1
    with pytest.raises(ValueError, match="Invalid transport fields"):
        TransportSpec.from_dict(data)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1/{x}",
        "http://127.0.0.1:1/{a}{b}/",
        "http://{a}.example.test/run",
        "http://127.0.0.1:1/{a",
        "http://127.0.0.1:1/run?x={a}",
    ],
)
def test_url_placeholder_must_be_declared_and_one_per_segment(url):
    with pytest.raises(ValueError):
        RequestSpecV2.from_dict(
            {"method": "GET", "url": url}, visible=frozenset({"a", "b"})
        )


def test_url_placeholder_allows_segment_affixes():
    req = RequestSpecV2.from_dict(
        {
            "method": "GET",
            "url": "http://127.0.0.1:1/automations/{automation_id}:invoke",
        },
        visible=frozenset({"automation_id"}),
    )
    assert req.placeholders == ("automation_id",)


@pytest.mark.parametrize("name", ["prompt", "history"])
def test_context_placeholder_in_url_is_rejected(name):
    with pytest.raises(ValueError):
        RequestSpecV2.from_dict(
            {"method": "GET", "url": "http://127.0.0.1:1/{" + name + "}"},
            visible=frozenset({name}),
        )


@pytest.mark.parametrize(
    "name",
    [
        "token",
        "api_key",
        "API-Key",
        "password",
        "x_secret",
        "credential",
        "key",
        "auth",
        "authorization",
        "apikey",
    ],
)
def test_query_credential_like_key_is_rejected(name):
    data = v2_dict()
    data["request"]["query"] = {name: {"literal": "x"}}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_query_business_keys_accept_expressions():
    data = v2_dict()
    data["request"]["query"] = {
        "page_size": {"literal": 20},
        "remoteId": {"generate": "uuid4"},
    }
    assert TransportSpecV2.from_dict(data).request.query == data["request"]["query"]


def test_query_with_literal_question_mark_is_rejected():
    data = v2_dict("http://127.0.0.1:1/run?")
    data["request"]["query"] = {}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_var_visibility_attempt_sees_run_not_reverse():
    data = v2_dict()
    data["let"] = {
        "run": {"first": {"literal": "x"}},
        "attempt": {"second": {"var": "first"}},
    }
    data["request"]["body"] = {"text": {"var": "second"}}
    assert TransportSpecV2.from_dict(data).let.attempt["second"] == {"var": "first"}
    for declarations in (
        {"run": {"first": {"var": "second"}}, "attempt": {"second": {"literal": "x"}}},
        {"run": {"first": {"var": "second"}, "second": {"literal": "x"}}},
        {"attempt": {"first": {"var": "second"}, "second": {"literal": "x"}}},
    ):
        data["let"] = declarations
        with pytest.raises(ValueError):
            TransportSpecV2.from_dict(data)


@pytest.mark.parametrize(
    "name",
    [
        "api_token",
        "session_key",
        "cookie_jar",
        "authz",
        "prompt",
        "run_id",
        "Bad",
        "9x",
    ],
)
def test_names_with_secret_words_are_rejected(name):
    data = v2_dict()
    data["let"] = {"run": {name: {"literal": "x"}}}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_run_and_attempt_share_namespace():
    data = v2_dict()
    data["let"] = {
        "run": {"ref": {"literal": "x"}},
        "attempt": {"ref": {"literal": "y"}},
    }
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize(
    "parts",
    [[{"literal": x}, {"literal": "x"}] for x in (True, 1.5, {})]
    + [[{"literal": "x"}], [{"literal": "x"}] * 17, [{"array": []}, {"literal": "x"}]],
)
def test_concat_rejects_non_string_parts(parts):
    with pytest.raises(ValueError):
        value_expr_v2({"concat": parts}, visible=frozenset())


def test_concat_utf8_static_boundary():
    accepted = {"concat": [{"literal": "é" * 4095}, {"literal": "é"}]}
    assert value_expr_v2(accepted, visible=frozenset()) == accepted
    rejected = {"concat": [{"literal": "é" * 4096}, {"literal": "x"}]}
    with pytest.raises(ValueError):
        value_expr_v2(rejected, visible=frozenset())


@pytest.mark.parametrize("name", ["lower", "A-B", "A" * 65])
def test_env_name_must_match_pattern(name):
    with pytest.raises(ValueError):
        value_expr_v2({"env": name}, visible=frozenset())


@pytest.mark.parametrize(
    "expr",
    [
        {"var": "ref", "missing": "omit"},
        {"concat": [{"literal": "x"}, {"var": "ref"}]},
        {"generate": "uuid4"},
        {"generate": "now_iso8601"},
        {"generate": "now_unix_ms"},
        {"base64": {"literal": "é"}},
        {"env": "OBJECT_NAME", "missing": "omit"},
        {"object": {"a": {"var": "ref"}}},
        {"array": [{"var": "ref"}]},
    ],
)
def test_expression_variants_roundtrip(expr):
    assert value_expr_v2(expr, visible=frozenset({"ref"})) == expr


@pytest.mark.parametrize(
    "expr",
    [
        {"var": "absent"},
        {"literal": "x", "env": "A"},
        {"generate": "random"},
        {"literal": "x", "missing": "omit"},
        {"env": "A", "missing": "ignore"},
        {"object": {str(n): {"literal": n} for n in range(129)}},
        {"array": [{"literal": "x"}] * 129},
    ],
)
def test_expression_shapes_and_collection_limits(expr):
    with pytest.raises(ValueError):
        value_expr_v2(expr, visible=frozenset())


def test_expression_depth_limit():
    expr = {"literal": "x"}
    for _ in range(16):
        expr = {"base64": expr}
    assert value_expr_v2(expr, visible=frozenset()) == expr
    with pytest.raises(ValueError):
        value_expr_v2({"base64": expr}, visible=frozenset())


def test_v2_schema_field_names_avoid_baseline_secret_words():
    assert spec_v2.SECRET_WORDS == _SECRET_WORDS
    assert {
        "let",
        "var",
        "concat",
        "generate",
        "base64",
        "env",
        "query",
    } <= spec_v2.V2_FIELD_NAMES
    assert all(
        not any(word in name.lower() for word in _SECRET_WORDS)
        for name in spec_v2.V2_FIELD_NAMES
    )


def test_v2_roundtrip_preserves_v2_fields():
    data = v2_dict("http://127.0.0.1:1/{ref}:invoke")
    data["let"] = {
        "run": {"ref": {"env": "OBJECT_ID"}},
        "attempt": {"suffix": {"concat": [{"var": "ref"}, {"literal": 7}]}},
    }
    data["request"]["query"] = {"ref": {"var": "suffix"}}
    spec = TransportSpecV2.from_dict(data)
    assert TransportSpecV2.from_dict(spec.to_dict()) == spec
    assert spec.to_dict()["let"] == data["let"]
    assert spec.to_dict()["version"] == 2
    assert "placeholders" not in spec.to_dict()["request"]
    assert "let" not in TransportSpecV2.from_dict(v2_dict()).to_dict()


def test_browser_use_rejects_version_2():
    with pytest.raises(ValueError, match="Unsupported transport version"):
        build_target(
            {
                "kind": "browser_use",
                "scenario_kind": "dom_injection",
                "transport": v2_dict(),
            }
        )


def test_poll_run_id_is_delivery_only_and_roundtrips():
    data = poll_dict()
    spec = TransportSpecV2.from_dict(data)
    assert spec.delivery.ids == {"run_id": {"path": "$.id"}}
    assert spec.delivery.request.placeholders == ("run_id",)
    assert TransportSpecV2.from_dict(spec.to_dict()) == spec
    assert spec.to_dict()["delivery"]["run_id"] == {"path": "$.id"}
    assert [name for name, _ in iter_requests(spec)] == ["submit", "poll"]
    data["request"]["url"] = "http://127.0.0.1:1/{run_id}"
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_explicit_delivery_ids_are_not_yet_supported():
    data = poll_dict()
    data["delivery"]["ids"] = data["delivery"].pop("run_id")
    with pytest.raises(ValueError, match="Invalid transport fields"):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize(
    "change", ["foreign_origin", "post", "public_auth_conflict", "missing_run_id"]
)
def test_poll_invariants(change):
    data = poll_dict()
    if change == "foreign_origin":
        data["delivery"]["request"]["url"] = "http://127.0.0.1:2/{run_id}"
    elif change == "post":
        data["delivery"]["request"]["method"] = "POST"
        data["delivery"]["request"]["body"] = {"none": True}
    elif change == "public_auth_conflict":
        data["auth"] = {
            "kind": "bearer",
            "secret": {"source": "env", "name": "TEST_AUTH"},
        }
        data["delivery"]["request"]["headers"] = {"Authorization": "public"}
    else:
        data["delivery"]["request"]["url"] = "http://127.0.0.1:1/jobs"
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_sse_schema_relabelled_v2_roundtrips():
    data = v2_dict()
    data["delivery"] = {
        "kind": "sse",
        "event_names": ["message"],
        "data_format": "json",
        "terminal": {"path": "$.done", "equals": True},
        "accumulation": "final_value",
        "idle_timeout_s": 10,
        "reconnect": False,
    }
    spec = TransportSpecV2.from_dict(data)
    assert isinstance(spec.delivery, SseSpec)
    assert spec.to_dict()["delivery"] == data["delivery"]
    assert TransportSpecV2.from_dict(spec.to_dict()) == spec
    data["delivery"]["reconnect"] = True
    with pytest.raises(ValueError, match="SSE reconnect unsupported"):
        TransportSpecV2.from_dict(data)


def test_with_origin_rewrites_submit_and_poll_and_rejects_paths():
    data = poll_dict()
    original = copy.deepcopy(data)
    rewritten = with_origin(data, "http://127.0.0.1:8080")
    assert rewritten["request"]["url"] == "http://127.0.0.1:8080/run"
    assert (
        rewritten["delivery"]["request"]["url"] == "http://127.0.0.1:8080/jobs/{run_id}"
    )
    assert data == original
    for override in (
        "http://127.0.0.1:8080/run",
        "http://127.0.0.1:8080/?x=1",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:8080/#x",
    ):
        with pytest.raises(
            ValueError, match="version 2 endpoint override takes an origin"
        ):
            with_origin(data, override)


def test_baseline_identity_changes_from_v1_to_v2():
    one = spec_dict()
    two = v2_dict()
    assert baseline_key(one) != baseline_key(two)
    two["let"] = {"run": {"ref": {"literal": "a"}}}
    before = baseline_key(two)
    two["let"]["run"]["ref"]["literal"] = "b"
    assert baseline_key(two) != before


def test_run_id_cannot_be_used_as_a_value_expression():
    data = poll_dict()
    data["delivery"]["request"]["query"] = {"ref": {"var": "run_id"}}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("data", [{"version": 2}, {"version": True}])
def test_direct_v2_parser_rejects_invalid_version_or_missing_fields(data):
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)
