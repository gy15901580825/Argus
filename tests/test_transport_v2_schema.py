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


def lifecycle_dict():
    data = v2_dict()
    data["let"] = {"run": {"prefix": {"literal": "objects/"}}}
    data["lifecycle"] = {"run": [{
        "id": "create", "request": {
            "method": "POST", "url": "http://127.0.0.1:1/objects",
            "body": {"text": {"var": "prefix"}},
        }, "expect": {"http_status": [201], "when": {"path": "$.ok", "equals": True}},
        "capture": {"ref": {"path": "$.id", "expect_prefix": {"var": "prefix"}}},
        "undo": {"request": {"method": "DELETE", "url": "http://127.0.0.1:1/objects/{ref}"},
                 "expect": {"http_status": [200, 204, 404]}},
    }], "attempt": [{
        "id": "fetch", "if_present": "prompt", "request": {
            "method": "GET", "url": "http://127.0.0.1:1/objects/{ref}",
        }, "expect": {"http_status": [200]},
        "capture": {"item": {"path": "$.id", "last_segment": True}},
    }]}
    for scope in ("run", "attempt"):
        for step in data["lifecycle"][scope]:
            requests = [step["request"]]
            if "undo" in step:
                requests.append(step["undo"]["request"])
            for request in requests:
                request.setdefault("headers", {})
                request.setdefault("body", {"none": True})
    return data


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_undo_method_must_be_delete_or_get(method):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0]["undo"]["request"].update(method=method, body={"none": True})
    with pytest.raises(ValueError, match="Undo method must be DELETE or GET"):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("owner", ["step", "undo"])
def test_step_and_undo_must_share_submit_origin(owner):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    step = data["lifecycle"]["run"][0]
    request = step["request"] if owner == "step" else step["undo"]["request"]
    request["url"] = "http://127.0.0.1:2/objects"
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("change", ["step", "capture_let", "capture_id", "let_id", "context_id"])
def test_step_ids_and_captures_share_the_namespace(change):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    if change == "step":
        data["lifecycle"]["attempt"][0]["id"] = "create"
    elif change == "capture_let":
        data["let"]["attempt"] = {"ref": {"literal": "x"}}
    elif change == "capture_id":
        data["lifecycle"]["attempt"][0]["capture"] = {"create": {"path": "$.id"}}
    elif change == "let_id":
        data["let"]["run"]["fetch"] = {"literal": "x"}
    else:
        data["lifecycle"]["run"][0]["id"] = "run_id"
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_undo_sees_own_capture_and_outer_scope_only():
    data = lifecycle_dict()
    data["lifecycle"]["run"][0]["undo"]["request"]["query"] = {"outer": {"var": "prefix"}}
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0]["undo"]["request"]["query"] = {"later": {"var": "item"}}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_let_attempt_and_submit_see_run_captures():
    data = lifecycle_dict()
    data["let"]["attempt"] = {"local": {"var": "ref"}}
    data["request"]["body"] = {"json": {"ref": {"var": "ref"}, "item": {"var": "item"}}}
    assert TransportSpecV2.from_dict(data).let.attempt["local"] == {"var": "ref"}
    data["lifecycle"]["run"][0]["request"]["body"] = {"text": {"var": "local"}}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("name", ["create", "missing", "item"])
def test_if_present_requires_visible_binding_or_context(name):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0]["if_present"] = name
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("value", [True, False, "60", 0, -1, 301, float("inf")])
def test_cleanup_s_defaults_to_60_and_caps_at_300(value):
    data = v2_dict()
    assert TransportSpecV2.from_dict(data).timeout.cleanup_s == 60
    data["timeout"]["cleanup_s"] = 300
    assert TransportSpecV2.from_dict(data).timeout.cleanup_s == 300
    data["timeout"]["cleanup_s"] = value
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("field,value", [
    ("max_requests", True), ("max_requests", 0), ("max_requests", -1),
    ("max_requests", 1.0), ("max_requests", None),
    ("cleanup_reserve", True), ("cleanup_reserve", -1), ("cleanup_reserve", 1.0),
])
def test_budget_requires_strict_integer_bounds(field, value):
    data = v2_dict()
    data["budget"] = {"max_requests": 1, "cleanup_reserve": 0}
    assert TransportSpecV2.from_dict(data).budget.cleanup_reserve == 0
    data["budget"][field] = value
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_lifecycle_roundtrip():
    data = lifecycle_dict()
    data["budget"] = {"max_requests": 20, "cleanup_reserve": 5}
    data["timeout"]["cleanup_s"] = 120
    spec = TransportSpecV2.from_dict(data)
    serialized = spec.to_dict()
    assert serialized["lifecycle"] == data["lifecycle"]
    assert serialized["budget"] == data["budget"]
    assert serialized["timeout"]["cleanup_s"] == 120
    assert TransportSpecV2.from_dict(serialized) == spec
    defaults = TransportSpecV2.from_dict(v2_dict()).to_dict()
    assert "lifecycle" not in defaults and "budget" not in defaults
    assert "cleanup_s" not in defaults["timeout"]


@pytest.mark.parametrize("field,value", [("last_segment", 1), ("last_segment", None),
    ("last_segment", "true"), ("expect_prefix", "objects/"), ("expect_prefix", None)])
def test_capture_transform_fields_have_exact_types(field, value):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0]["capture"]["ref"][field] = value
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("name", ["ref", "item", "create"])
def test_capture_prefix_uses_only_pre_step_visibility(name):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0]["capture"]["ref"]["expect_prefix"] = {"var": name}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_lifecycle_field_names_avoid_baseline_secret_words():
    assert {"lifecycle", "run", "attempt", "id", "if_present", "expect", "http_status",
            "when", "capture", "undo", "budget", "max_requests", "cleanup_reserve",
            "cleanup_s", "last_segment", "expect_prefix"} <= spec_v2.V2_FIELD_NAMES
    assert all(not any(word in name.lower() for word in _SECRET_WORDS)
               for name in spec_v2.V2_FIELD_NAMES)


def test_lifecycle_request_traversal_and_origin_override():
    data = lifecycle_dict()
    spec = TransportSpecV2.from_dict(data)
    assert [owner for owner, _ in iter_requests(spec)] == ["submit", "setup", "cleanup", "setup"]
    rewritten = with_origin(data, "http://127.0.0.1:8080")
    assert rewritten["lifecycle"]["run"][0]["request"]["url"] == "http://127.0.0.1:8080/objects"
    assert rewritten["lifecycle"]["run"][0]["undo"]["request"]["url"] == "http://127.0.0.1:8080/objects/{ref}"
    assert rewritten["lifecycle"]["attempt"][0]["request"]["url"] == "http://127.0.0.1:8080/objects/{ref}"
    assert data["request"]["url"] == "http://127.0.0.1:1/run"


@pytest.mark.parametrize("field,value", [
    ("expect", {"http_status": []}), ("expect", {"http_status": [True]}),
    ("expect", {"http_status": [99]}), ("expect", {"http_status": [600]}),
    ("expect", {"http_status": [200.0]}),
    ("expect", {"http_status": [200], "when": {"path": "$.x", "exists": "yes"}}),
    ("capture", {"ref": {"path": "$..id"}}),
])
def test_lifecycle_expect_and_capture_validation(field, value):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0][field] = value
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_lifecycle_step_method_is_restricted(method):
    data = lifecycle_dict()
    TransportSpecV2.from_dict(data)
    data["lifecycle"]["run"][0]["request"].update(method=method, body={"none": True})
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("payload", [None, [], "DELETE"])
def test_undo_request_rejects_non_objects(payload):
    data = lifecycle_dict()
    data["lifecycle"]["run"][0]["undo"]["request"] = payload
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize("method", [[], {}, 7])
def test_undo_method_rejects_non_strings(method):
    data = lifecycle_dict()
    data["lifecycle"]["run"][0]["undo"]["request"]["method"] = method
    with pytest.raises(ValueError, match="Undo method must be DELETE or GET"):
        TransportSpecV2.from_dict(data)


def sse_timeout_dict():
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
    return data


@pytest.mark.parametrize("parser", [TransportSpecV2.from_dict, parse_transport_spec])
@pytest.mark.parametrize("timeout", [None, [], "bad"])
def test_sse_timeout_rejects_non_objects(parser, timeout):
    data = sse_timeout_dict()
    data["timeout"] = timeout
    with pytest.raises(ValueError):
        parser(data)


@pytest.mark.parametrize("cleanup_s", [None, 60, 120, 300])
def test_sse_cleanup_timeout_preserves_defaults_and_roundtrip(cleanup_s):
    data = sse_timeout_dict()
    if cleanup_s is not None:
        data["timeout"]["cleanup_s"] = cleanup_s
    original = copy.deepcopy(data)
    spec = TransportSpecV2.from_dict(data)
    assert isinstance(spec.delivery, SseSpec)
    assert spec.timeout.cleanup_s == (60 if cleanup_s is None else cleanup_s)
    serialized = spec.to_dict()
    if cleanup_s in (None, 60):
        assert "cleanup_s" not in serialized["timeout"]
    else:
        assert serialized["timeout"]["cleanup_s"] == cleanup_s
    assert TransportSpecV2.from_dict(serialized) == spec
    assert data == original


@pytest.mark.parametrize("cleanup_s", [0, 301, True])
def test_sse_cleanup_timeout_rejects_invalid_bounds(cleanup_s):
    data = sse_timeout_dict()
    data["timeout"]["cleanup_s"] = cleanup_s
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)
