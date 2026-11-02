from __future__ import annotations

import copy
import importlib.util
import json
from contextlib import asynccontextmanager

import httpx
import pytest
from aiohttp import web


def test_shared_transport_package_exists():
    assert importlib.util.find_spec("argus_transport") is not None


def spec_dict(url="http://127.0.0.1:1/run"):
    return {
        "version": 1,
        "request": {
            "method": "POST",
            "url": url,
            "headers": {"Accept": "application/json"},
            "body": {"json": {"goal": {"context": "prompt"}}},
        },
        "auth": {"kind": "none"},
        "response": {
            "format": "json",
            "text": {
                "paths": ["$.result.result", "$.result"],
                "cast": "string_or_json",
                "empty": "error",
            },
            "metadata": {},
        },
        "outcome": {
            "kind": "rules",
            "unmatched": "target_error",
            "rules": [
                {
                    "id": "policy_refusal",
                    "priority": 100,
                    "http_status": [200, 403],
                    "when": {"path": "$.error.code", "equals": "POLICY_REFUSAL"},
                    "outcome": "blocked",
                },
                {
                    "id": "failed",
                    "priority": 50,
                    "http_status": [200],
                    "when": {"path": "$.status", "equals": "FAILED"},
                    "outcome": "target_error",
                },
                {
                    "id": "completed",
                    "priority": 10,
                    "http_status": [200],
                    "when": {"path": "$.status", "equals": "COMPLETED"},
                    "outcome": "succeeded",
                },
            ],
        },
        "delivery": {"kind": "sync"},
        "timeout": {"total_deadline_s": 300, "read_s": 300},
        "session": {"mode": "none"},
        "limits": {
            "response_bytes": 8388608,
            "event_bytes": 1048576,
            "max_events": 1024,
            "max_rules": 32,
        },
    }


@asynccontextmanager
async def server(body, status=200, delay=0, plain=False, response_gate=None):
    import asyncio

    calls = []

    async def handler(request):
        calls.append({"headers": dict(request.headers), "body": await request.json()})
        if delay:
            await asyncio.sleep(delay)
        if response_gate is not None:
            await response_gate.wait()
        return (
            web.Response(text=body, status=status)
            if plain
            else web.json_response(body, status=status)
        )

    app = web.Application()
    app.router.add_post("/run", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        yield url, calls
    finally:
        await runner.cleanup()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(unknown=True),
        lambda d: d["request"]["body"]["json"]["goal"].update(literal="x"),
        lambda d: d["request"]["headers"].update({"Host": "elsewhere.invalid"}),
        lambda d: d["request"]["headers"].update({"X-Unsafe": "one\r\ntwo"}),
        lambda d: d["outcome"]["rules"][1].update(priority=100),
        lambda d: d["response"]["text"].update(paths=["$..result"]),
        lambda d: d["timeout"].update(read_s=0),
        lambda d: d["request"].update(url="http://{prompt}.invalid/run"),
        lambda d: d["session"].update(mode="server_returned"),
    ],
)
def test_strict_schema_rejects_unsafe_or_ambiguous_inputs(mutation):
    from argus_transport import TransportSpec

    data = spec_dict()
    mutation(data)
    with pytest.raises(ValueError):
        TransportSpec.from_dict(data)


@pytest.mark.parametrize(
    "body,status,outcome,reason",
    [
        ({"status": "COMPLETED", "result": "top"}, 200, "succeeded", "ok"),
        (
            {"status": "COMPLETED", "result": {"result": "nested"}},
            200,
            "succeeded",
            "ok",
        ),
        (
            {"status": "FAILED", "result": "do not score"},
            200,
            "target_error",
            "target_error",
        ),
        (
            {"status": "COMPLETED", "result": "cannot override"},
            500,
            "target_error",
            "http_error",
        ),
        ({"error": {"code": "POLICY_REFUSAL"}}, 403, "blocked", "target_refusal"),
        (
            {"status": "COMPLETED", "result": "not authenticated"},
            401,
            "target_error",
            "http_error",
        ),
        (
            {"status": "UNKNOWN", "result": "not complete"},
            200,
            "target_error",
            "unknown_status",
        ),
    ],
)
async def test_response_result_and_nested_result(body, status, outcome, reason):
    from argus_transport import (
        TransportContext,
        TransportEngine,
        TransportSpec,
        ExecutionPolicy,
    )

    async with server(body, status) as (url, calls):
        spec = TransportSpec.from_dict(spec_dict(url))
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.outcome.value == outcome
        assert result.reason_code.value == reason
        assert len(calls) == 1
        assert calls[0]["body"] == {"goal": "normal task"}
        assert (
            result.response_text
            == (
                body["result"].get("result")
                if isinstance(body.get("result"), dict)
                else body.get("result")
            )
            if outcome == "succeeded"
            else result.response_text is None
        )


@pytest.mark.parametrize("answer", [None, "", " ", [], {}])
def test_response_missing_ambiguous_or_wrong_type_errors(answer):
    from argus_transport import TransportSpec, evaluate_response

    result = evaluate_response(
        TransportSpec.from_dict(spec_dict()),
        200,
        {"status": "COMPLETED", "result": answer},
    )
    assert result.outcome.value == "target_error"
    assert result.reason_code.value == "mapping_error"


def test_validate_missing_path_safe_diagnostic():
    from argus_transport import TransportSpec, evaluate_response

    result = evaluate_response(
        TransportSpec.from_dict(spec_dict()),
        200,
        {"status": "COMPLETED", "output": "private answer"},
    )
    assert result.outcome.value == "target_error"
    assert result.diagnostics["response_paths"] == {
        "$.result.result": "NOT_FOUND",
        "$.result": "NOT_FOUND",
    }
    assert result.as_dict()["diagnostics"]["top_keys"] == ["status", "output"]
    assert "private answer" not in json.dumps(result.as_dict())


async def test_auth_file_ref_exact_header_and_no_literal_in_spec(tmp_path):
    from argus_transport import (
        TransportSpec,
        TransportEngine,
        TransportContext,
        ExecutionPolicy,
    )

    path = tmp_path / "credential"
    path.write_text("synthetic token\n")
    async with server({"status": "COMPLETED", "result": "answer"}) as (url, calls):
        data = spec_dict(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {
                    "name": "X-Api-Key",
                    "secret": {
                        "source": "file",
                        "path": str(path),
                        "strip_final_newline": True,
                    },
                }
            ],
        }
        spec = TransportSpec.from_dict(data)
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.response_text == "answer"
        assert calls[0]["headers"]["X-Api-Key"] == "synthetic token"
        assert "synthetic token" not in json.dumps(spec.to_dict())
        assert "synthetic token" not in json.dumps(result.as_dict())


async def test_missing_or_disallowed_secret_makes_zero_requests(tmp_path):
    from argus_transport import (
        TransportSpec,
        TransportEngine,
        TransportContext,
        ExecutionPolicy,
    )

    async with server({"status": "COMPLETED", "result": "answer"}) as (url, calls):
        data = spec_dict(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {
                    "name": "X-Api-Key",
                    "secret": {"source": "file", "path": str(tmp_path / "missing")},
                }
            ],
        }
        spec = TransportSpec.from_dict(data)
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "secret_error"
        assert result.as_dict()["diagnostics"]["requests"] == {
            "submit": 0,
            "poll": 0,
            "retry": 0,
        }
        assert calls == []


async def test_secret_not_in_wire_result_logs_or_reports(tmp_path):
    from argus_transport import (
        TransportSpec,
        TransportEngine,
        TransportContext,
        ExecutionPolicy,
    )

    token = "synthetic-secret-text"
    path = tmp_path / "credential"
    path.write_text(token)
    async with server(
        {"status": "FAILED", token: token, "error": {"message": token}}
    ) as (url, calls):
        data = spec_dict(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {"name": "X-Api-Key", "secret": {"source": "file", "path": str(path)}}
            ],
        }
        spec = TransportSpec.from_dict(data)
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.outcome.value == "target_error"
        assert token not in json.dumps(result.as_dict())
        assert calls[0]["headers"]["X-Api-Key"] == token


async def test_deadline_and_response_size_are_enforced():
    import asyncio

    from argus_transport import (
        TransportSpec,
        TransportEngine,
        TransportContext,
        ExecutionPolicy,
    )

    response_gate = asyncio.Event()
    async with server(
        {"status": "COMPLETED", "result": "answer"}, response_gate=response_gate
    ) as (url, calls):
        data = spec_dict(url)
        data["timeout"] = {"total_deadline_s": 1, "read_s": 10}
        spec = TransportSpec.from_dict(data)
        async with httpx.AsyncClient(trust_env=False) as client:
            try:
                result = await asyncio.wait_for(
                    TransportEngine(
                        spec, policy=ExecutionPolicy.local(spec), client=client
                    ).run(TransportContext(prompt="normal task")),
                    timeout=2,
                )
            finally:
                response_gate.set()
        assert result.outcome.value == "timed_out"
        assert result.reason_code.value == "timeout"
        assert result.response_text is None
        assert len(calls) == 1
        assert result.diagnostics["requests"] == {"submit": 1, "poll": 0, "retry": 0}
    async with server({"status": "COMPLETED", "result": "x" * 500}) as (url, calls):
        data = spec_dict(url)
        data["limits"]["response_bytes"] = 100
        spec = TransportSpec.from_dict(data)
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "response_limit"
        assert result.response_text is None


async def test_server_policy_blocks_loopback_before_request():
    from argus_transport import TransportSpec, TransportEngine, TransportContext

    async with server({"status": "COMPLETED", "result": "answer"}) as (url, calls):
        result = await TransportEngine(TransportSpec.from_dict(spec_dict(url))).run(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "endpoint_error"
        assert calls == []


async def test_template_value_is_data_not_execution():
    from argus_transport import (
        TransportSpec,
        TransportEngine,
        TransportContext,
        ExecutionPolicy,
    )

    prompt = 'literal " \\ {{ access }}'
    async with server({"status": "COMPLETED", "result": "answer"}) as (url, calls):
        spec = TransportSpec.from_dict(spec_dict(url))
        await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt=prompt)
        )
        assert calls[0]["body"] == {"goal": prompt}


def test_spec_and_result_are_deeply_immutable():
    from argus_transport import TransportSpec, evaluate_response

    spec = TransportSpec.from_dict(spec_dict())
    with pytest.raises(TypeError):
        spec.request.headers["Accept"] = "changed"
    with pytest.raises(TypeError):
        spec.request.body["json"]["goal"]["context"] = "run_id"
    result = evaluate_response(spec, 200, {"status": "COMPLETED", "result": "answer"})
    with pytest.raises(TypeError):
        result.diagnostics["outcome_selected"] = "forged"
    assert spec.to_dict()["request"]["body"]["json"]["goal"] == {"context": "prompt"}


async def test_auth_env_ref_and_file_newline(monkeypatch, tmp_path):
    from argus_transport.security import resolve_secret
    from argus_transport import SecretRef, ExecutionPolicy

    monkeypatch.setattr(
        "argus_transport.security.os.getenv",
        lambda name: " synthetic token " if name == "TEST_CREDENTIAL" else None,
    )
    ref = SecretRef.from_dict({"source": "env", "name": "TEST_CREDENTIAL"})
    assert (
        resolve_secret(
            ref, ExecutionPolicy(allowed_env_names=frozenset({"TEST_CREDENTIAL"}))
        )
        == " synthetic token "
    )
    with pytest.raises(ValueError):
        resolve_secret(ref, ExecutionPolicy())
    path = tmp_path / "credential"
    path.write_bytes(b" synthetic token \r\n")
    ref = SecretRef.from_dict(
        {"source": "file", "path": str(path), "strip_final_newline": True}
    )
    assert (
        resolve_secret(ref, ExecutionPolicy(allowed_secret_roots=(tmp_path,)))
        == " synthetic token "
    )


def test_secret_file_links_and_unauthorized_roots_are_rejected(tmp_path):
    from argus_transport import SecretRef, ExecutionPolicy
    from argus_transport.security import resolve_secret

    root = tmp_path / "authorized"
    root.mkdir()
    other = tmp_path / "outside"
    other.mkdir()
    (other / "credential").write_text("synthetic token")
    (root / "link").symlink_to(other, target_is_directory=True)
    (root / "credential").symlink_to(other / "credential")
    policy = ExecutionPolicy(allowed_secret_roots=(root,))
    for path in [
        root / "link" / "credential",
        root / "credential",
        other / "credential",
    ]:
        with pytest.raises((ValueError, OSError)):
            resolve_secret(
                SecretRef.from_dict({"source": "file", "path": str(path)}), policy
            )


@pytest.mark.parametrize("provided_client", [False, True])
async def test_dns_checked_address_is_used_for_connection(monkeypatch, provided_client):
    import asyncio
    from argus_transport import (
        TransportContext,
        TransportEngine,
        TransportSpec,
        ExecutionPolicy,
    )

    async with server({"status": "COMPLETED", "result": "answer"}) as (url, calls):
        hostname_url = url.replace("127.0.0.1", "localhost")
        loop = asyncio.get_running_loop()
        original = loop.getaddrinfo
        resolutions = []

        async def getaddrinfo(host, *args, **kwargs):
            if host == "localhost":
                resolutions.append(host)
                if len(resolutions) > 1:
                    raise AssertionError(
                        "Hostname resolved again after policy approval"
                    )
                return await original("127.0.0.1", *args, **kwargs)
            return await original(host, *args, **kwargs)

        monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
        spec = TransportSpec.from_dict(spec_dict(hostname_url))
        async with httpx.AsyncClient(trust_env=False) as client:
            result = await TransportEngine(
                spec,
                policy=ExecutionPolicy.local(spec),
                client=client if provided_client else None,
            ).run(TransportContext(prompt="normal task"))
        assert result.response_text == "answer"
        assert resolutions == ["localhost"]
        assert calls[0]["headers"]["Host"].startswith("localhost:")


def test_secret_parent_symlink_is_rejected_even_inside_authorized_root(tmp_path):
    from argus_transport import SecretRef, ExecutionPolicy
    from argus_transport.security import resolve_secret

    directory = tmp_path / "actual"
    directory.mkdir()
    (directory / "credential").write_text("synthetic token")
    linked = tmp_path / "linked"
    linked.symlink_to(directory, target_is_directory=True)
    ref = SecretRef.from_dict({"source": "file", "path": str(linked / "credential")})
    for policy in [
        ExecutionPolicy(allowed_secret_roots=(tmp_path,)),
        ExecutionPolicy(allowed_secret_roots=None),
    ]:
        with pytest.raises((ValueError, OSError)):
            resolve_secret(ref, policy)


async def test_deep_json_returns_parse_error():
    from argus_transport import (
        TransportContext,
        TransportEngine,
        TransportSpec,
        ExecutionPolicy,
    )

    raw = "[" * 2000 + "0" + "]" * 2000
    calls = []

    async def handler(request):
        calls.append(await request.json())
        return web.Response(text=raw, content_type="application/json")

    app = web.Application()
    app.router.add_post("/run", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        spec = TransportSpec.from_dict(spec_dict(url))
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.outcome.value == "target_error"
        assert result.reason_code.value == "parse_error"
        assert calls == [{"goal": "normal task"}]
    finally:
        await runner.cleanup()


def test_rules_require_explicit_rules_and_unmatched():
    from argus_transport import TransportSpec

    data = spec_dict()
    data["outcome"] = {"kind": "rules"}
    with pytest.raises(ValueError):
        TransportSpec.from_dict(data)


def test_invalid_enum_shape_is_a_schema_error():
    from argus_transport import TransportSpec

    data = spec_dict()
    data["response"]["format"] = ["json"]
    with pytest.raises(ValueError):
        TransportSpec.from_dict(data)


def test_spec_roundtrip_preserves_nested_bindings_and_predicates():
    from argus_transport import TransportSpec

    data = spec_dict()
    data["request"]["body"]["json"]["items"] = {
        "array": [
            {"literal": {"nested": ["first", "second"]}},
            {"object": {"task": {"context": "prompt"}}},
        ]
    }
    data["outcome"]["rules"][2]["when"] = {
        "all": [
            {"path": "$.status", "one_of": ["COMPLETED", "FINISHED"]},
            {
                "any": [
                    {"path": "$.result", "exists": True},
                    {"not": {"path": "$.output", "exists": False}},
                ]
            },
        ]
    }
    parsed = TransportSpec.from_dict(data)
    exported = parsed.to_dict()
    roundtrip = TransportSpec.from_dict(exported)
    assert (
        roundtrip.to_dict()["request"]["body"]["json"]["items"]
        == data["request"]["body"]["json"]["items"]
    )
    assert (
        roundtrip.to_dict()["outcome"]["rules"][2]["when"]
        == data["outcome"]["rules"][2]["when"]
    )
    data["delivery"] = {
        "kind": "poll",
        "run_id": {"path": "$.run_id"},
        "request": {
            "method": "GET",
            "url": "http://127.0.0.1:1/runs/{run_id}",
            "body": {"none": True},
        },
        "pending": {"path": "$.status", "one_of": ["PENDING", "RUNNING"]},
        "interval_s": 2,
        "max_polls": 3,
        "submit_http_status": [200, 202],
        "submit_outcome": {"kind": "rules", "rules": [], "unmatched": "accepted"},
    }
    poll = TransportSpec.from_dict(data)
    assert type(poll.delivery.submit_outcome).__name__ == "SubmissionOutcomeSpec"
    assert (
        TransportSpec.from_dict(poll.to_dict()).delivery.submit_outcome.unmatched
        == "accepted"
    )
    with pytest.raises(ValueError):
        TransportSpec.from_dict(
            {**data, "outcome": {"kind": "rules", "rules": [], "unmatched": "accepted"}}
        )


def test_policy_refusal_precedes_generic_failed():
    from argus_transport import TransportSpec, evaluate_response

    result = evaluate_response(
        TransportSpec.from_dict(spec_dict()),
        200,
        {
            "status": "FAILED",
            "result": "unscored answer",
            "error": {"code": "POLICY_REFUSAL"},
        },
    )
    assert result.outcome.value == "blocked"
    assert result.response_text is None
    assert result.matched_rule_id == "policy_refusal"
    assert result.as_dict()["diagnostics"]["outcome_matches"] == [
        "policy_refusal",
        "failed",
    ]


def test_new_transport_cannot_override_response_encoding():
    from argus_transport import TransportSpec

    data = spec_dict()
    data["request"]["headers"]["Accept-Encoding"] = "gzip"
    with pytest.raises(ValueError):
        TransportSpec.from_dict(data)


async def test_unexpected_compression_is_rejected_before_decoding():
    import gzip
    from argus_transport import (
        TransportContext,
        TransportEngine,
        TransportSpec,
        ExecutionPolicy,
    )

    calls = []

    async def handler(request):
        calls.append(request.headers.get("Accept-Encoding"))
        content = gzip.compress(
            json.dumps({"status": "COMPLETED", "result": "answer"}).encode()
        )
        return web.Response(
            body=content,
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        )

    app = web.Application()
    app.router.add_post("/run", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        spec = TransportSpec.from_dict(spec_dict(url))
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="normal task")
        )
        assert result.outcome.value == "target_error"
        assert result.reason_code.value == "parse_error"
        assert result.response_text is None
        assert calls == ["identity"]
    finally:
        await runner.cleanup()


@pytest.mark.parametrize("status", [401, 407, 500, 502])
async def test_non_json_http_error_keeps_http_classification(status):
    from argus_transport import (
        TransportSpec,
        TransportEngine,
        TransportContext,
        ExecutionPolicy,
    )

    async with server("Unauthorized or unavailable", status=status, plain=True) as (
        url,
        calls,
    ):
        spec = TransportSpec.from_dict(spec_dict(url))
        result = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            TransportContext(prompt="ping")
        )
    assert result.outcome.value == "target_error"
    assert result.reason_code.value == "http_error"
    assert result.http_status == status
    assert len(calls) == 1
    assert result.response_text is None
