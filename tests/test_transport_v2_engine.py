from __future__ import annotations

import asyncio
import base64
import json
import re
import time
import uuid

import pytest
from aiohttp import web

from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import (
    ExecutionPolicy,
    TransportContext,
    TransportEngine,
    TransportSpec,
    local_transport_mode,
)
from argus_transport.runtime_v2 import V2Run
from argus_transport.spec_v2 import TransportSpecV2
from test_transport_engine import spec_dict
from test_transport_poll import poll_dict
from transport_v2_fakes import RecordingApp, serve


async def completed(request):
    return web.json_response({"status": "COMPLETED", "result": "done"})


def v2_dict(url):
    data = spec_dict(url)
    data["version"] = 2
    return data


def runtime(data, **kwargs):
    spec = TransportSpecV2.from_dict(data)
    return V2Run(spec, policy=ExecutionPolicy.local(spec), **kwargs)


def bodies(app):
    return [json.loads(call[3]) for call in app.calls]


async def test_let_run_value_is_stable_across_attempts():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["let"] = {
            "run": {
                "source_name": {
                    "concat": [{"literal": "argus-"}, {"generate": "uuid4"}]
                }
            }
        }
        data["request"]["body"] = {"json": {"source": {"var": "source_name"}}}
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            assert (await target.send_prompt("first"))[0] == "done"
            await target.begin_probe(None)
            assert (await target.send_prompt("second"))[0] == "done"
        first, second = bodies(app)
        assert first["source"] == second["source"]
        assert re.fullmatch(r"argus-[0-9a-f-]{36}", first["source"])


async def test_let_attempt_value_is_fresh_per_attempt():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["let"] = {"attempt": {"ref": {"generate": "uuid4"}}}
        data["request"]["body"] = {"json": {"ref": {"var": "ref"}}}
        run = runtime(data)
        await run.attempt(TransportContext(prompt="first"))
        await run.attempt(TransportContext(prompt="second"))
        first, second = bodies(app)
        assert first["ref"] != second["ref"]


async def test_generate_formats():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["let"] = {"attempt": {"ref": {"generate": "uuid4"}}}
        data["request"]["body"] = {
            "json": {
                "ref": {"var": "ref"},
                "again": {"var": "ref"},
                "timestamp": {"generate": "now_iso8601"},
                "ms": {"generate": "now_unix_ms"},
            }
        }
        await runtime(data).attempt(TransportContext(prompt="normal task"))
        body = bodies(app)[0]
        assert body["ref"] == body["again"]
        assert uuid.UUID(body["ref"]).version == 4
        assert re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", body["timestamp"]
        )
        assert type(body["ms"]) is int
        assert abs(body["ms"] - time.time() * 1000) < 5000


@pytest.mark.parametrize(
    "value,path,expected",
    [
        ("a/b?c", "/items/{ref}", "/items/a%2Fb%3Fc"),
        (".", "/items/{ref}", "/items/%2E"),
        ("..", "/items/{ref}", "/items/%2E%2E"),
        ("a/b?c", "/items/{ref}:invoke", "/items/a%2Fb%3Fc:invoke"),
    ],
)
async def test_path_vars_encoded_per_segment(value, path, expected):
    app = RecordingApp()
    app.route("POST", "/{tail:.*}", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + path)
        data["let"] = {"run": {"ref": {"literal": value}}}
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.response_text == "done"
        assert app.calls[0][1] == expected


async def test_query_values_urlencoded():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["query"] = {
            "q": {"literal": "a b&c"},
            "n": {"literal": 3},
            "skip": {"env": "ABSENT_REF", "missing": "omit"},
        }
        result = await runtime(data, environ={}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.response_text == "done"
        assert app.calls[0][1] == "/run?q=a+b%26c&n=3"


async def test_base64_encodes_utf8_value():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["body"] = {"json": {"encoded": {"base64": {"literal": "é✓"}}}}
        await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert base64.b64decode(bodies(app)[0]["encoded"]).decode("utf-8") == "é✓"


async def test_env_read_once_at_run_start(monkeypatch):
    monkeypatch.setenv("SOURCE_REF", "before-construction")
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["body"] = {"json": {"ref": {"env": "SOURCE_REF"}}}
        run = runtime(data)
        monkeypatch.setenv("SOURCE_REF", "at-start")
        await run.attempt(TransportContext(prompt="first"))
        monkeypatch.setenv("SOURCE_REF", "after-start")
        await run.attempt(TransportContext(prompt="second"))
        assert bodies(app) == [{"ref": "at-start"}, {"ref": "at-start"}]


@pytest.mark.parametrize(
    "missing,reason,count,body",
    [("error", "binding_error", 0, None), ("omit", "ok", 1, {})],
)
async def test_env_missing_error_vs_omit(missing, reason, count, body):
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["body"] = {
            "json": {"ref": {"env": "ABSENT_REF", "missing": missing}}
        }
        result = await runtime(data, environ={}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == reason
        assert len(app.calls) == count
        if count:
            assert bodies(app) == [body]


@pytest.mark.parametrize(
    "nested,extra,reason",
    [
        (False, "", "ok"),
        (False, "x", "binding_error"),
        (True, "", "ok"),
        (True, "x", "binding_error"),
    ],
)
async def test_concat_final_utf8_boundary(nested, extra, reason):
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        inner = {"concat": [{"literal": "é" * 4095}, {"literal": "é"}]}
        if not nested:
            data["let"] = {"run": {"ref": {"literal": "é" * 4096}}}
            inner = {"var": "ref"}
        data["request"]["body"] = {
            "json": {"ref": {"concat": [inner, {"literal": extra}]}}
        }
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.reason_code.value == reason
        assert len(app.calls) == (1 if reason == "ok" else 0)
        if app.calls:
            assert bodies(app)[0]["ref"] == "é" * 4096


@pytest.mark.parametrize("extra,reason", [("", "ok"), ("x", "binding_error")])
async def test_nonsecret_env_snapshot_utf8_boundary(extra, reason):
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["body"] = {"json": {"ref": {"env": "SOURCE_REF"}}}
        result = await runtime(data, environ={"SOURCE_REF": "é" * 512 + extra}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == reason
        assert len(app.calls) == (1 if reason == "ok" else 0)
        if app.calls:
            assert bodies(app)[0]["ref"] == "é" * 512


async def test_v2_poll_with_run_id_matches_v1_sequence():
    app = RecordingApp()
    index = 0

    async def submitted(request):
        return web.json_response({"run_id": "a/b?c", "status": "PENDING"}, status=202)

    async def polled(request):
        nonlocal index
        index += 1
        return web.json_response(
            {"status": "RUNNING"}
            if index % 2
            else {"status": "COMPLETED", "result": "done"}
        )

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", polled)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        spec = TransportSpec.from_dict(data)
        context = TransportContext(prompt="normal task")
        old = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            context
        )
        old_calls = [(call[0], call[1]) for call in app.calls]
        app.calls.clear()
        data["version"] = 2
        new = await runtime(data).attempt(context)
        assert (
            [(call[0], call[1]) for call in app.calls]
            == old_calls
            == [
                ("POST", "/run"),
                ("GET", "/runs/a%2Fb%3Fc"),
                ("GET", "/runs/a%2Fb%3Fc"),
            ]
        )
        assert new.outcome == old.outcome
        assert new.metadata["run_id"] == old.metadata["run_id"] == "a/b?c"
        assert (
            new.diagnostics["requests"]
            == old.diagnostics["requests"]
            == {"submit": 1, "poll": 2, "retry": 0}
        )


async def test_v2_delete_request_sends_no_body():
    app = RecordingApp()
    app.route("DELETE", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"] = {"method": "DELETE", "url": origin + "/run"}
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.response_text == "done"
        assert app.calls[0][3] == b""


async def test_sse_unsupported_delivery_makes_zero_requests():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["delivery"] = {
            "kind": "sse",
            "event_names": ["message"],
            "data_format": "json",
            "terminal": {"path": "$.done", "equals": True},
            "accumulation": "final_value",
            "idle_timeout_s": 5,
            "reconnect": False,
        }
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.reason_code.value == "unsupported_delivery"
        assert app.calls == []
        assert result.diagnostics["requests"] == {"submit": 0, "poll": 0, "retry": 0}


@pytest.mark.parametrize("run_id", [None, "previous-job"])
async def test_legacy_context_run_id_preserves_v1_semantics(run_id):
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        data["request"]["body"] = {
            "json": {"ref": {"context": "run_id", "missing": "omit"}}
        }
        context = TransportContext(prompt="normal task", run_id=run_id)
        spec = TransportSpec.from_dict(data)
        old = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            context
        )
        data["version"] = 2
        new = await runtime(data).attempt(context)
        assert (
            bodies(app)[0]
            == bodies(app)[1]
            == ({} if run_id is None else {"ref": "previous-job"})
        )
        assert new.outcome == old.outcome


@pytest.mark.parametrize(
    "placement,value",
    [
        ("query", True),
        ("query", {"x": 1}),
        ("query", [1]),
        ("text", 3),
        ("base64", 3),
        ("concat", True),
        ("declaration", []),
    ],
)
async def test_dynamic_binding_type_errors_make_zero_requests(placement, value):
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        if placement == "query":
            data["request"]["query"] = {"q": {"literal": value}}
        elif placement == "text":
            data["request"]["body"] = {"text": {"literal": value}}
        elif placement == "base64":
            data["request"]["body"] = {"json": {"ref": {"base64": {"literal": value}}}}
        elif placement == "concat":
            data["request"]["body"] = {
                "json": {"ref": {"concat": [{"context": "history"}, {"literal": "x"}]}}
            }
        else:
            data["let"] = {"run": {"ref": {"literal": value}}}
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.reason_code.value == "binding_error"
        assert app.calls == []


async def test_ordered_declarations_and_omitted_variables():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["let"] = {
            "run": {
                "prefix": {"literal": "task-"},
                "ref": {"concat": [{"var": "prefix"}, {"literal": 7}]},
            },
            "attempt": {
                "gone": {"env": "ABSENT_REF", "missing": "omit"},
                "label": {"concat": [{"var": "ref"}, {"context": "prompt"}]},
            },
        }
        data["request"]["body"] = {
            "json": {
                "nested": {
                    "object": {
                        "label": {"var": "label"},
                        "skip": {"var": "gone", "missing": "omit"},
                    }
                },
                "values": {
                    "array": [{"var": "ref"}, {"var": "gone", "missing": "omit"}]
                },
            }
        }
        result = await runtime(data, environ={}).attempt(
            TransportContext(prompt="-done")
        )
        assert result.response_text == "done"
        assert bodies(app) == [
            {"nested": {"label": "task-7-done"}, "values": ["task-7"]}
        ]


@pytest.mark.parametrize(
    "submit,polls,submit_status,poll_status,reason",
    [
        ({"status": "COMPLETED", "result": "already done"}, [], 200, 200, "ok"),
        ({"status": "FAILED"}, [], 202, 200, "target_error"),
        ({"run_id": True}, [], 202, 200, "mapping_error"),
        ({"run_id": ""}, [], 202, 200, "mapping_error"),
        ({"run_id": "job-1"}, [{"status": "RUNNING"}], 202, 200, "poll_limit"),
        ({"run_id": "job-1"}, [{"status": "UNKNOWN"}], 202, 200, "unknown_status"),
        (
            {"run_id": "job-1"},
            [{"status": "COMPLETED", "result": "done"}],
            202,
            500,
            "http_error",
        ),
        (
            {"run_id": "job-1"},
            [{"status": "RUNNING", "error": {"code": "POLICY_REFUSAL"}}],
            202,
            200,
            "target_refusal",
        ),
    ],
)
async def test_v2_poll_error_and_terminal_classification_matches_v1(
    submit, polls, submit_status, poll_status, reason
):
    app = RecordingApp()

    async def submitted(request):
        return web.json_response(submit, status=submit_status)

    async def polled(request):
        return web.json_response(polls[0], status=poll_status)

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", polled)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        spec = TransportSpec.from_dict(data)
        context = TransportContext(prompt="normal task")
        old = await TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
            context
        )
        old_calls = [(call[0], call[1]) for call in app.calls]
        app.calls.clear()
        data["version"] = 2
        new = await runtime(data).attempt(context)
        assert [(call[0], call[1]) for call in app.calls] == old_calls
        assert old.reason_code.value == reason
        assert new.reason_code.value == ('missing_id' if reason == 'mapping_error' else reason)
        assert (
            new.outcome,
            new.response_text,
            new.http_status,
            new.matched_rule_id,
            new.metadata,
        ) == (
            old.outcome,
            old.response_text,
            old.http_status,
            old.matched_rule_id,
            old.metadata,
        )
        assert new.diagnostics["requests"] == old.diagnostics["requests"]


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("redirect", "http_error"),
        ("compressed", "parse_error"),
        ("oversized", "response_limit"),
        ("invalid_json", "parse_error"),
        ("invalid_utf8", "parse_error"),
        ("timeout", "timeout"),
    ],
)
async def test_v2_exchange_preserves_response_safeguards(mode, reason):
    app = RecordingApp()

    async def response(request):
        if mode == "redirect":
            return web.Response(status=302, headers={"Location": "/elsewhere"})
        if mode == "compressed":
            return web.Response(body=b"ignored", headers={"Content-Encoding": "gzip"})
        if mode == "oversized":
            return web.json_response({"status": "COMPLETED", "result": "x" * 200})
        if mode == "invalid_json":
            return web.Response(text="invalid")
        if mode == "invalid_utf8":
            return web.Response(body=b"\xff")
        await asyncio.sleep(0.1)
        return await completed(request)

    app.route("POST", "/run", response)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["limits"]["response_bytes"] = 100
        if mode == "timeout":
            data["timeout"] = {"total_deadline_s": 0.03, "read_s": 1}
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.reason_code.value == reason
        assert result.response_text is None
        assert len(app.calls) == 1
        assert app.calls[0][2]["Accept-Encoding"] == "identity"
        assert app.calls[0][2]["Host"] == origin.removeprefix("http://")
        assert result.diagnostics["requests"] == {"submit": 1, "poll": 0, "retry": 0}


async def test_v2_poll_auth_and_redaction_survive_attempts(monkeypatch):
    monkeypatch.setenv("DUMMY_ACCESS", "dummy-not-a-key")
    app = RecordingApp()

    async def submitted(request):
        return web.json_response(
            {"run_id": "dummy-not-a-key", "status": "PENDING"}, status=202
        )

    async def polled(request):
        return web.json_response({"status": "COMPLETED", "result": "dummy-not-a-key"})

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", polled)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        data["version"] = 2
        data["auth"] = {
            "kind": "bearer",
            "secret": {"source": "env", "name": "DUMMY_ACCESS"},
        }
        data['budget'] = {'stop_on': {'credential_echo': False}}
        run = runtime(data)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt="normal task"))
            assert result.response_text == "<redacted>"
            assert result.metadata["run_id"] == "<redacted>"
            assert "dummy-not-a-key" not in json.dumps(result.as_dict())
        assert len(app.calls) == 4
        assert all(
            call[2]["Authorization"] == "Bearer dummy-not-a-key" for call in app.calls
        )
        assert [call[1] for call in app.calls] == ["/run", "/runs/dummy-not-a-key"] * 2


async def test_v2_borrowed_client_stays_open():
    import httpx

    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        async with httpx.AsyncClient(trust_env=False) as client:
            run = runtime(v2_dict(origin + "/run"), client=client)
            assert (
                await run.attempt(TransportContext(prompt="first"))
            ).response_text == "done"
            assert not client.is_closed
            assert (
                await run.attempt(TransportContext(prompt="second"))
            ).response_text == "done"
        assert len(app.calls) == 2


async def test_literal_env_field_is_not_an_environment_binding():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["body"] = {
            "json": {"value": {"literal": {"env": "SOURCE_REF"}}}
        }
        result = await runtime(data, environ={"SOURCE_REF": "x" * 1025}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.response_text == "done"
        assert bodies(app) == [{"value": {"env": "SOURCE_REF"}}]


async def test_missing_variable_error_makes_zero_requests():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["let"] = {"run": {"ref": {"env": "ABSENT_REF", "missing": "omit"}}}
        data["request"]["body"] = {"json": {"ref": {"var": "ref"}}}
        result = await runtime(data, environ={}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "binding_error"
        assert app.calls == []


async def test_default_policy_denies_unapproved_loopback():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        spec = TransportSpecV2.from_dict(v2_dict(origin + "/run"))
        result = await V2Run(spec, policy=ExecutionPolicy()).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "endpoint_error"
        assert result.diagnostics["requests"] == {"submit": 0, "poll": 0, "retry": 0}
        assert app.calls == []


async def test_poll_deadline_covers_sleep_and_preserves_run_id():
    app = RecordingApp()

    async def submitted(request):
        return web.json_response({"run_id": "job-1", "status": "PENDING"}, status=202)

    async def pending(request):
        return web.json_response({"status": "RUNNING"})

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", pending)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        data["version"] = 2
        data["timeout"] = {"total_deadline_s": 0.2, "read_s": 1}
        data["delivery"]["interval_s"] = 1
        result = await runtime(data).attempt(TransportContext(prompt="normal task"))
        assert result.reason_code.value == "timeout"
        assert result.outcome.value == "timed_out"
        assert result.metadata["run_id"] == "job-1"
        assert result.diagnostics["requests"] == {"submit": 1, "poll": 1, "retry": 0}


async def test_poll_cancellation_preserves_detached_diagnostics():
    app = RecordingApp()
    received = asyncio.Event()

    async def submitted(request):
        return web.json_response({"run_id": "job-1", "status": "PENDING"}, status=202)

    async def pending(request):
        received.set()
        return web.json_response({"status": "RUNNING"})

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", pending)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        data["version"] = 2
        data["delivery"]["interval_s"] = 1
        task = asyncio.create_task(
            runtime(data).attempt(TransportContext(prompt="normal task"))
        )
        try:
            await asyncio.wait_for(received.wait(), timeout=2)
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError) as caught:
                await task
        diagnostics = caught.value.transport_diagnostics
        assert diagnostics["job_detached"] is True
        assert diagnostics["run_id"] == "job-1"
        assert diagnostics["requests"] == {"submit": 1, "poll": 1, "retry": 0}


class TrackingMapping(dict):
    def __init__(self, values):
        super().__init__(values)
        self.get_calls = []

    def get(self, name, default=None):
        self.get_calls.append(name)
        return super().get(name, default)


def env_binding_spec(url, placement, expression):
    if placement == "poll":
        data = poll_dict(url)
        data["version"] = 2
        data["delivery"]["request"]["query"] = {"ref": expression}
    else:
        data = v2_dict(url)
        if placement == "run":
            data["let"] = {"run": {"ref": expression}}
            expression = {"var": "ref", "missing": "omit"}
        data["request"]["body"] = {"json": {"ref": expression}}
    return data


@pytest.mark.parametrize("placement", ["body", "run", "poll"])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("missing", ["error", "omit"])
async def test_denied_environment_binding_never_reads_or_sends(
    placement, present, missing
):
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = env_binding_spec(
            origin + "/run", placement, {"env": "SOURCE_REF", "missing": missing}
        )
        spec = TransportSpecV2.from_dict(data)
        environ = TrackingMapping({"SOURCE_REF": "synthetic-value"} if present else {})
        policy = ExecutionPolicy(
            allowed_origins=frozenset({origin}), allowed_env_names=frozenset()
        )
        run = V2Run(spec, policy=policy, environ=environ)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt="normal task"))
            assert environ.get_calls == []
            assert result.reason_code.value == "binding_error"
            assert result.diagnostics["requests"] == {"submit": 0, "poll": 0, "retry": 0}
            assert app.calls == []


async def test_environment_policy_checks_all_names_before_any_read():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["request"]["body"] = {
            "json": {
                "permitted": {"env": "PERMITTED_REF"},
                "denied": {"env": "DENIED_REF", "missing": "omit"},
            }
        }
        environ = TrackingMapping({"PERMITTED_REF": "synthetic-value"})
        spec = TransportSpecV2.from_dict(data)
        policy = ExecutionPolicy(
            allowed_origins=frozenset({origin}),
            allowed_env_names=frozenset({"PERMITTED_REF"}),
        )
        result = await V2Run(spec, policy=policy, environ=environ).attempt(
            TransportContext(prompt="normal task")
        )
        assert environ.get_calls == []
        assert result.reason_code.value == "binding_error"
        assert app.calls == []


@pytest.mark.parametrize("placement", ["body", "run", "poll"])
@pytest.mark.parametrize("allowed", [None, frozenset({"SOURCE_REF"})])
async def test_permitted_environment_binding_snapshots_once(placement, allowed):
    app = RecordingApp()

    async def submitted(request):
        return web.json_response({"run_id": "job-1", "status": "PENDING"}, status=202)

    app.route("POST", "/run", submitted if placement == "poll" else completed)
    app.route("GET", "/runs/{tail:.*}", completed)
    async with serve(app) as origin:
        data = env_binding_spec(origin + "/run", placement, {"env": "SOURCE_REF"})
        spec = TransportSpecV2.from_dict(data)
        environ = TrackingMapping({"SOURCE_REF": "synthetic-value"})
        policy = ExecutionPolicy(
            allowed_origins=frozenset({origin}), allowed_env_names=allowed
        )
        run = V2Run(spec, policy=policy, environ=environ)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt="normal task"))
            assert result.reason_code.value == "ok"
            environ["SOURCE_REF"] = "changed-value"
        assert environ.get_calls == ["SOURCE_REF"]
        if placement == "poll":
            assert [call[1] for call in app.calls] == [
                "/run",
                "/runs/job-1?ref=synthetic-value",
            ] * 2
        else:
            assert bodies(app) == [{"ref": "synthetic-value"}] * 2


@pytest.mark.parametrize(
    "query",
    [
        {"ref": {"env": "ABSENT_REF"}},
        {"ref": {"env": "ABSENT_REF", "missing": "error"}},
        {
            "optional": {"env": "ABSENT_REF", "missing": "omit"},
            "required": {"env": "ABSENT_REF"},
        },
        {
            "required": {"env": "ABSENT_REF"},
            "optional": {"env": "ABSENT_REF", "missing": "omit"},
        },
    ],
)
async def test_required_poll_environment_fails_before_submit(query):
    app = RecordingApp()

    async def submitted(request):
        return web.json_response({"run_id": "job-1", "status": "PENDING"}, status=202)

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", completed)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        data["version"] = 2
        data["delivery"]["request"]["query"] = query
        environ = TrackingMapping({})
        run = runtime(data, environ=environ)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt="normal task"))
            assert result.reason_code.value == "binding_error"
            assert result.diagnostics["requests"] == {"submit": 0, "poll": 0, "retry": 0}
            assert app.calls == []
            environ["ABSENT_REF"] = "appeared-later"
        assert environ.get_calls == ["ABSENT_REF"]


async def test_optional_poll_environment_remains_omitted():
    app = RecordingApp()

    async def submitted(request):
        return web.json_response({"run_id": "job-1", "status": "PENDING"}, status=202)

    app.route("POST", "/run", submitted)
    app.route("GET", "/runs/{tail:.*}", completed)
    async with serve(app) as origin:
        data = env_binding_spec(
            origin + "/run", "poll", {"env": "ABSENT_REF", "missing": "omit"}
        )
        result = await runtime(data, environ={}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "ok"
        assert [call[1] for call in app.calls] == ["/run", "/runs/job-1"]


async def test_required_attempt_environment_fails_even_when_variable_unused():
    app = RecordingApp()
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = v2_dict(origin + "/run")
        data["let"] = {
            "run": {"optional": {"env": "ABSENT_REF", "missing": "omit"}},
            "attempt": {"required": {"env": "ABSENT_REF"}},
        }
        result = await runtime(data, environ={}).attempt(
            TransportContext(prompt="normal task")
        )
        assert result.reason_code.value == "binding_error"
        assert app.calls == []
