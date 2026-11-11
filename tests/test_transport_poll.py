from __future__ import annotations

import asyncio
import copy
import json
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
import pytest
from aiohttp import web

from argus_transport import (
    TransportContext,
    TransportEngine,
    TransportSpec,
    ExecutionPolicy,
)
from test_transport_engine import spec_dict


def poll_dict(url):
    data = spec_dict(url)
    data["response"]["metadata"] = {"run_id": {"path": "$.run_id", "required": False}}
    data["delivery"] = {
        "kind": "poll",
        "run_id": {"path": "$.run_id"},
        "request": {
            "method": "GET",
            "url": url.rsplit("/", 1)[0] + "/runs/{run_id}",
            "body": {"none": True},
        },
        "pending": {"path": "$.status", "one_of": ["PENDING", "RUNNING"]},
        "interval_s": 0.01,
        "max_polls": 3,
        "submit_http_status": [200, 202],
        "submit_outcome": {
            "kind": "rules",
            "unmatched": "accepted",
            "rules": [
                {**rule, "http_status": [200, 202, 403], "id": "submit_" + rule["id"]}
                for rule in data["outcome"]["rules"]
            ],
        },
    }
    return data


@asynccontextmanager
async def poll_server(
    submit=None, polls=None, *, submit_status=202, delays=(0, 0), poll_status=200
):
    calls = []
    submit = {"run_id": "job-1", "status": "PENDING"} if submit is None else submit
    polls = [{"status": "COMPLETED", "result": "done"}] if polls is None else polls
    index = 0

    async def post(request):
        calls.append(
            ("POST", request.raw_path, dict(request.headers), await request.json())
        )
        await asyncio.sleep(delays[0])
        return web.json_response(submit, status=submit_status)

    async def get(request):
        nonlocal index
        calls.append(
            ("GET", request.raw_path, dict(request.headers), await request.read())
        )
        body = polls[min(index, len(polls) - 1)]
        index += 1
        await asyncio.sleep(delays[1])
        return web.json_response(body, status=poll_status)

    app = web.Application()
    app.router.add_post("/run", post)
    app.router.add_get("/runs/{tail:.*}", get)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        yield url, calls
    finally:
        await runner.cleanup()


async def run(data, **kwargs):
    spec = TransportSpec.from_dict(data)
    return await TransportEngine(
        spec, policy=ExecutionPolicy.local(spec), **kwargs
    ).run(TransportContext(prompt="normal task"))


async def test_submit_once_poll_pending_to_complete(tmp_path, monkeypatch):
    import argus_transport.engine as engine_module

    secret = tmp_path / "credential"
    secret.write_text("synthetic-poll-token")
    resolved = []
    resolver = engine_module.resolve_secret

    def resolve(ref, policy):
        resolved.append(ref.path)
        return resolver(ref, policy)

    monkeypatch.setattr(engine_module, "resolve_secret", resolve)
    async with poll_server(
        polls=[{"status": "RUNNING"}, {"status": "COMPLETED", "result": "done"}]
    ) as (url, calls):
        data = poll_dict(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {"name": "X-Api-Key", "secret": {"source": "file", "path": str(secret)}}
            ],
        }
        result = await run(data)
        assert result.outcome.value == "succeeded"
        assert result.response_text == "done"
        assert [c[0] for c in calls] == ["POST", "GET", "GET"]
        assert [c[1] for c in calls] == ["/run", "/runs/job-1", "/runs/job-1"]
        assert [c[2]["X-Api-Key"] for c in calls] == ["synthetic-poll-token"] * 3
        assert calls[0][3] == {"goal": "normal task"}
        assert all(c[3] == b"" for c in calls[1:])
        assert resolved == [str(secret)]
        assert result.metadata["run_id"] == "job-1"
        assert result.diagnostics["requests"] == {"submit": 1, "poll": 2, "retry": 0}


@pytest.mark.parametrize(
    "body,outcome,reason",
    [
        (
            {"error": {"code": "POLICY_REFUSAL"}, "status": "FAILED"},
            "blocked",
            "target_refusal",
        ),
        (
            {"status": "FAILED", "result": "not an answer"},
            "target_error",
            "target_error",
        ),
        ({"status": "PENDING"}, "target_error", "mapping_error"),
        ({"run_id": ""}, "target_error", "mapping_error"),
        ({"run_id": True}, "target_error", "mapping_error"),
    ],
)
async def test_submit_refusal_or_missing_id_never_polls(body, outcome, reason):
    async with poll_server(submit=body) as (url, calls):
        result = await run(poll_dict(url))
        assert result.outcome.value == outcome
        assert result.reason_code.value == reason
        assert result.response_text is None
        assert [c[0] for c in calls] == ["POST"]
        assert result.diagnostics["requests"] == {"submit": 1, "poll": 0, "retry": 0}


@pytest.mark.parametrize("status", [200, 202])
async def test_submit_explicit_completion_returns_answer_without_id(status):
    async with poll_server(
        submit={"status": "COMPLETED", "result": "already done"}, submit_status=status
    ) as (url, calls):
        result = await run(poll_dict(url))
        assert result.outcome.value == "succeeded"
        assert result.response_text == "already done"
        assert result.matched_rule_id == "submit_completed"
        assert [c[0] for c in calls] == ["POST"]


async def test_submit_completion_is_not_guessed_without_explicit_rule():
    async with poll_server(
        submit={"status": "COMPLETED", "result": "ignore", "run_id": "job-1"}
    ) as (url, calls):
        data = poll_dict(url)
        data["delivery"]["submit_outcome"]["rules"] = []
        result = await run(data)
        assert result.response_text == "done"
        assert [c[0] for c in calls] == ["POST", "GET"]


@pytest.mark.parametrize(
    "polls,status,reason,count",
    [
        ([{"status": "UNKNOWN", "result": "ignore"}], 200, "unknown_status", 1),
        ([{"status": "RUNNING"}], 200, "poll_limit", 3),
        ([{"status": "COMPLETED", "result": "ignore"}], 500, "http_error", 1),
        ([{"status": "COMPLETED", "result": "ignore"}], 401, "http_error", 1),
    ],
)
async def test_poll_unknown_state_limit_and_http_failure(polls, status, reason, count):
    async with poll_server(polls=polls, poll_status=status) as (url, calls):
        result = await run(poll_dict(url))
        assert result.outcome.value == "target_error"
        assert result.reason_code.value == reason
        assert result.response_text is None
        assert [c[0] for c in calls] == ["POST"] + ["GET"] * count
        assert result.diagnostics["requests"] == {
            "submit": 1,
            "poll": count,
            "retry": 0,
        }


async def test_terminal_rule_precedes_pending_predicate():
    async with poll_server(
        polls=[{"status": "RUNNING", "error": {"code": "POLICY_REFUSAL"}}]
    ) as (url, calls):
        result = await run(poll_dict(url))
        assert result.outcome.value == "blocked"
        assert result.matched_rule_id == "policy_refusal"
        assert [c[0] for c in calls] == ["POST", "GET"]


@pytest.mark.parametrize("delays,interval", [((0.35, 0.35), 0.01), ((0.01, 0.01), 1.0)])
async def test_deadline_covers_submit_poll_sleep_and_read(delays, interval):
    async with poll_server(
        polls=[{"status": "RUNNING"}, {"status": "COMPLETED", "result": "too late"}],
        delays=delays,
    ) as (url, calls):
        data = poll_dict(url)
        data["timeout"] = {"total_deadline_s": 0.5, "read_s": 2}
        data["delivery"]["interval_s"] = interval
        async with httpx.AsyncClient(trust_env=False) as client:
            result = await asyncio.wait_for(run(data, client=client), timeout=1.5)
        assert result.outcome.value == "timed_out"
        assert result.reason_code.value == "timeout"
        assert result.latency_ms < 1000
        assert [c[0] for c in calls] == ["POST", "GET"]
        assert result.diagnostics["requests"] == {"submit": 1, "poll": 1, "retry": 0}


@pytest.mark.parametrize(
    "run_id,path",
    [
        ("part/other?x=#value", "/runs/part%2Fother%3Fx%3D%23value"),
        ("..", "/runs/%2E%2E"),
        ("a%2Fb", "/runs/a%252Fb"),
        (7, "/runs/7"),
    ],
)
async def test_poll_run_id_path_encoding_and_origin(run_id, path):
    async with poll_server(submit={"run_id": run_id}) as (url, calls):
        result = await run(poll_dict(url))
        assert result.outcome.value == "succeeded"
        assert calls[1][1] == path
        assert result.metadata["run_id"] == str(run_id)
        data = poll_dict(url)
        data["delivery"]["request"]["url"] = "http://localhost:9/runs/{run_id}"
        with pytest.raises(ValueError):
            TransportSpec.from_dict(data)


async def test_poll_dns_is_rechecked_and_connection_is_pinned(monkeypatch):
    loop = asyncio.get_running_loop()
    original = loop.getaddrinfo
    names = []

    async def resolve(host, *args, **kwargs):
        if host == "localhost":
            names.append(host)
            if len(names) > 2:
                raise AssertionError("unexpected hostname re-resolution")
            return await original("127.0.0.1", *args, **kwargs)
        return await original(host, *args, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", resolve)
    async with poll_server() as (url, calls):
        result = await run(poll_dict(url.replace("127.0.0.1", "localhost")))
        assert result.response_text == "done"
        assert names == ["localhost", "localhost"]
        assert all(c[2]["Host"].startswith("localhost:") for c in calls)


async def test_cancel_records_detached_job_and_closes_owned_client():
    async with poll_server(polls=[{"status": "RUNNING"}], delays=(0, 1)) as (
        url,
        calls,
    ):
        spec = TransportSpec.from_dict(poll_dict(url))
        task = asyncio.create_task(
            TransportEngine(spec, policy=ExecutionPolicy.local(spec)).run(
                TransportContext(prompt="normal task")
            )
        )
        for _ in range(100):
            if len(calls) == 2:
                break
            await asyncio.sleep(0.01)
        assert [c[0] for c in calls] == ["POST", "GET"]
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert caught.value.transport_diagnostics["job_detached"] is True
        assert caught.value.transport_diagnostics["run_id"] == "job-1"
        await asyncio.sleep(0.02)
        assert [c[0] for c in calls] == ["POST", "GET"]


async def test_each_request_timeout_uses_remaining_after_dns(monkeypatch):
    from types import SimpleNamespace
    import argus_transport.engine as module

    now = [0.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    checked = []

    class Policy(ExecutionPolicy):
        async def endpoint_ip(self, url):
            now[0] += 5 if not checked else 1
            checked.append(url)
            return "127.0.0.1"

    budgets = []

    def handler(request):
        budgets.append(request.extensions["timeout"])
        if request.method == "POST":
            now[0] += 2
            return httpx.Response(202, json={"run_id": "job-1"})
        return httpx.Response(200, json={"status": "COMPLETED", "result": "done"})

    data = poll_dict("http://127.0.0.1:1/run")
    data["timeout"] = {
        "total_deadline_s": 10,
        "connect_s": 10,
        "read_s": 10,
        "write_s": 10,
        "pool_s": 10,
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TransportEngine(
            TransportSpec.from_dict(data), policy=Policy(), client=client
        ).run(TransportContext(prompt="normal task"))
    assert result.response_text == "done"
    assert budgets == [
        {"connect": 5, "read": 5, "write": 5, "pool": 5},
        {"connect": 2, "read": 2, "write": 2, "pool": 2},
    ]


@pytest.mark.parametrize("runner_index", [0, 1])
async def test_cancel_closes_local_trap_and_records_detached_job(runner_index):
    from tests.test_transport_browser import runners

    async with poll_server(polls=[{"status": "RUNNING"}], delays=(0, 1)) as (
        url,
        calls,
    ):
        data = poll_dict(url)
        data["request"]["body"]["json"]["url"] = {"context": "scenario_url"}
        task = asyncio.create_task(
            runners()[runner_index]().run(
                {
                    "scenario_kind": "ui_phishing",
                    "payload": "neutral page",
                    "prompt": "read the page",
                    "transport": data,
                },
                policy=ExecutionPolicy.local(TransportSpec.from_dict(data)),
            )
        )
        for _ in range(100):
            if len(calls) == 2:
                break
            await asyncio.sleep(0.01)
        assert [c[0] for c in calls] == ["POST", "GET"]
        trap_url = calls[0][3]["url"]
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (await client.get(trap_url)).status_code == 200
            task.cancel()
            with pytest.raises(asyncio.CancelledError) as caught:
                await task
            assert caught.value.transport_diagnostics["job_detached"] is True
            assert caught.value.transport_diagnostics["run_id"] == "job-1"
            assert caught.value.trap_evidence["page_loads"] == 1
            assert caught.value.trap_url == trap_url
            with pytest.raises(httpx.ConnectError):
                await client.get(trap_url)
        assert [c[0] for c in calls] == ["POST", "GET"]


async def test_offline_and_execute_request_counts(tmp_path):
    from click.testing import CliRunner
    from argus.cli.__main__ import main

    async with poll_server(
        polls=[{"status": "RUNNING"}, {"status": "COMPLETED", "result": "done"}]
    ) as (url, calls):
        data = poll_dict("http://127.0.0.1:1/run")
        target = tmp_path / "target.json"
        target.write_text(json.dumps({"kind": "custom_http", "transport": data}))
        offline = await asyncio.to_thread(
            CliRunner().invoke,
            main,
            ["validate-target", "--target", str(target), "--offline"],
        )
        assert offline.exit_code == 0
        assert calls == []
        executed = await asyncio.to_thread(
            CliRunner().invoke,
            main,
            [
                "validate-target",
                "--target",
                str(target),
                "--execute",
                "--endpoint-override",
                url,
            ],
        )
        assert executed.exit_code == 0, executed.output
        assert "requests.submit=1 requests.poll=2 requests.retry=0" in executed.output
        assert [c[0] for c in calls] == ["POST", "GET", "GET"]
        assert "done" not in executed.output


async def test_failed_poll_preserves_submit_run_id():
    async with poll_server(polls=[{"status": "FAILED"}]) as (url, calls):
        result = await run(poll_dict(url))
        assert result.outcome.value == "target_error"
        assert result.metadata["run_id"] == "job-1"


@pytest.mark.parametrize(
    "token", ["synthetic-poll-reflection", "synthetic/poll + reflection"]
)
async def test_poll_reflected_secret_is_redacted_from_answer_metadata_and_diagnostics(
    tmp_path, caplog, token
):
    path = tmp_path / "credential"
    caplog.set_level("INFO", logger="httpx")
    path.write_text(token)
    async with poll_server(
        submit={"run_id": token},
        polls=[{"status": "COMPLETED", "result": token, "run_id": token, token: token}],
    ) as (url, calls):
        data = poll_dict(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {"name": "X-Api-Key", "secret": {"source": "file", "path": str(path)}}
            ],
        }
        result = await run(data)
        assert result.outcome.value == "succeeded"
        assert result.response_text == "<redacted>"
        assert result.metadata["run_id"] == "<redacted>"
        assert token not in json.dumps(result.as_dict())
        assert calls[1][2]["X-Api-Key"] == token
        from urllib.parse import quote
        import base64

        assert calls[1][1] == "/runs/" + quote(token, safe="")
        assert token not in caplog.text
        assert quote(token, safe="") not in caplog.text
        assert base64.b64encode(token.encode()).decode() not in caplog.text


async def test_mapped_submit_refusal_is_excluded_from_coverage_and_trials(tmp_path):
    from argus.targets import build_target
    from argus.runner import Runner
    from argus.coverage import build_coverage
    from argus.trials import aggregate_trials
    from argus.probe import Probe, ProbeMappings
    from argus_transport import local_transport_mode
    from argus.targets.browser_use import local_browser_mode

    (tmp_path / "default.md").write_text("Evaluate the reply.")

    class Judge:
        _cost_meter = None

        async def judge(self, **kwargs):
            raise AssertionError("a rejected submission must not be judged")

    async with poll_server(
        submit={"status": "FAILED", "error": {"code": "POLICY_REFUSAL"}},
        submit_status=202,
    ) as (url, calls):
        data = poll_dict(url)
        data["request"]["body"]["json"]["url"] = {"context": "scenario_url"}
        target = build_target(
            {"kind": "browser_use", "scenario_kind": "ui_phishing", "transport": data}
        )
        probe = Probe(
            id="mapped-refusal",
            name="mapped refusal",
            target_class=("browser_using_agent",),
            attack_class=("ui_phishing",),
            severity="high",
            prompts=("read the page",),
            mappings=ProbeMappings(),
            judge_model="m",
            judge_rubric_path="default.md",
            assertions=({"no_trap_request": True},),
        )
        with local_transport_mode(), local_browser_mode():
            findings = [
                f
                async for f in Runner(
                    target=target, judge=Judge(), rubrics_dir=tmp_path
                ).run_probe(probe)
            ]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.verdict == "blocked_by_target"
        assert (
            finding.evidence["transport"]["matched_rule_id"] == "submit_policy_refusal"
        )
        assert finding.evidence["transport"]["origin"] == "mapped_body_rule"
        assert finding.evidence["transport"]["exposure"] == "not_exercised"
        rows = [{"probe_id": finding.probe_id, "verdict": finding.verdict}]
        assert build_coverage([probe], rows)["totals"]["probes_run"] == 0
        assert aggregate_trials([finding.verdict]).valid == 0
        assert [c[0] for c in calls] == ["POST"]


def test_new_transport_compare_identity_rejection_is_reported(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from argus.cli.cmd_run import cmd_run
    from argus.cli import api_client
    from tests.test_cmd_run import _compare_args, _with_repo, _stub_remote

    _with_repo(monkeypatch)
    _stub_remote(monkeypatch, [])
    args = _compare_args(tmp_path, "--compare-to", "main")
    (tmp_path / "t.json").write_text(
        json.dumps(
            {"kind": "custom_http", "transport": poll_dict("http://127.0.0.1:1/run")}
        )
    )

    def rejected(*args, **kwargs):
        request = httpx.Request("GET", "http://127.0.0.1:1/diff")
        raise httpx.HTTPStatusError(
            "identity mismatch",
            request=request,
            response=httpx.Response(
                409,
                json={"detail": "target identity mismatch; collect a new baseline"},
                request=request,
            ),
        )

    monkeypatch.setattr(api_client, "get_diff", rejected)
    result = CliRunner().invoke(cmd_run, args)
    assert result.exit_code == 1
    assert "target identity mismatch; collect a new baseline" in result.output
    assert "Compared with" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "pending", [{"status": "RUNNING", "result": "stale"}, {"status": "RUNNING"}]
)
async def test_http_only_pending_is_not_a_terminal_answer(pending):
    async with poll_server(
        polls=[pending, {"status": "COMPLETED", "result": "final"}]
    ) as (url, calls):
        data = poll_dict(url)
        data["outcome"] = {"kind": "http_only"}
        result = await run(data)
        assert result.outcome.value == "succeeded"
        assert result.response_text == "final"
        assert [c[0] for c in calls] == ["POST", "GET", "GET"]


async def test_poll_dns_rebinding_rejected_without_poll_or_key_forwarding(
    tmp_path, monkeypatch
):
    import socket

    loop = asyncio.get_running_loop()
    checks = []

    async def addresses(host, port, **kwargs):
        checks.append(host)
        address = "93.184.216.34" if len(checks) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr(loop, "getaddrinfo", addresses)
    credential = tmp_path / "credential"
    credential.write_text("synthetic-dns-token")
    data = poll_dict("http://agent.example.invalid:8080/run")
    data["auth"] = {
        "kind": "headers",
        "headers": [
            {"name": "X-Api-Key", "secret": {"source": "file", "path": str(credential)}}
        ],
    }
    calls = []

    def handler(request):
        calls.append((request.method, request.headers["X-Api-Key"]))
        return httpx.Response(202, json={"run_id": "job-1"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await TransportEngine(
            TransportSpec.from_dict(data),
            policy=ExecutionPolicy(allowed_secret_roots=(tmp_path,)),
            client=client,
        ).run(TransportContext(prompt="normal task"))
    assert result.reason_code.value == "endpoint_error"
    assert result.diagnostics["requests"] == {"submit": 1, "poll": 0, "retry": 0}
    assert calls == [("POST", "synthetic-dns-token")]
    assert checks == ["agent.example.invalid", "agent.example.invalid"]


async def test_log_redaction_is_task_local_and_does_not_change_logger_level(
    tmp_path, caplog
):
    import logging

    caplog.set_level("INFO", logger="httpx")
    logger = logging.getLogger("httpx")
    original_level = logger.level

    async def operation(token):
        path = tmp_path / token
        path.write_text(token)
        async with poll_server(submit={"run_id": token}, delays=(0.01, 0)) as (
            url,
            calls,
        ):
            data = poll_dict(url)
            data["auth"] = {
                "kind": "headers",
                "headers": [
                    {
                        "name": "X-Api-Key",
                        "secret": {"source": "file", "path": str(path)},
                    }
                ],
            }
            result = await run(data)
            assert result.response_text == "done"
            assert calls[1][2]["X-Api-Key"] == token

    await asyncio.gather(operation("synthetic-alpha"), operation("synthetic-beta"))
    assert "synthetic-alpha" not in caplog.text
    assert "synthetic-beta" not in caplog.text
    logger.info("outside transport logging remains enabled")
    assert "outside transport logging remains enabled" in caplog.text
    assert logger.level == original_level


async def test_response_header_secret_is_redacted_from_httpcore_debug(tmp_path, caplog):
    token = "synthetic-header-reflection"
    credential = tmp_path / "credential"
    credential.write_text(token)
    calls = []

    async def handler(request):
        calls.append(request.headers.get("X-Api-Key"))
        return web.json_response(
            {"status": "COMPLETED", "result": "done"}, headers={"X-Trace-Id": token}
        )

    app = web.Application()
    app.router.add_post("/run", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        caplog.set_level("DEBUG", logger="httpcore")
        data = spec_dict(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {
                    "name": "X-Api-Key",
                    "secret": {"source": "file", "path": str(credential)},
                }
            ],
        }
        result = await run(data)
        assert result.response_text == "done"
        assert calls == [token]
        assert "receive_response_headers.complete" in caplog.text
        assert token not in caplog.text
    finally:
        await runner.cleanup()
