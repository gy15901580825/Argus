import asyncio
import json

import pytest
from aiohttp import web
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.cli.baseline_key import baseline_key
from argus.cli.target_loader import check_target_spec
from argus.targets import build_target
from argus.targets._base import Turn


def transport(url):
    return {
        "version": 1,
        "request": {
            "method": "POST",
            "url": url,
            "headers": {},
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
                    "id": "policy",
                    "priority": 100,
                    "http_status": [200],
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
        "timeout": {"total_deadline_s": 3, "read_s": 3},
        "session": {"mode": "none"},
        "limits": {},
    }


@pytest.fixture
async def hosted_agent():
    state = {
        "body": {"status": "COMPLETED", "result": {"result": "answer"}},
        "requests": [],
    }

    async def respond(request):
        state["requests"].append(await request.json())
        return web.json_response(state["body"])

    app = web.Application()
    app.router.add_post("/run", respond)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    state["url"] = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        yield state
    finally:
        await runner.cleanup()


async def test_custom_http_uses_shared_transport_and_goal(hosted_agent):
    target = build_target(
        {"kind": "custom_http", "transport": transport(hosted_agent["url"])}
    )
    from argus_transport import local_transport_mode

    with local_transport_mode():
        text, latency = await target.send_prompt('say "hello"')
    assert text == "answer"
    assert latency >= 0
    assert hosted_agent["requests"] == [{"goal": 'say "hello"'}]
    assert target.supports_history is False


def test_new_transport_rejects_legacy_fields_and_scenario_binding():
    spec = {"kind": "custom_http", "transport": transport("https://agent.example/run")}
    with pytest.raises(ValueError, match="conflict"):
        build_target({**spec, "request_url": "https://agent.example/old"})
    spec["transport"]["request"]["body"]["json"]["url"] = {"context": "scenario_url"}
    with pytest.raises(ValueError, match="scenario_url"):
        build_target(spec)


def test_transport_reference_names_are_not_env_expanded(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "argus.cli.target_loader.os.path.expandvars",
        lambda value: calls.append(value) or "expanded",
    )
    raw = {"kind": "custom_http", "transport": transport("https://agent.example/run")}
    raw["transport"]["auth"] = {
        "kind": "headers",
        "headers": [
            {"name": "X-Api-Key", "secret": {"source": "env", "name": "SYNTHETIC_KEY"}}
        ],
    }
    parsed, values = check_target_spec(raw)
    assert parsed["transport"] == raw["transport"]
    assert values == []
    assert "SYNTHETIC_KEY" not in calls


async def test_failed_200_ignores_nonempty_result(hosted_agent, tmp_path):
    from argus.probe import Probe, ProbeMappings
    from argus.runner import Runner
    from argus_transport import local_transport_mode

    hosted_agent["body"] = {"status": "FAILED", "result": "not an answer"}
    target = build_target(
        {"kind": "custom_http", "transport": transport(hosted_agent["url"])}
    )
    (tmp_path / "default.md").write_text("Evaluate the reply.")

    class Judge:
        _cost_meter = None
        calls = 0

        async def judge(self, **kwargs):
            self.calls += 1
            raise AssertionError("failed target results cannot be judged")

    judge = Judge()
    probe = Probe(
        id="failed-status",
        name="status",
        target_class=("llm_chat",),
        attack_class=("test",),
        severity="high",
        prompts=("hello",),
        mappings=ProbeMappings(),
        judge_model="m",
        judge_rubric_path="default.md",
    )
    with local_transport_mode():
        findings = [
            f
            async for f in Runner(
                target=target, judge=judge, rubrics_dir=tmp_path
            ).run_probe(probe)
        ]
    assert len(findings) == 1
    assert findings[0].verdict == "error"
    assert judge.calls == 0
    assert findings[0].target_response == ""
    assert findings[0].evidence["transport"]["outcome"] == "target_error"
    assert findings[0].evidence["transport"]["matched_rule_id"] == "failed"
    assert hosted_agent["requests"] == [{"goal": "hello"}]


async def test_server_session_first_and_second_turn(hosted_agent):
    from argus_transport import local_transport_mode

    config = transport(hosted_agent["url"])
    config["session"] = {"mode": "server_returned", "id_path": "$.session_id"}
    config["request"]["body"]["json"]["session"] = {
        "context": "session_id",
        "missing": "omit",
    }
    hosted_agent["body"]["session_id"] = "server-session-1"
    target = build_target({"kind": "custom_http", "transport": config})
    with local_transport_mode():
        await target.send_prompt("first")
        await target.send_prompt(
            "second", (Turn("user", "first"), Turn("assistant", "answer"))
        )
        await target.begin_probe(None)
        await target.send_prompt("third")
    assert hosted_agent["requests"] == [
        {"goal": "first"},
        {"goal": "second", "session": "server-session-1"},
        {"goal": "third"},
    ]
    assert target.supports_history is True


async def test_offline_and_execute_request_counts(tmp_path, hosted_agent):
    target_file = tmp_path / "target.json"
    raw = {"kind": "custom_http", "transport": transport(hosted_agent["url"])}
    target_file.write_text(json.dumps(raw))
    invoke = lambda flags: CliRunner().invoke(
        main, ["validate-target", "--target", str(target_file), *flags]
    )
    offline = await asyncio.to_thread(invoke, ["--offline"])
    assert offline.exit_code == 0, offline.output
    assert "requests.submit=0" in offline.output
    assert '"goal"' in offline.output and '"context": "prompt"' in offline.output
    assert hosted_agent["requests"] == []
    executed = await asyncio.to_thread(invoke, ["--execute"])
    assert executed.exit_code == 0, executed.output
    assert "requests.submit=1" in executed.output
    assert hosted_agent["requests"] == [{"goal": "ping"}]
    assert "answer" not in executed.output


async def test_execute_missing_secret_reports_zero_requests(tmp_path, hosted_agent):
    config = transport(hosted_agent["url"])
    config["auth"] = {
        "kind": "headers",
        "headers": [
            {
                "name": "X-Api-Key",
                "secret": {"source": "file", "path": str(tmp_path / "missing")},
            }
        ],
    }
    target_file = tmp_path / "target.json"
    target_file.write_text(json.dumps({"kind": "custom_http", "transport": config}))
    result = await asyncio.to_thread(
        CliRunner().invoke,
        main,
        ["validate-target", "--target", str(target_file), "--execute"],
    )
    assert result.exit_code != 0
    assert "requests.submit=0 requests.poll=0 requests.retry=0" in result.output
    assert hosted_agent["requests"] == []


def test_validate_missing_path_safe_diagnostic(tmp_path):
    target_file = tmp_path / "target.json"
    target_file.write_text(
        json.dumps(
            {"kind": "custom_http", "transport": transport("https://agent.example/run")}
        )
    )
    sample = tmp_path / "sample.json"
    sample.write_text(
        json.dumps({"status": "COMPLETED", "output": "private returned content"})
    )
    result = CliRunner().invoke(
        main,
        [
            "validate-target",
            "--target",
            str(target_file),
            "--offline",
            "--sample-response",
            str(sample),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "$.result.result" in result.output and "$.result" in result.output
    assert "status" in result.output and "output" in result.output
    assert "private returned content" not in result.output
    assert "target_error" in result.output


def test_baseline_identity_legacy_preserved_and_new_spec_requires_rebaseline(tmp_path):
    legacy = {
        "kind": "custom_http",
        "request_url": "https://agent.example/run",
        "request_body_template": '{"goal": {{prompt|tojson}}}',
        "response_jsonpath": "$.result",
    }
    expected = baseline_key(legacy)
    parsed, _ = check_target_spec(legacy)
    assert baseline_key(parsed) == expected
    target_file = tmp_path / "legacy.json"
    target_file.write_text(json.dumps(legacy))
    result = CliRunner().invoke(
        main, ["validate-target", "--target", str(target_file), "--offline"]
    )
    assert result.exit_code == 0, result.output
    assert "rebaseline" in result.output
    assert expected in result.output
    new = {"kind": "custom_http", "transport": transport("https://agent.example/run")}
    assert baseline_key(new) != expected


async def test_metadata_paths_and_target_run_log_preserved(hosted_agent):
    from argus_transport import local_transport_mode

    config = transport(hosted_agent["url"])
    config["response"]["metadata"] = {
        "session_id": {"path": "$.session_id"},
        "run_id": {"path": "$.run_id"},
        "run_log": {"path": "$.run_log"},
    }
    hosted_agent["body"].update(
        session_id="session",
        run_id="target-run",
        run_log={
            "is_dry_run": True,
            "events": [{"operation": "read", "status": "intent"}],
        },
    )
    target = build_target({"kind": "custom_http", "transport": config})
    with local_transport_mode():
        assert (await target.send_prompt("task"))[0] == "answer"
    log = target.last_run_log()
    assert log.session_id == "session" and log.run_id == "target-run"
    assert log.is_dry_run is True
    assert log.events[0]["operation"] == "read"
    await target.begin_probe(None)
    assert target.last_run_log() is None


async def test_invalid_run_log_is_a_mapping_error_finding(hosted_agent, tmp_path):
    from argus_transport import local_transport_mode
    from argus.probe import Probe, ProbeMappings
    from argus.runner import Runner

    (tmp_path / "default.md").write_text("Evaluate the reply.")
    config = transport(hosted_agent["url"])
    config["response"]["metadata"] = {"run_log": {"path": "$.run_log"}}
    hosted_agent["body"]["run_log"] = ["invalid-event"]
    target = build_target({"kind": "custom_http", "transport": config})

    class Judge:
        _cost_meter = None

        async def judge(self, **kwargs):
            raise AssertionError("invalid metadata must not reach the judge")

    probe = Probe(
        id="metadata-check",
        name="metadata",
        target_class=("llm_chat",),
        attack_class=("test",),
        severity="high",
        prompts=("task",),
        mappings=ProbeMappings(),
        judge_model="m",
        judge_rubric_path="default.md",
    )
    with local_transport_mode():
        findings = [
            f
            async for f in Runner(
                target=target, judge=Judge(), rubrics_dir=tmp_path
            ).run_probe(probe)
        ]
    assert len(findings) == 1
    assert findings[0].verdict == "error"
    assert "mapping_error" in findings[0].reasoning
    assert "invalid-event" not in findings[0].reasoning


def test_legacy_normalization_and_conflicting_fields():
    legacy = {
        "kind": "custom_http",
        "request_url": "https://agent.example/run",
        "request_body_template": "{}",
        "response_jsonpath": "$.result",
    }
    target = build_target(legacy)
    assert target.spec.timeout_s == 120.0
    assert target.spec.request_method == "POST"
    assert target.supports_history is True
    for key, value in [
        ("timeout_s", 120.0),
        ("request_method", "POST"),
        ("api_key", None),
    ]:
        with pytest.raises(ValueError, match="conflict"):
            build_target(
                {
                    "kind": "custom_http",
                    "transport": transport(legacy["request_url"]),
                    key: value,
                }
            )


def test_validate_rejects_invalid_run_log_sample(tmp_path):
    config = transport("https://agent.example/run")
    config["response"]["metadata"] = {"run_log": {"path": "$.run_log"}}
    target_file = tmp_path / "target.json"
    target_file.write_text(json.dumps({"kind": "custom_http", "transport": config}))
    sample = tmp_path / "sample.json"
    sample.write_text(
        json.dumps({"status": "COMPLETED", "result": "answer", "run_log": ["invalid"]})
    )
    result = CliRunner().invoke(
        main,
        [
            "validate-target",
            "--target",
            str(target_file),
            "--offline",
            "--sample-response",
            str(sample),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "mapping_error" in result.output
    assert "requests.submit=0" in result.output
