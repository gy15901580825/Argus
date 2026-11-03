import json
from dataclasses import replace

import pytest
from aiohttp import web
from click.testing import CliRunner

from argus import api, local
from argus.cli.__main__ import main
from argus.probe import load_probe_library
from test_transport_lifecycle import lifecycle_dict, recording_lifecycle
from transport_v2_fakes import RecordingApp, serve_in_thread


@pytest.fixture
def stop_library(monkeypatch):
    base = load_probe_library(api.PROBES_DIR)[0]
    probes = [
        replace(
            base, id=f"local_stop_{index}", target_class=("llm_chat",),
            prompts=("normal",),
            assertions=({"no_call_to_tool": "unused"},),
            judge_when_assertions_pass=False, conversation=False,
            requires_interaction=False,
        )
        for index in range(3)
    ]
    monkeypatch.setattr(api, "load_probe_library", lambda *_: probes)
    monkeypatch.setattr(local, "load_probe_library", lambda *_: probes)
    monkeypatch.setattr(api, "Judge", lambda **_: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-not-a-key")
    return probes


def invoke_run(tmp_path, data, probes):
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"kind": "custom_http", "transport": data}))
    out = tmp_path / "run.json"
    result = CliRunner().invoke(main, [
        "run", "--local", "--target", str(target), "--probes",
        ",".join(probe.id for probe in probes), "--format", "json", "--out", str(out),
    ])
    assert result.exit_code == 1, result.output
    assert out.is_file()
    return result, json.loads(out.read_text()), out.read_text()


def assert_target_stop(result, record):
    assert record["status"] == "incomplete"
    assert "target stopped the run: stop_on_status" in record["incomplete_reason"]
    assert "Target stopped the run: stop_on_status. No further request was sent, cleanup included." in result.stderr
    assert record["target_cleanup"]["stop_reason"] == "stop_on_status"
    assert record["target_cleanup"]["complete"] is False


def test_target_stop_renders_incomplete_with_cleanup_pending_and_exit_1(tmp_path, stop_library):
    submitted = 0
    app = RecordingApp()

    async def created(request):
        return web.json_response({"id": "source-one"}, status=201)

    async def submit(request):
        nonlocal submitted
        submitted += 1
        if submitted == 2:
            return web.Response(status=429)
        return web.json_response({"status": "COMPLETED", "result": "done"})

    app.route("POST", "/v1/sources", created)
    app.route("POST", "/run", submit)
    with serve_in_thread(app) as origin:
        result, record, _ = invoke_run(tmp_path, lifecycle_dict(origin, attempt=False), stop_library)
        assert_target_stop(result, record)
        assert [(item["probe_id"], item["verdict"]) for item in record["findings"]] == [(stop_library[0].id, "pass")]
        assert record["summary"]["total"] == 1
        assert record["target_cleanup"]["open"][0]["step"] == "source"
        assert record["target_cleanup"]["open"][0]["status"] == "skipped_stopped"
        assert f"[ ] DELETE {origin}/v1/sources/source-one" in result.stderr
        assert [(method, path) for method, path, _, _ in app.calls] == [
            ("POST", "/v1/sources"), ("POST", "/run"), ("POST", "/run"),
        ]


def test_429_on_first_request_writes_incomplete_report_with_zero_findings(tmp_path, stop_library):
    async def stopped(request):
        return web.Response(status=429)

    app = RecordingApp()
    app.route("POST", "/v1/sources", stopped)
    with serve_in_thread(app) as origin:
        result, record, _ = invoke_run(tmp_path, lifecycle_dict(origin, attempt=False), stop_library)
        assert_target_stop(result, record)
        assert record["findings"] == []
        assert record["summary"]["total"] == 0
        assert [(method, path) for method, path, _, _ in app.calls] == [("POST", "/v1/sources")]


def test_cleanup_lines_redact_secret_values_in_undo_urls(tmp_path, stop_library, monkeypatch):
    monkeypatch.setenv("DUMMY_ACCESS", "dummy-private-value")

    async def created(request):
        return web.json_response({"id": "dummy-private-value"}, status=201)

    async def stopped(request):
        return web.Response(status=429)

    app = RecordingApp()
    app.route("POST", "/v1/sources", created)
    app.route("POST", "/run", stopped)
    with serve_in_thread(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        data["auth"] = {"kind": "bearer", "secret": {"source": "env", "name": "DUMMY_ACCESS"}}
        data["budget"] = {"stop_on": {"credential_echo": False}}
        result, record, text = invoke_run(tmp_path, data, stop_library)
        assert_target_stop(result, record)
        assert record["findings"] == []
        assert record["target_cleanup"]["open"][0]["url"] == f"{origin}/v1/sources/<redacted>"
        assert f"[ ] DELETE {origin}/v1/sources/<redacted>" in result.stderr
        assert "dummy-private-value" not in result.output + text
        assert [(method, path) for method, path, _, _ in app.calls] == [("POST", "/v1/sources"), ("POST", "/run")]


def test_request_budget_stop_reports_cleanup_enabled_after_actual_delete(tmp_path, stop_library):
    app = recording_lifecycle()
    with serve_in_thread(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        data["budget"] = {"max_requests": 2}
        result, record, _ = invoke_run(tmp_path, data, stop_library)
        assert record["status"] == "incomplete"
        assert "target stopped the run: request_budget" in record["incomplete_reason"]
        assert [(item["probe_id"], item["verdict"]) for item in record["findings"]] == [(stop_library[0].id, "pass")]
        assert record["target_cleanup"] == {"complete": True, "done": 1, "open": [], "stop_reason": "request_budget"}
        assert [(method, path) for method, path, _, _ in app.calls] == [
            ("POST", "/v1/sources"), ("POST", "/run"), ("DELETE", "/v1/sources/source-one"),
        ]
        assert "Target stopped the run: request_budget. Configured cleanup remained enabled." in result.stderr
        assert "No further request was sent, cleanup included." not in result.stderr
