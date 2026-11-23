"""Offline re-rendering through the real CLI and loopback scan engine."""

import json
import re
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET

import pytest
from click.testing import CliRunner

from argus import api, local
from argus.cli.__main__ import main
from argus.cli.run_json import render_json
from argus.probe import load_probe_library


@pytest.fixture
def loopback_target(monkeypatch):
    probe = replace(
        load_probe_library(api.PROBES_DIR)[0], id="offline_probe", severity="high",
        target_class=("llm_chat",), prompts=("check",),
        assertions=({"no_secret_in_response": "LEAK"},),
        judge_when_assertions_pass=False, conversation=False,
        requires_interaction=False, trials=1,
    )
    monkeypatch.setattr(api, "load_probe_library", lambda *_: [probe])
    monkeypatch.setattr(local, "load_probe_library", lambda *_: [probe])
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    state = {"requests": 0, "reply": "safe", "secret": "offline-secret-123"}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            state["requests"] += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {
                "content": state["reply"] + " " + state["secret"],
            }}]}).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["spec"] = {"kind": "openai_compat", "model": "test-model",
                     "api_key": state["secret"],
                     "endpoint_url": f"http://127.0.0.1:{server.server_port}/chat"}
    state["server"] = server
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def normalize_report(text, report_format):
    # Independent scans differ in run.id (HTML and JUnit suite name),
    # started_at/finished_at (SARIF invocation), and target_latency_ms
    # (HTML latency and JUnit testcase time), and probed_at (HTML).
    # No finding content or verdict is excluded.
    if report_format == "sarif":
        report = json.loads(text)
        for invocation in report["runs"][0]["invocations"]:
            invocation.pop("startTimeUtc")
            invocation.pop("endTimeUtc")
        return report
    if report_format == "junit":
        report = ET.fromstring(text)
        report.find("testsuite").set("name", "redteam-run-ID")
        for case in report.iter("testcase"):
            case.set("time", "LATENCY")
        return ET.tostring(report)
    text = re.sub(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", "RUN-ID", text)
    text = re.sub(r"latency: \d+ms", "latency: LATENCY", text)
    text = re.sub(r"probed at [^<]+", "probed at TIMESTAMP", text)
    return re.sub(r"(Run )[0-9a-f]{8}", r"\1ID", text)


@pytest.mark.parametrize("report_format,extension", [("html", "html"), ("sarif", "sarif"), ("junit", "xml")])
@pytest.mark.parametrize("reply,verdict", [("safe", "pass"), ("LEAK", "fail")])
def test_report_from_matches_direct_scan(tmp_path, loopback_target, report_format, extension, reply, verdict):
    target = loopback_target
    target["reply"] = reply
    runner = CliRunner()
    record_path = tmp_path / "run.json"
    direct_path = tmp_path / f"direct.{extension}"
    args = ["run", "--local", "--target", json.dumps(target["spec"]),
            "--probes", "offline_probe", "--seed", "offline-parity"]
    for fmt, path in [("json", record_path), (report_format, direct_path)]:
        result = runner.invoke(main, [*args, "--format", fmt, "--out", str(path)])
        assert result.exit_code == 0, result.output
    record = json.loads(record_path.read_text())
    assert record["findings"][0]["verdict"] == verdict
    assert record["target_spec"]["api_key"] == "***"
    assert record["findings"][0]["target_response"] == reply + " ***"
    assert target["requests"] == 2
    # Turn off the target before re-rendering: no target or server is needed.
    target["server"].shutdown()
    target["server"].server_close()
    rerender_path = tmp_path / f"rerender.{extension}"
    result = runner.invoke(main, ["report", "--from", str(record_path), "--out", str(rerender_path)])
    assert result.exit_code == 0, result.output
    rendered = rerender_path.read_text()
    assert "offline_probe" in rendered
    assert target["secret"] not in rendered
    if verdict == "fail" or report_format == "html":
        assert "***" in rendered
    assert normalize_report(rendered, report_format) == normalize_report(direct_path.read_text(), report_format)
    assert target["requests"] == 2


@pytest.mark.parametrize("contents,message", [
    ("{", "invalid JSON"),
    ("{}", "missing schema_version"),
    ('{"schema_version":"argus.run/999"}', "unsupported schema_version"),
    ('{"schema_version":null}', "unsupported schema_version"),
    ("[]", "must be an object"),
    ('{"schema_version":"argus.run/1"}', "id must be a non-empty string"),
    ('{"schema_version":"argus.run/1","id":"r"}', "status must be a string"),
    ('{"schema_version":"argus.run/1","id":"r","status":"completed"}', "target_spec must be an object"),
    ('{"schema_version":"argus.run/1","id":"r","status":"completed","target_spec":{},"findings":null}',
     "findings must be a list of objects"),
])
def test_report_from_rejects_invalid_record_without_writing(tmp_path, contents, message):
    source = tmp_path / "run.json"
    source.write_text(contents)
    out = tmp_path / "report.html"
    out.write_text("previous report")
    result = CliRunner().invoke(main, ["report", "--from", str(source), "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert message in result.output
    assert "Traceback" not in result.output
    assert out.read_text() == "previous report"


@pytest.mark.parametrize("source_kind", ["missing", "directory", "non_utf8"])
def test_report_from_unreadable_file(tmp_path, source_kind):
    source = tmp_path / "run.json"
    if source_kind == "directory":
        source.mkdir()
    elif source_kind == "non_utf8":
        source.write_bytes(b"\xff")
    out = tmp_path / "report.html"
    result = CliRunner().invoke(main, ["report", "--from", str(source), "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert "cannot read run.json" in result.output
    assert not out.exists()


@pytest.mark.parametrize("source_args", [[], ["--from", "run.json", "--run-id", "server-run"]])
def test_report_requires_exactly_one_source(tmp_path, source_args):
    result = CliRunner().invoke(main, ["report", *source_args, "--out", str(tmp_path / "report.html")])
    assert result.exit_code == 2, result.output
    assert "exactly one of --from or --run-id" in result.output


@pytest.mark.parametrize("missing", ["--token", "--api-url"])
def test_server_report_requires_credentials(tmp_path, missing):
    options = {"--token": "test", "--api-url": "http://127.0.0.1:1"}
    del options[missing]
    args = ["report", "--run-id", "r", "--out", str(tmp_path / "report.html")]
    for option, value in options.items():
        args.extend([option, value])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    assert missing in result.output and "required" in result.output


@pytest.mark.parametrize("status,expected_exit", [("completed", 0), ("incomplete", 1)])
def test_report_from_sarif_uses_status_when_scan_exit_is_not_recorded(tmp_path, status, expected_exit):
    source = tmp_path / "run.json"
    record = json.loads(render_json({"id": "recorded-run", "status": status, "target_spec": {}, "findings": []}))
    record["future_optional_field"] = {"ignore": "this"}
    source.write_text(json.dumps(record))
    out = tmp_path / "report.sarif"
    result = CliRunner().invoke(main, ["report", "--from", str(source), "--format", "sarif", "--out", str(out)])
    assert result.exit_code == 0, result.output
    invocation = json.loads(out.read_text())["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] == (status == "completed")
    assert invocation["exitCode"] == expected_exit
