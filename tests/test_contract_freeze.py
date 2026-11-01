"""Frozen contracts other tools build against. Changing any value here is a breaking change:
run.json needs a new schema_version, and plugins or servers need a coordinated release."""

import dataclasses
import json
from types import SimpleNamespace

import httpx
import respx
from click.testing import CliRunner

from argus import coverage, probe, runner, targets
from argus.cli import api_client, run_json, severity
from argus.cli.__main__ import main
from argus.targets._base import Target

RUN_JSON_KEYS = ["schema_version", "id", "status", "started_at", "finished_at",
                 "argus_version", "target_spec", "coverage", "summary", "findings"]
FINDING_KEYS = ["id", "probe_id", "attack_prompt", "target_response", "target_latency_ms", "probed_at",
                "verdict", "severity", "confidence", "reasoning", "judge_model", "escalated_model",
                "atlas_id", "owasp_id", "owasp_agentic", "nist_id", "eu_ai_act_id", "created_at", "evidence", "remediation"]
API = "https://srv.example"


@dataclasses.dataclass(frozen=True)
class _Spec:
    kind: str


class _Target(Target):
    def __init__(self, spec: _Spec):
        self.spec = spec

    async def send_prompt(self, prompt, history=()):
        return "ok", 0.0


def test_run_json_schema_and_key_order():
    run = {"id": "r", "status": "completed", "started_at": "s", "finished_at": "f",
           "target_spec": {"kind": "openai_compat"}, "coverage": None, "findings": []}
    out = json.loads(run_json.render_json(run))
    assert list(out) == RUN_JSON_KEYS
    assert out["schema_version"] == run_json.SCHEMA_VERSION == "argus.run/1"


def test_finding_keys_and_order():
    assert [f.name for f in dataclasses.fields(runner.Finding)] == FINDING_KEYS


def test_verdict_and_severity_values():
    verdicts = {runner.VERDICT_PASS, runner.VERDICT_FAIL, runner.VERDICT_ERROR, runner.VERDICT_BLOCKED_BY_TARGET,
                runner.VERDICT_SKIPPED, runner.VERDICT_ABORTED}
    assert verdicts == {"pass", "fail", "error", "blocked_by_target", "skipped", "aborted_cost"}
    assert runner.VERDICT_WARN == "warn"
    assert coverage._TESTED_VERDICTS == {"pass", "fail", "warn"}
    assert severity.SEVERITY_ORDER == ("info", "low", "medium", "high", "critical")
    assert probe.VALID_SEVERITIES == set(severity.SEVERITY_ORDER)
    assert set(coverage.SUMMARY_VERDICTS) == verdicts | {runner.VERDICT_WARN}
    assert coverage.SUMMARY_SEVERITIES == severity.SEVERITY_ORDER


def test_entry_point_group_names():
    assert targets.ENTRY_POINT_GROUP == "argus.targets"
    assert probe.PROBE_PACK_GROUP == "argus.probe_packs"


def test_target_plugin_is_a_spec_class_target_class_tuple(monkeypatch):
    ep = SimpleNamespace(name="frozen_kind", value="x:y", load=lambda: (_Spec, _Target))
    monkeypatch.setattr(targets, "entry_points",
                        lambda *, group: [ep] if group == "argus.targets" else [])
    targets._plugin_builders.cache_clear()
    try:
        t = targets.build_target({"kind": "frozen_kind"})
    finally:
        targets._plugin_builders.cache_clear()
    assert isinstance(t, _Target) and t.spec == _Spec(kind="frozen_kind")


@respx.mock
def test_server_mode_paths():
    hdr = {"x-api-token": "t"}
    routes = [
        respx.post(f"{API}/api/v1/redteam/runs", headers=hdr).mock(httpx.Response(200, json={"run_id": "r1"})),
        respx.get(f"{API}/api/v1/redteam/runs/r1", headers=hdr).mock(httpx.Response(200, json={"status": "completed"})),
        respx.get(f"{API}/api/v1/redteam/runs/r1/report", params={"format": "sarif"}, headers=hdr)
             .mock(httpx.Response(200, text="R")),
        respx.get(f"{API}/api/v1/redteam/probes", headers=hdr).mock(httpx.Response(200, json={"probe_ids": ["a"]})),
        respx.get(f"{API}/api/v1/redteam/coverage", headers=hdr).mock(httpx.Response(200, json={"coverage": {"c": 1}})),
        respx.get(f"{API}/api/v1/redteam/runs/r1/diff", params={"base": "main"}, headers=hdr)
             .mock(httpx.Response(200, json={"new": []})),
    ]
    assert api_client.post_run(API, "t", {"x": 1}) == {"run_id": "r1"}
    assert api_client.get_run(API, "t", "r1") == {"status": "completed"}
    assert api_client.get_report(API, "t", "r1", "sarif") == "R"
    assert api_client.list_probes(API, "t") == ["a"]
    assert api_client.get_coverage(API, "t") == {"c": 1}
    assert api_client.get_diff(API, "t", "r1", "main") == {"new": []}
    assert all(r.call_count == 1 for r in routes)


def test_server_mode_run_payload(tmp_path, monkeypatch):
    seen = {}

    def post_run(api_url, token, body):
        seen.update(body)
        return {"run_id": "r1"}

    monkeypatch.setattr(api_client, "post_run", post_run)
    monkeypatch.setattr(api_client, "poll_until_complete", lambda *a, **k: {"status": "completed", "findings": []})
    monkeypatch.setattr(api_client, "get_report", lambda *a, **k: "<html/>")
    monkeypatch.setattr("argus.cli.cmd_run.git_context.detect",
                        lambda: {"repo": "o/r", "branch": "b", "commit": "c"})
    spec = {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"}
    result = CliRunner().invoke(main, ["run", "--target", json.dumps(spec), "--probes", "p1",
                                       "--per-run-cap", "2", "--out", str(tmp_path / "r.html"),
                                       "--token", "t", "--api-url", API])
    assert result.exit_code == 0, result.output
    assert list(seen) == ["target", "probe_ids", "per_run_cap_usd", "repo", "branch", "commit", "baseline_key"]
    assert seen["target"] == spec and seen["probe_ids"] == ["p1"] and seen["per_run_cap_usd"] == 2.0
