"""The vllm_server adapter and its version probe: one GET /version, matched against the vLLM advisories."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchestrator.redteam.assertions import evaluate_assertions
from orchestrator.redteam.probe import load_probe
from orchestrator.redteam.runner import Runner
from orchestrator.redteam.targets import build_target

PROBE = Path(__file__).resolve().parents[1] / "orchestrator" / "redteam" / "probes" / "vllm_server" \
    / "vllm_server_known_vulnerable_version.yaml"


def _server(version, log=None, status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        if log is not None:
            log.append(req)
        if req.url.path != "/version":
            return httpx.Response(404)
        return httpx.Response(status, json={"version": version} if version is not None else {})
    return httpx.MockTransport(handler)


def _target(transport, url="http://10.0.0.5:8000/", headers=()):
    t = build_target({"kind": "vllm_server", "url": url, "headers": list(headers)})
    t._transport = transport
    return t


async def _evidence(transport, **kw):
    t = _target(transport, **kw)
    await t.send_prompt("ignored")
    return await t.collect_evidence()


def _check(version):
    (r,) = evaluate_assertions(({"vllm_no_known_vulnerable_version": True},), {"server_version": version}, "")
    return r


def test_url_is_required():
    with pytest.raises(ValueError, match="url"):
        build_target({"kind": "vllm_server", "url": ""})


@pytest.mark.asyncio
async def test_sends_one_get_to_version_with_the_configured_headers():
    log: list[httpx.Request] = []
    ev = await _evidence(_server("0.25.0", log), headers=[("Authorization", "Bearer k")])
    assert [(r.method, r.url.path) for r in log] == [("GET", "/version")]
    assert log[0].headers["authorization"] == "Bearer k"
    assert ev["server_version"] == "0.25.0" and ev["interaction_count"] == 1


@pytest.mark.parametrize("version,hits", [
    ("0.25.0", ["GHSA-w9hx-wr9v-56wv", "GHSA-6vc9-vh4h-cxh4", "GHSA-v8gv-gxpf-cg62"]),
    ("0.10.2", ["GHSA-p9gm-63qh-x2pq", "GHSA-v8gv-gxpf-cg62"]),
    ("0.30.1", ["GHSA-6vc9-vh4h-cxh4", "GHSA-v8gv-gxpf-cg62"]),
])
def test_affected_versions_name_every_matching_advisory(version, hits):
    r = _check(version)
    assert not r.passed
    assert sorted(g for g in ("GHSA-p9gm-63qh-x2pq", "GHSA-w9hx-wr9v-56wv", "GHSA-6vc9-vh4h-cxh4",
                              "GHSA-v8gv-gxpf-cg62") if g in r.reason) == sorted(hits)


@pytest.mark.parametrize("version", ["0.31.0", "0.31.0+cu128", "1.0.0", "0.8.4"])
def test_versions_outside_every_range_pass(version):
    assert _check(version).passed


@pytest.mark.parametrize("version", ["0.30.0rc1", "0.11.1.dev12+gabc", "dev"])
def test_unparseable_version_fails_closed(version):
    r = _check(version)
    assert not r.passed and "does not parse" in r.reason


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", [
    _server(None), _server("0.31.0", status=401),
    httpx.MockTransport(lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))),
])
async def test_unidentified_server_fails_closed(transport):
    ev = await _evidence(transport)
    assert ev["server_version"] is None and ev["errors"]
    r = _check(ev["server_version"])
    assert not r.passed and "cannot be identified" in r.reason


class _NoJudge:
    async def judge(self, **kw):
        raise AssertionError("the assertion decides this probe")


@pytest.mark.asyncio
@pytest.mark.parametrize("version,want", [("0.25.0", "fail"), ("0.31.0", "pass")])
async def test_shipped_probe_end_to_end(tmp_path, version, want):
    runner = Runner(target=_target(_server(version)), judge=_NoJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(load_probe(PROBE))]
    assert [f.verdict for f in findings] == [want]


@pytest.mark.asyncio
async def test_unreachable_server_is_an_error_not_a_pass(tmp_path):
    def refuse(req):
        raise httpx.ConnectError("refused")
    runner = Runner(target=_target(httpx.MockTransport(refuse)), judge=_NoJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(load_probe(PROBE))]
    assert [f.verdict for f in findings] == ["error"]
