"""覆盖率的两条出口:离线库级端点,和运行结束时的 SSE 事件。"""

import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from server import app


def test_coverage_endpoint_is_offline_and_library_scoped():
    """它不该跑任何探针 —— 客户要能免费问"你们库里有什么"。"""
    client = TestClient(app)
    resp = client.get("/redteam/coverage")
    assert resp.status_code == 200
    cov = resp.json()["coverage"]
    assert len(cov["standards"]["owasp-llm-top10"]["cells"]) == 10
    # 库级视图:没有任何一格声称跑过
    assert all(c["run_status"] == "not_run"
               for c in cov["standards"]["owasp-llm-top10"]["cells"])
    assert cov["totals"]["probes_run"] == 0


def test_redteam_run_sse_ends_with_coverage_event(monkeypatch):
    """POST /redteam/run 的 SSE 流在最后多发一个 coverage 事件。"""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    request_body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
            "api_key": "sk-test",
        },
        "probe_ids": ["owasp_01_prompt_injection_basic"],
    }

    fake_finding = {
        "id": "00000000-0000-0000-0000-000000000001",
        "probe_id": "owasp_01_prompt_injection_basic",
        "verdict": "pass",
        "severity": "info",
        "atlas_id": ["AML.T0051.000"],
        "owasp_id": ["LLM01"],
        "nist_id": [],
        "eu_ai_act_id": [],
    }

    async def _fake_run(*args, **kwargs):
        yield fake_finding

    with patch("orchestrator.redteam.api._run_probes", _fake_run):
        client = TestClient(app)
        with client.stream("POST", "/redteam/run", json=request_body) as resp:
            assert resp.status_code == 200
            chunks = list(resp.iter_lines())
            # The stream ends with `event: end\ndata: {}`, so the coverage event
            # is the last *payload-bearing* data line, not the last data line.
            data_lines = [c for c in chunks if c.startswith("data: ") and c != "data: {}"]
            last_payload = json.loads(data_lines[-1][len("data: "):])
            assert last_payload["type"] == "coverage"
            assert "standards" in last_payload["coverage"]
