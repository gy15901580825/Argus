"""coverage 必须以 dict 回来,不能是 JSONB 的原始字符串。

也覆盖跨服务的消费者路径: orchestrator 的 SSE 流里混着一个
`{"type": "coverage", ...}` 事件时, api_service 不能把它当成 finding
插库 —— 那张表的 probe_id/verdict 都是 NOT NULL, 之前这条路径完全没有
测试覆盖, 一个成功的 run 会在写完所有 finding 之后被判定为 failed。
"""
import json
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from redteam.runs import decode_run_row


def test_decode_run_row_still_parses_target_spec():
    """Plan 1 已有的行为不能被这次改动弄丢。"""
    row = {"id": "x", "target_spec": json.dumps({"kind": "openai_compat"}), "coverage": None}
    assert decode_run_row(row)["target_spec"]["kind"] == "openai_compat"


def test_decode_run_row_parses_coverage_jsonb():
    row = {"id": "x", "coverage": json.dumps({"totals": {"probes_in_library": 3}})}
    out = decode_run_row(row)
    assert isinstance(out["coverage"], dict)
    assert out["coverage"]["totals"]["probes_in_library"] == 3


def test_decode_run_row_leaves_null_coverage_alone():
    assert decode_run_row({"id": "x", "coverage": None})["coverage"] is None


def test_decode_run_row_survives_corrupt_coverage():
    """坏数据宁可显示成"没有清单",也不能让整张报告 500。"""
    assert decode_run_row({"id": "x", "coverage": "{not json"})["coverage"] is None


@pytest.mark.asyncio
async def test_consume_orchestrator_stream_separates_coverage_event_from_findings():
    """跨服务回归测试:混合流里的 coverage 事件不能被当成 finding 插库,
    也不能被吞掉 —— 必须原样交给 update_run_status(..., coverage=...)。

    修复前: coverage 事件会被 insert_finding 当成 finding, KeyError('probe_id')
    被 _consume_orchestrator_stream 的 except Exception 吞掉, 整次成功的
    run 被打上 status="failed"。
    """
    from redteam import routes

    run_id = uuid4()
    finding = {
        "id": str(uuid4()),
        "probe_id": "owasp_01_prompt_injection_basic",
        "verdict": "pass",
    }
    coverage_payload = {"totals": {"probes_in_library": 3, "probes_run": 1}}

    async def _fake_stream(*args, **kwargs):
        yield finding
        yield {"type": "coverage", "coverage": coverage_payload}

    with patch("redteam.routes.orchestrator_client.stream_findings", _fake_stream), \
         patch("redteam.routes.runs.update_run_status", new=AsyncMock()) as mock_update, \
         patch("redteam.routes.runs.insert_finding", new=AsyncMock()) as mock_insert:
        await routes._consume_orchestrator_stream(run_id, {"kind": "openai_compat"}, ["owasp_01_prompt_injection_basic"])

    # The coverage event must never reach insert_finding.
    mock_insert.assert_awaited_once_with(run_id, finding)

    # The final status update must be "completed" carrying the coverage payload.
    completed_calls = [c for c in mock_update.await_args_list if c.args[1:2] == ("completed",)]
    assert completed_calls, f"no 'completed' status update; calls were {mock_update.await_args_list}"
    completed_call = completed_calls[-1]
    assert completed_call.kwargs.get("coverage") == coverage_payload
