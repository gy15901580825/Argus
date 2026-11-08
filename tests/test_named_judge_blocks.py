"""Provider filters remain undecided while preserving useful, safe diagnostics."""
import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from argus import cost_meter, llm
from argus.cli import cmd_scan_mcp
from argus.cli.__main__ import main
from argus.drafting.openapi import catalog_operations, load_openapi
from argus.drafting.proposal import propose_choices
from argus.mcp_scan import checks, scan
from argus.mcp_scan.client import HttpServer
from argus.mcp_scan.findings import unjudged_count
from argus.mcp_scan.judging import ERROR_REASON, JudgeGate
from argus.mcp_scan.models import Candidate
from test_draft_target import input_file
from test_draft_target_model import sync_document
from test_judge_blocked import DEPLOYMENT, PROMPT_MARK, VERDICT, _azure_block, _config
from test_mcp_scan_findings import hit, tool


def candidate(text, name="echo", seq=None):
    return Candidate(checks.DESCRIPTION, name, text, seq, "description")


def scripted_model(monkeypatch, errors):
    """Use the actual SDK-to-LLM exception mapping and actual Judge completion path."""
    pending = iter(errors)
    calls = []

    async def complete(**kwargs):
        calls.append(kwargs)
        error = next(pending)
        if error is not None:
            raise error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=VERDICT))],
                               usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))

    monkeypatch.setattr(llm, "_acompletion", complete)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, DEPLOYMENT, {"input": 0.0, "output": 0.0})
    return replace(_config(REDTEAM_LLM_FALLBACK="off"), fallback_enabled=False), calls


async def run_scan(monkeypatch, cfg, candidates, hits=()):
    @asynccontextmanager
    async def session(*args, **kwargs):
        async def list_tools():
            return [tool("echo", annotations={}), tool("other", annotations={})], []
        yield SimpleNamespace(list_tools=list_tools, server_info=None, list_truncated=False, tools_listed=2)

    async def server_checks(*args):
        return []

    monkeypatch.setattr(scan, "open_session", session)
    monkeypatch.setattr(scan, "http_server_findings", server_checks)
    monkeypatch.setattr(scan.checks, "static_hits", lambda *args, **kwargs: (list(hits), list(candidates)))
    return await scan.scan_mcp(scan.ScanConfig(target=HttpServer("http://127.0.0.1:9/mcp"),
                                              judge_config=cfg), mask=lambda s: s, echo=lambda s: None)


async def test_filter_gate_keeps_error_and_continues_distinct_text(monkeypatch):
    cfg, calls = scripted_model(monkeypatch, [_azure_block(), None])
    outcomes = await JudgeGate(.5, cfg, "rubric").judge_all(
        [candidate("blocked text"), candidate("normal text", "other")], lambda s: s)
    assert [o.status for o in outcomes] == ["error", "judged"]
    assert outcomes[1].verdict == "pass" and len(calls) == 2
    assert outcomes[0].error_code == "content_filter"
    assert "content filter" in outcomes[0].reasoning.lower() and "jailbreak" in outcomes[0].reasoning


def test_cached_filtered_items_count_in_real_scan_and_cli(monkeypatch, tmp_path):
    cfg, calls = scripted_model(monkeypatch, [_azure_block(), None])
    result = asyncio.run(run_scan(monkeypatch, cfg, [candidate("blocked text"), candidate("blocked text", seq=2),
                                                    candidate("normal text", "other")]))
    assert len(calls) == 2
    assert result.unjudged == 1
    errors = [f for f in result.findings if f["probe_id"] == checks.DESCRIPTION and f["verdict"] == "error"]
    assert len(errors) == 1 and errors[0]["evidence"]["error_code"] == "content_filter"
    assert len(errors[0]["evidence"]["items"]) == 2
    assert all(i["error_code"] == "content_filter" and "jailbreak" in i["reasoning"]
               for i in errors[0]["evidence"]["items"])
    assert any("2" in note and "content filter" in note.lower() for note in result.notes)
    assert unjudged_count(result.findings, (ERROR_REASON,)) == 0

    async def completed_scan(*args, **kwargs):
        return result

    monkeypatch.setattr(scan, "scan_mcp", completed_scan)
    monkeypatch.setattr(cmd_scan_mcp, "sdk_problem", lambda extra: None)
    monkeypatch.chdir(tmp_path)
    cli = CliRunner().invoke(main, ["scan-mcp", "http://127.0.0.1:9/mcp"])
    assert cli.exit_code == 1, cli.output
    assert "content filter" in cli.output.lower() and "policy" in cli.output.lower()
    assert "check the judge provider and its key" not in cli.output


async def test_filter_summary_survives_known_fail_winning_aggregation(monkeypatch):
    cfg, calls = scripted_model(monkeypatch, [_azure_block()])
    result = await run_scan(monkeypatch, cfg, [candidate("blocked text"), candidate("blocked text", seq=2)],
                            hits=[hit(checks.DESCRIPTION, "echo")])
    selected = [f for f in result.findings if f["probe_id"] == checks.DESCRIPTION and "echo" in f["evidence"]["tools"]]
    assert len(selected) == 1 and selected[0]["verdict"] == "fail"
    assert len(calls) == 1
    assert any("2" in note and "content filter" in note.lower() for note in result.notes)


async def test_mixed_unjudged_group_preserves_each_filtered_item_cause(monkeypatch):
    cfg, _ = scripted_model(monkeypatch, [RuntimeError("ordinary failure"), _azure_block()])
    result = await run_scan(monkeypatch, cfg, [candidate("ordinary text"), candidate("blocked text", seq=2)])
    error = next(f for f in result.findings if f["probe_id"] == checks.DESCRIPTION and f["verdict"] == "error")
    assert error["reasoning"] == ERROR_REASON and result.unjudged == 1
    blocked = error["evidence"]["items"][1]
    assert blocked["error_code"] == "content_filter" and "jailbreak" in blocked["reasoning"]


async def test_filtered_category_diagnostic_masks_and_escapes_without_exception_text(monkeypatch):
    secret = "category-private-value"
    error = llm.JudgeBlockedError(PROMPT_MARK, provider="neutral", model="neutral", categories=(secret + "\x1b[31m",),
                                  fallback=None)

    class BlockedJudge:
        async def judge(self, *args):
            raise error

    cfg, _ = scripted_model(monkeypatch, [])
    outcomes = await JudgeGate(.5, cfg, "rubric", lambda *args: BlockedJudge()).judge_all(
        [candidate("text")], lambda s: s.replace(secret, "[masked]"))
    assert outcomes[0].status == "error"
    text = outcomes[0].reasoning
    assert "content filter" in text.lower() and "[masked]" in text
    assert secret not in text and PROMPT_MARK not in text and "\x1b" not in text


async def test_filtered_proposal_uses_named_failure_and_keeps_deterministic_choices(monkeypatch, tmp_path):
    cfg, calls = scripted_model(monkeypatch, [_azure_block()])
    monkeypatch.setattr(llm, "text_config", lambda: cfg)
    monkeypatch.setattr(llm, "missing_text", lambda config: None)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, sync_document())))
    result = await propose_choices(catalog)
    assert result.disclosure.status == "failed" and result.disclosure.application_calls == 1 and len(calls) == 1
    gap = next(g for g in result.choices.gaps if g.code == "model_blocked")
    assert "content filter" in gap.why.lower() and "policy" in gap.decision.lower()
    assert result.choices.operation is not None
    assert PROMPT_MARK not in json.dumps(result.disclosure.to_dict())


async def test_ordinary_proposal_failure_keeps_existing_code(monkeypatch, tmp_path):
    cfg, calls = scripted_model(monkeypatch, [RuntimeError("ordinary failure")])
    monkeypatch.setattr(llm, "text_config", lambda: cfg)
    monkeypatch.setattr(llm, "missing_text", lambda config: None)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, sync_document())))
    result = await propose_choices(catalog)
    assert result.disclosure.status == "failed" and len(calls) == 1
    assert any(g.code == "model_call_failed" for g in result.choices.gaps)


async def test_unavailable_proposal_keeps_no_call_control(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "text_config", lambda: None)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, sync_document())))
    result = await propose_choices(catalog)
    assert result.disclosure.status == "unavailable" and result.disclosure.application_calls == 0
    assert any(g.code == "model_unavailable" for g in result.choices.gaps)
