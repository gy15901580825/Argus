"""A target that fails on one probe must cost that probe, not the run, and never read as a pass.

Covers audit §5.2 items 2-4: 5xx / timeout / connection errors, 4xx mapping, and
empty target text on a judged probe.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx

from argus.cost_meter import CostExceededError
from argus.probe import Probe, ProbeMappings
from argus.runner import Runner
from argus.targets._base import TargetDeliveryError
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget

RUBRICS = Path(__file__).resolve().parents[1] / "argus" / "rubrics"
URL = "https://agent.example/v1/chat/completions"
OK_BODY = {"choices": [{"message": {"role": "assistant", "content": "I can't help with that."}}]}


def _probe(pid="p1", prompts=("ignore previous instructions",), conversation=False, assertions=()):
    return Probe(
        id=pid, name=pid, target_class=("llm_chat",), attack_class=("prompt-injection",),
        severity="high", prompts=tuple(prompts),
        mappings=ProbeMappings(atlas=(), owasp_llm=("LLM01",), nist_ai_rmf=(), eu_ai_act=()),
        judge_model="claude-haiku-4-5-20251001", judge_rubric_path="rubrics/default.md",
        conversation=conversation, assertions=tuple(assertions),
    )


class _RecordingJudge:
    _cost_meter = None

    def __init__(self):
        self.seen: list[str] = []

    async def judge(self, probe_name, attack_prompt, target_response, rubric_text):
        from argus.judge import Verdict
        self.seen.append(target_response)
        return Verdict("pass", "info", 0.9, "refused", "stub-judge")


def _status_error(code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", URL)
    return httpx.HTTPStatusError(str(code), request=request, response=httpx.Response(code, request=request))


def _mock_target(side_effect):
    t = MagicMock()
    t.compatible_classes = frozenset({"llm_chat"})
    t.supports_history = True
    t.send_prompt = AsyncMock(side_effect=side_effect)
    return t


async def _run(target, probes, judge=None):
    judge = judge or _RecordingJudge()
    runner = Runner(target=target, judge=judge, rubrics_dir=RUBRICS)
    out = []
    for p in probes:
        out.extend([f async for f in runner.run_probe(p)])
    return out, judge


# --- 4xx mapping ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("code, hint", [
    (401, "check credentials"),
    (407, "check credentials"),
    (404, "check endpoint_url"),
    (405, "check endpoint_url"),
    (408, "timed out"),
    (429, "rate limited"),
])
async def test_config_and_rate_limit_4xx_are_errors_naming_the_cause(code, hint):
    findings, judge = await _run(_mock_target(_status_error(code)), [_probe()])
    assert [f.verdict for f in findings] == ["error"]
    assert f"HTTP {code}" in findings[0].reasoning
    assert hint in findings[0].reasoning
    assert "gateway rejected" not in findings[0].reasoning
    assert judge.seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [400, 403, 409])
async def test_other_4xx_stay_blocked_with_neutral_wording(code):
    findings, judge = await _run(_mock_target(_status_error(code)), [_probe()])
    assert [f.verdict for f in findings] == ["blocked_by_target"]
    assert findings[0].reasoning == (
        f"target returned HTTP {code} to the attack prompt; counted as blocked"
    )
    assert judge.seen == []


@pytest.mark.asyncio
async def test_sdk_style_status_code_attribute_uses_the_same_mapping():
    class FakeSDKError(Exception):
        def __init__(self, status_code):
            super().__init__("sdk said no")
            self.status_code = status_code

    findings, _ = await _run(_mock_target(FakeSDKError(429)), [_probe()])
    assert findings[0].verdict == "error" and "rate limited" in findings[0].reasoning
    findings, _ = await _run(_mock_target(FakeSDKError(400)), [_probe()])
    assert findings[0].verdict == "blocked_by_target"
    findings, _ = await _run(_mock_target(FakeSDKError(503)), [_probe()])
    assert findings[0].verdict == "error" and "HTTP 503" in findings[0].reasoning


@pytest.mark.asyncio
async def test_unfollowed_redirect_is_an_endpoint_error_not_a_server_error():
    findings, _ = await _run(_mock_target(_status_error(302)), [_probe()])
    assert findings[0].verdict == "error"
    assert findings[0].reasoning == "target returned HTTP 302; check endpoint_url / request_url"


# --- 5xx / timeout / connection: one probe errors, the run continues -------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("exc, needle", [
    (_status_error(502), "HTTP 502"),
    (httpx.ReadTimeout("", request=httpx.Request("POST", URL)), "ReadTimeout"),
    (httpx.ConnectError("refused", request=httpx.Request("POST", URL)), "ConnectError"),
    (TargetDeliveryError("bridge gone"), "bridge gone"),
    (TimeoutError(), "TimeoutError"),
])
async def test_transient_failure_errors_one_probe_and_the_run_goes_on(exc, needle):
    target = _mock_target([exc, ("I can't help with that.", 5.0)])
    findings, judge = await _run(target, [_probe("p1"), _probe("p2")])
    assert [(f.probe_id, f.verdict) for f in findings] == [("p1", "error"), ("p2", "pass")]
    assert needle in findings[0].reasoning
    assert judge.seen == ["I can't help with that."]


@pytest.mark.asyncio
async def test_unrelated_exception_from_target_still_propagates():
    # A bug in an adapter must not be dressed up as a target outage.
    with pytest.raises(RuntimeError, match="adapter bug"):
        await _run(_mock_target(RuntimeError("adapter bug")), [_probe()])


@pytest.mark.asyncio
async def test_cost_cap_from_send_still_stops_the_run():
    with pytest.raises(CostExceededError):
        await _run(_mock_target(CostExceededError("cap")), [_probe()])


@pytest.mark.asyncio
async def test_conversation_probe_stops_at_the_first_failed_turn():
    # Later turns are meaningless without the earlier ones; sending them would test something else.
    target = _mock_target([("ok", 1.0), _status_error(503), ("later", 1.0)])
    probe = _probe(prompts=("one", "two", "three"), conversation=True)
    findings, judge = await _run(target, [probe])
    assert [f.verdict for f in findings] == ["pass", "error"]
    assert target.send_prompt.await_count == 2


# --- empty target text on a judged probe -------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("text", ["", "   \n"])
async def test_empty_text_is_an_error_and_never_judged(text):
    findings, judge = await _run(_mock_target([(text, 3.0)]), [_probe()])
    assert [f.verdict for f in findings] == ["error"]
    assert findings[0].reasoning == "target returned no text; check the endpoint"  # adapter kind unknown
    assert judge.seen == []


@pytest.mark.asyncio
async def test_empty_text_on_assertion_probe_is_still_decided_by_evidence():
    class _Target:
        compatible_classes = frozenset({"llm_chat"})
        supports_history = True

        async def send_prompt(self, prompt, history=()):
            return "", 2.0

        async def collect_evidence(self):
            return {"interaction_count": 1}

    probe = _probe(assertions=({"max_payments": 0},))
    findings, judge = await _run(_Target(), [probe])
    assert [f.verdict for f in findings] == ["pass"]
    assert judge.seen == []


# --- iterative path ----------------------------------------------------------------------------

def _iterative(pid="tap_1"):
    p = MagicMock()
    p.id, p.name, p.iterative, p.conversation = pid, pid, True, False
    p.target_class = ("llm_chat",)
    p.assertions = ()
    p.judge_rubric_path = "rubrics/default.md"
    p.rubrics_dir = None
    p.mappings = ProbeMappings(atlas=(), owasp_llm=(), nist_ai_rmf=(), eu_ai_act=())
    p.should_halt = MagicMock(side_effect=lambda ctx: ctx.round_n >= 2)
    p.next_prompt = AsyncMock(return_value="round prompt")
    return p


@pytest.mark.asyncio
@pytest.mark.parametrize("exc, verdict, needle", [
    (_status_error(500), "error", "HTTP 500"),
    (httpx.ReadTimeout("", request=httpx.Request("POST", URL)), "error", "ReadTimeout"),
    (_status_error(401), "error", "check credentials"),
    (_status_error(400), "blocked_by_target", "counted as blocked"),
])
async def test_iterative_send_failure_ends_that_thread_only(exc, verdict, needle):
    target = _mock_target([exc, ("no", 1.0), ("no", 1.0)])
    findings, judge = await _run(target, [_iterative("t1"), _iterative("t2")])
    assert [(f.probe_id, f.verdict) for f in findings] == [
        ("t1", verdict), ("t2", "pass"), ("t2", "pass"),
    ]
    assert needle in findings[0].reasoning


@pytest.mark.asyncio
async def test_iterative_empty_text_errors_and_skips_the_judge():
    findings, judge = await _run(_mock_target([("", 1.0), ("no", 1.0)]), [_iterative()])
    assert [f.verdict for f in findings] == ["error"]
    assert "returned no text" in findings[0].reasoning
    assert judge.seen == []


# --- real adapters through the real Runner (the audit's reproduction path) ---------------------

@pytest.mark.asyncio
@respx.mock
async def test_openai_compat_200_with_error_body_is_not_judged():
    respx.post(URL).mock(return_value=httpx.Response(200, json={"error": {"message": "overloaded"}}))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ["error"]
    assert judge.seen == []


@pytest.mark.asyncio
@respx.mock
async def test_openai_compat_502_then_ok_keeps_earlier_and_later_findings():
    respx.post(URL).mock(side_effect=[
        httpx.Response(200, json=OK_BODY), httpx.Response(502), httpx.Response(200, json=OK_BODY),
    ])
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, _ = await _run(target, [_probe("a"), _probe("b"), _probe("c")])
    assert [(f.probe_id, f.verdict) for f in findings] == [("a", "pass"), ("b", "error"), ("c", "pass")]
    assert "HTTP 502" in findings[1].reasoning


@pytest.mark.asyncio
@respx.mock
async def test_openai_compat_401_is_a_credentials_error_not_a_block():
    respx.post(URL).mock(return_value=httpx.Response(401, json={"error": "bad key"}))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, _ = await _run(target, [_probe()])
    assert findings[0].verdict == "error"
    assert "HTTP 401" in findings[0].reasoning and "check credentials" in findings[0].reasoning


@pytest.mark.asyncio
@respx.mock
async def test_custom_http_jsonpath_miss_is_an_error():
    respx.post("https://agent.example/chat").mock(return_value=httpx.Response(200, json={"reply": "hello"}))
    target = CustomHTTPTarget(CustomHTTPSpec(
        request_url="https://agent.example/chat",
        request_body_template='{"q": {{ prompt | tojson }}}',
        response_jsonpath="$.answer",
    ))
    findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ["error"]
    assert "response_jsonpath" in findings[0].reasoning
    assert judge.seen == []


# --- default timeouts: real agents with tools often take longer than 30-60 s ------------------

def test_chat_adapters_default_to_a_120_second_timeout():
    from argus.targets.anthropic_native import AnthropicNativeSpec

    assert OpenAICompatSpec(endpoint_url=URL, model="m").timeout_s == 120.0
    assert CustomHTTPSpec(request_url=URL, request_body_template="{}", response_jsonpath="$.a").timeout_s == 120.0
    assert AnthropicNativeSpec(model="m", api_key="not-a-real-key").timeout_s == 120.0


# --- fix round 1 -------------------------------------------------------------------------------

def _req():
    return httpx.Request("POST", URL)


def _anthropic_errors():
    import anthropic
    return [
        (anthropic.APIConnectionError(request=_req()), "error", "APIConnectionError"),
        (anthropic.APITimeoutError(request=_req()), "error", "APITimeoutError"),
        (anthropic.APIStatusError("overloaded", response=httpx.Response(529, request=_req()), body=None),
         "error", "HTTP 529 (server error)"),
        (anthropic.BadRequestError("refused", response=httpx.Response(400, request=_req()), body=None),
         "blocked_by_target", "HTTP 400 to the attack prompt"),
    ]


def _grpc_error(code_name, details="boom"):
    import grpc
    return grpc.aio.AioRpcError(getattr(grpc.StatusCode, code_name), grpc.aio.Metadata(), grpc.aio.Metadata(),
                                details=details)


@pytest.mark.asyncio
@pytest.mark.parametrize("exc, verdict, needle", _anthropic_errors())
async def test_anthropic_sdk_errors_cost_one_probe(exc, verdict, needle):
    findings, _ = await _run(_mock_target([exc, ("no", 1.0)]), [_probe("p1"), _probe("p2")])
    assert [(f.probe_id, f.verdict) for f in findings] == [("p1", verdict), ("p2", "pass")]
    assert needle in findings[0].reasoning


@pytest.mark.asyncio
@pytest.mark.parametrize("code, reason", [
    ("UNAVAILABLE", "target request failed: gRPC UNAVAILABLE: boom"),
    ("DEADLINE_EXCEEDED", "target request failed: gRPC DEADLINE_EXCEEDED: boom"),
    ("UNAUTHENTICATED", "target returned gRPC UNAUTHENTICATED (check credentials): boom"),
    ("PERMISSION_DENIED", "target returned gRPC PERMISSION_DENIED (check credentials): boom"),
    ("RESOURCE_EXHAUSTED", "target returned gRPC RESOURCE_EXHAUSTED (rate limited; slow down or retry later): boom"),
    ("INTERNAL", "target request failed: gRPC INTERNAL: boom"),
])
async def test_grpc_errors_get_one_line_reasons(code, reason):
    findings, _ = await _run(_mock_target([_grpc_error(code)]), [_probe()])
    assert findings[0].verdict == "error"
    assert findings[0].reasoning == reason


@pytest.mark.asyncio
@pytest.mark.parametrize("code, hint", [
    (404, "check endpoint_url / request_url / model"),
    (422, "check request_body_template / the request schema"),
])
async def test_404_and_422_hints(code, hint):
    findings, _ = await _run(_mock_target(_status_error(code)), [_probe()])
    assert findings[0].verdict == "error"
    assert findings[0].reasoning == f"target returned HTTP {code} (" + {
        404: "not found; ", 422: "unprocessable request; "}[code] + hint + ")"


@pytest.mark.asyncio
@respx.mock
async def test_200_with_a_non_json_body_costs_one_probe():
    respx.post(URL).mock(side_effect=[
        httpx.Response(200, text="<html>gateway</html>", headers={"content-type": "application/json"}),
        httpx.Response(200, json=OK_BODY),
    ])
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, _ = await _run(target, [_probe("a"), _probe("b")])
    assert [(f.probe_id, f.verdict) for f in findings] == [("a", "error"), ("b", "pass")]
    assert findings[0].reasoning.startswith("target request failed: JSONDecodeError")


@pytest.mark.asyncio
async def test_blocked_turn_ends_a_conversation_probe():
    target = _mock_target([("ok", 1.0), _status_error(400), ("later", 1.0)])
    findings, _ = await _run(target, [_probe(prompts=("one", "two", "three"), conversation=True)])
    assert [f.verdict for f in findings] == ["pass", "blocked_by_target"]
    assert target.send_prompt.await_count == 2


# Breaker: a target that stopped answering must not cost hours of timeouts.

@pytest.mark.asyncio
async def test_five_unreachable_probes_in_a_row_stop_the_run():
    from argus.runner import TargetUnreachableError

    timeout = httpx.ReadTimeout("", request=_req())
    target = _mock_target([timeout] * 10)
    runner = Runner(target=target, judge=_RecordingJudge(), rubrics_dir=RUBRICS)
    seen = []
    with pytest.raises(TargetUnreachableError) as info:
        for i in range(8):
            async for f in runner.run_probe(_probe(f"p{i}")):
                seen.append(f.probe_id)
    assert seen == ["p0", "p1", "p2", "p3", "p4"]
    assert str(info.value) == "target unreachable: 5 probes in a row failed (target request failed: ReadTimeout)"
    assert target.send_prompt.await_count == 5


@pytest.mark.asyncio
async def test_a_probe_that_got_an_answer_resets_the_breaker():
    err = _status_error(503)
    target = _mock_target([err] * 4 + [("no", 1.0)] + [err] * 4 + [_status_error(400)] + [err] * 4)
    findings, _ = await _run(target, [_probe(f"p{i}") for i in range(14)])
    assert len(findings) == 14  # never five failed probes in a row: a pass and a block reset it


@pytest.mark.asyncio
async def test_breaker_counts_a_probe_only_when_every_send_failed():
    err = _status_error(502)
    # Each two-prompt probe gets one failure and one answer: never "all sends failed".
    target = _mock_target([err, ("no", 1.0)] * 6)
    findings, _ = await _run(target, [_probe(f"p{i}", prompts=("a", "b")) for i in range(6)])
    assert len(findings) == 12


# Missing rubric: never judge against an empty rubric.

@pytest.mark.asyncio
async def test_missing_rubric_is_an_error_and_the_judge_is_not_called(tmp_path):
    runner = Runner(target=_mock_target([("reply", 1.0)]), judge=_RecordingJudge(), rubrics_dir=tmp_path)
    judge = runner._judge
    findings = [f async for f in runner.run_probe(_probe())]
    assert [f.verdict for f in findings] == ["error"]
    assert findings[0].reasoning.startswith("rubric file not found: ")
    assert judge.seen == []


# Setup and evidence: a transport-shaped failure there costs the probe, not the run.

class _TestbedTarget:
    compatible_classes = frozenset({"llm_chat"})
    supports_history = True

    def __init__(self, begin_exc=None, evidence_exc=None):
        self._begin_exc, self._evidence_exc = begin_exc, evidence_exc

    async def begin_probe(self, probe):
        if self._begin_exc:
            raise self._begin_exc

    async def send_prompt(self, prompt, history=()):
        return "done", 1.0

    async def collect_evidence(self):
        if self._evidence_exc:
            raise self._evidence_exc
        return {"interaction_count": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize("exc", [TimeoutError(), ConnectionResetError("reset")])
async def test_setup_timeout_costs_one_probe(exc):
    findings, _ = await _run(_TestbedTarget(begin_exc=exc), [_probe(assertions=({"max_payments": 0},))])
    assert [f.verdict for f in findings] == ["error"]
    assert findings[0].reasoning.startswith("target could not set up this probe: ")


@pytest.mark.asyncio
async def test_non_json_evidence_body_costs_one_probe():
    import json
    exc = json.JSONDecodeError("Expecting value", "<html>", 0)
    findings, _ = await _run(_TestbedTarget(evidence_exc=exc), [_probe(assertions=({"max_payments": 0},))])
    assert [f.verdict for f in findings] == ["error"]
    assert findings[0].reasoning.startswith("could not read evidence from the testbed: ")


# Reply shapes the adapters must turn into text, a block, or nothing.

@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("value", [None, [], {}, "  "])
async def test_custom_http_empty_json_values_are_no_text(value):
    respx.post("https://agent.example/chat").mock(return_value=httpx.Response(200, json={"reply": value}))
    target = CustomHTTPTarget(CustomHTTPSpec(
        request_url="https://agent.example/chat",
        request_body_template='{"q": {{ prompt | tojson }}}', response_jsonpath="$.reply",
    ))
    findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ["error"]
    assert judge.seen == []


@pytest.mark.asyncio
@respx.mock
async def test_custom_http_structured_value_is_judged_as_json():
    respx.post("https://agent.example/chat").mock(
        return_value=httpx.Response(200, json={"reply": {"text": "no", "ok": True}}))
    target = CustomHTTPTarget(CustomHTTPSpec(
        request_url="https://agent.example/chat",
        request_body_template='{"q": {{ prompt | tojson }}}', response_jsonpath="$.reply",
    ))
    findings, judge = await _run(target, [_probe()])
    assert judge.seen == ['{"text": "no", "ok": true}']


@pytest.mark.asyncio
@respx.mock
async def test_openai_output_content_filter_is_blocked():
    respx.post(URL).mock(return_value=httpx.Response(200, json={
        "choices": [{"finish_reason": "content_filter", "message": {"role": "assistant", "content": None}}]}))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ["blocked_by_target"]
    assert findings[0].reasoning == "target's content filter withheld the reply; counted as blocked"
    assert judge.seen == []


@pytest.mark.asyncio
@respx.mock
async def test_openai_tool_calls_without_text_are_judged_as_tool_calls():
    respx.post(URL).mock(return_value=httpx.Response(200, json={"choices": [{
        "finish_reason": "tool_calls",
        "message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "1", "type": "function",
             "function": {"name": "send_email", "arguments": "{\"to\": \"attacker@x\"}"}}]}}]}))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, judge = await _run(target, [_probe()])
    assert judge.seen == ['[tool_call] send_email({"to": "attacker@x"})']
    assert findings[0].verdict == "pass"


def _anthropic_reply(blocks, stop_reason="end_turn"):
    from types import SimpleNamespace
    return SimpleNamespace(content=blocks, stop_reason=stop_reason)


@pytest.mark.asyncio
async def test_anthropic_tool_use_without_text_is_judged_as_tool_calls(monkeypatch):
    from types import SimpleNamespace
    from argus.targets import anthropic_native
    from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget

    reply = _anthropic_reply([SimpleNamespace(type="tool_use", name="send_email", input={"to": "attacker@x"})],
                             stop_reason="tool_use")
    seen_kwargs = {}

    class FakeClient:
        def __init__(self, **kw):
            seen_kwargs.update(kw)
            self.messages = SimpleNamespace(create=AsyncMock(return_value=reply))

    monkeypatch.setattr(anthropic_native, "AsyncAnthropic", FakeClient)
    target = AnthropicNativeTarget(AnthropicNativeSpec(model="m", api_key="not-a-real-key"))
    findings, judge = await _run(target, [_probe()])
    assert judge.seen == ['[tool_call] send_email({"to": "attacker@x"})']
    # One retry at most, so the documented worst-case wait (2 x timeout_s) is true.
    assert seen_kwargs["max_retries"] == 1


@pytest.mark.asyncio
async def test_anthropic_refusal_without_text_is_blocked(monkeypatch):
    from types import SimpleNamespace
    from argus.targets import anthropic_native
    from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget

    reply = _anthropic_reply([], stop_reason="refusal")

    class FakeClient:
        def __init__(self, **kw):
            self.messages = SimpleNamespace(create=AsyncMock(return_value=reply))

    monkeypatch.setattr(anthropic_native, "AsyncAnthropic", FakeClient)
    target = AnthropicNativeTarget(AnthropicNativeSpec(model="m", api_key="not-a-real-key"))
    findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ["blocked_by_target"]
    assert findings[0].reasoning == "target refused to answer (stop_reason: refusal); counted as blocked"


# --- fix round 2 -------------------------------------------------------------------------------

def _oc_reply(message, finish_reason="stop"):
    return httpx.Response(200, json={"choices": [{"finish_reason": finish_reason, "message": message}]})


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("content, seen", [
    ([{"type": "text", "text": "I can't"}, {"type": "image_url", "image_url": {"url": "x"}},
      {"type": "text", "text": " help."}], "I can't help."),
    ({"answer": "no"}, '{"answer": "no"}'),
    (42, "42"),
])
async def test_openai_non_string_content_is_judged_as_text(content, seen):
    # Some OpenAI-compatible servers return content as a list of parts; base judged it, so must we.
    respx.post(URL).mock(side_effect=[_oc_reply({"role": "assistant", "content": content}),
                                      httpx.Response(200, json=OK_BODY)])
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, judge = await _run(target, [_probe("a"), _probe("b")])
    assert [(f.probe_id, f.verdict) for f in findings] == [("a", "pass"), ("b", "pass")]
    assert judge.seen[0] == seen


@pytest.mark.asyncio
@respx.mock
async def test_openai_parts_without_text_are_no_text():
    respx.post(URL).mock(return_value=_oc_reply({"role": "assistant", "content": [{"type": "image_url"}]}))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ["error"] and judge.seen == []


@pytest.mark.asyncio
@respx.mock
async def test_openai_whitespace_content_with_tool_calls_is_judged_on_the_calls():
    respx.post(URL).mock(return_value=_oc_reply({"role": "assistant", "content": "\n", "tool_calls": [
        {"id": "1", "type": "function", "function": {"name": "send_email", "arguments": "{}"}}]}, "tool_calls"))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, judge = await _run(target, [_probe()])
    assert judge.seen == ["[tool_call] send_email({})"]


@pytest.mark.asyncio
async def test_runner_tolerates_a_non_string_reply_from_any_adapter():
    findings, judge = await _run(_mock_target([(["part"], 1.0)]), [_probe()])
    assert findings[0].verdict == "pass"


@pytest.mark.asyncio
@respx.mock
async def test_empty_reply_hint_names_the_adapter_field():
    respx.post(URL).mock(return_value=_oc_reply({"role": "assistant", "content": None}))
    target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=URL, model="m"))
    findings, _ = await _run(target, [_probe()])
    assert findings[0].reasoning == "target returned no text; the endpoint returned no message content"

    respx.post("https://agent.example/chat").mock(return_value=httpx.Response(200, json={"x": 1}))
    target = CustomHTTPTarget(CustomHTTPSpec(
        request_url="https://agent.example/chat",
        request_body_template='{"q": {{ prompt | tojson }}}', response_jsonpath="$.reply",
    ))
    findings, _ = await _run(target, [_probe()])
    assert findings[0].reasoning == "target returned no text; check response_jsonpath or the endpoint"


@pytest.mark.asyncio
async def test_missing_rubric_errors_before_anything_is_sent_or_any_attacker_call(tmp_path):
    target = _mock_target([("reply", 1.0)])
    it = _iterative()
    runner = Runner(target=target, judge=_RecordingJudge(), rubrics_dir=tmp_path)
    findings = [f for p in (_probe(), it) for f in [g async for g in runner.run_probe(p)]]
    assert [f.verdict for f in findings] == ["error", "error"]
    assert all(f.reasoning.startswith("rubric file not found: ") for f in findings)
    target.send_prompt.assert_not_called()
    it.next_prompt.assert_not_called()
