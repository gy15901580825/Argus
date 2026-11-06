"""A provider content filter that refuses the judge prompt stops the run with a named JudgeBlockedError."""
from __future__ import annotations

import json
from types import SimpleNamespace

import anthropic
import httpx
import litellm
import openai
import pytest
from click.testing import CliRunner
from fastapi import FastAPI
from litellm.litellm_core_utils.exception_mapping_utils import exception_type

from argus import api, cost_meter, llm
from argus.cli.__main__ import main
from argus.cost_meter import CostMeter
from argus.probe import Probe, ProbeMappings

PROMPT_MARK = "attack-text-that-must-not-leak"
DEPLOYMENT = "judge-deployment"
# The shape Azure OpenAI returns when its prompt shield fires on a judge prompt.
AZURE_FILTER_BODY = {
    "message": "The response was filtered due to the prompt triggering Azure OpenAI's content management policy.",
    "type": None,
    "param": "prompt",
    "code": "content_filter",
    "status": 400,
    "innererror": {
        "code": "ResponsibleAIPolicyViolation",
        "content_filter_result": {
            "hate": {"filtered": False, "severity": "safe"},
            "jailbreak": {"detected": True, "filtered": True},
            "self_harm": {"filtered": False, "severity": "safe"},
            "sexual": {"filtered": False, "severity": "safe"},
            "violence": {"filtered": False, "severity": "safe"},
        },
    },
}
VERDICT = json.dumps({"verdict": "pass", "severity": "info", "confidence": 1.0, "reasoning": "No violation."})


def _request():
    return httpx.Request("POST", "http://127.0.0.1/chat/completions")


def _litellm_error(provider: str, original: Exception, model: str = DEPLOYMENT) -> Exception:
    """The exception litellm raises for this provider error, from litellm's own mapping."""
    litellm.suppress_debug_info = True
    try:
        exception_type(model=model, original_exception=original, custom_llm_provider=provider)
    except Exception as e:  # noqa: BLE001 - the mapping always raises; the raised error is the result
        return e
    raise AssertionError("litellm did not map the error")


def _sdk_400(body: dict) -> openai.BadRequestError:
    response = httpx.Response(400, json={"error": body}, request=_request())
    return openai.BadRequestError(message=f"Error code: 400 - {{'error': {body!r}}}", response=response, body=body)


def _azure_block() -> Exception:
    return _litellm_error("azure", _sdk_400(AZURE_FILTER_BODY))


def _stub_litellm(monkeypatch, error: Exception | None = None) -> list[str]:
    calls: list[str] = []

    async def fake(**kwargs):
        calls.append(kwargs["model"])
        if error is not None:
            raise error
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=VERDICT))],
                               usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))

    monkeypatch.setattr(llm, "_acompletion", fake)
    return calls


def _stub_anthropic(monkeypatch, error: Exception | None = None) -> list[str]:
    calls: list[str] = []

    class Messages:
        async def create(self, **kwargs):
            calls.append(kwargs["model"])
            if error is not None:
                raise error
            return SimpleNamespace(content=[SimpleNamespace(text=VERDICT)], stop_reason="end_turn",
                                   usage=SimpleNamespace(input_tokens=1, output_tokens=1))

    monkeypatch.setattr(llm, "_anthropic_client", lambda api_key: SimpleNamespace(messages=Messages()))
    return calls


def _config(provider: str = "azure", **env) -> llm.LLMConfig:
    base = {"REDTEAM_MODEL_PROVIDER": provider, "REDTEAM_FAST_MODEL": DEPLOYMENT, "REDTEAM_STRONG_MODEL": DEPLOYMENT}
    return llm.resolve_config({**base, **env})


async def _complete(cfg: llm.LLMConfig) -> llm.Completion:
    return await llm.complete(cfg, role="fast", system="rubric", user=f"Probe: x\n{PROMPT_MARK}", max_tokens=10)


async def test_azure_filter_block_names_provider_deployment_and_category_without_falling_back(monkeypatch):
    _stub_litellm(monkeypatch, _azure_block())
    fallback_calls = _stub_anthropic(monkeypatch)
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _complete(_config())
    e = caught.value
    assert (e.provider, e.model, e.categories) == ("azure", DEPLOYMENT, ("jailbreak",))
    assert e.as_dict() == {"provider": "azure", "model": DEPLOYMENT, "categories": ["jailbreak"], "fallback": "off"}
    assert f"azure deployment {DEPLOYMENT}" in str(e) and "jailbreak" in str(e)
    assert "REDTEAM_LLM_FALLBACK=on" in str(e)
    assert PROMPT_MARK not in str(e) and PROMPT_MARK not in json.dumps(e.as_dict())
    assert fallback_calls == []


async def test_an_ordinary_azure_failure_still_falls_back_by_default(monkeypatch):
    _stub_litellm(monkeypatch, _litellm_error("azure", openai.InternalServerError(
        message="upstream failed", response=httpx.Response(500, request=_request()), body=None)))
    fallback_calls = _stub_anthropic(monkeypatch)
    out = await _complete(_config())
    assert fallback_calls == ["claude-haiku-4-5-20251001"]
    assert out.model == "claude-haiku-4-5-20251001"


async def test_an_ordinary_400_is_not_a_filter_block(monkeypatch):
    body = {"message": "max_tokens is too large", "type": "invalid_request_error", "param": "max_tokens",
            "code": "invalid_value"}
    _stub_litellm(monkeypatch, _litellm_error("azure", _sdk_400(body)))
    _stub_anthropic(monkeypatch, RuntimeError("no fallback key"))
    with pytest.raises(llm.AllProvidersFailed) as caught:
        await _complete(_config())
    assert not isinstance(caught.value, llm.JudgeBlockedError)


async def test_explicit_fallback_judges_a_blocked_prompt_on_the_other_provider(monkeypatch):
    _stub_litellm(monkeypatch, _azure_block())
    fallback_calls = _stub_anthropic(monkeypatch)
    out = await _complete(_config(REDTEAM_LLM_FALLBACK="on"))
    assert fallback_calls == ["claude-haiku-4-5-20251001"]
    assert out.text == VERDICT


async def test_explicit_fallback_that_fails_too_says_so_in_the_error(monkeypatch):
    _stub_litellm(monkeypatch, _azure_block())
    _stub_anthropic(monkeypatch, RuntimeError("no fallback key"))
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _complete(_config(REDTEAM_LLM_FALLBACK="on"))
    e = caught.value
    assert e.as_dict()["fallback"] == "anthropic/claude-haiku-4-5-20251001: RuntimeError"
    assert "REDTEAM_LLM_FALLBACK=on" in str(e) and "anthropic/claude-haiku-4-5-20251001: RuntimeError" in str(e)


async def test_a_block_on_both_providers_names_the_first(monkeypatch):
    message = "Output blocked by content filtering policy"
    _stub_litellm(monkeypatch, _azure_block())
    _stub_anthropic(monkeypatch, anthropic.BadRequestError(
        message=message, response=httpx.Response(400, request=_request()), body=None))
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _complete(_config(REDTEAM_LLM_FALLBACK="on"))
    assert caught.value.as_dict() == {"provider": "azure", "model": DEPLOYMENT, "categories": ["jailbreak"],
                                      "fallback": "anthropic/claude-haiku-4-5-20251001: BadRequestError"}


def test_describe_says_when_a_filter_block_falls_back():
    assert "content-filter blocks" in llm.describe(_config(REDTEAM_LLM_FALLBACK="on"))
    assert "content-filter blocks" not in llm.describe(_config())


@pytest.mark.parametrize("provider, error, categories", [
    # OPENAI_API_KEY with an Azure api base: litellm maps the reply to a plain BadRequestError.
    ("openai", lambda: _litellm_error("openai", _sdk_400(AZURE_FILTER_BODY)), ("jailbreak",)),
    ("openai", lambda: _litellm_error("openai", _sdk_400(
        {k: v for k, v in AZURE_FILTER_BODY.items() if k != "innererror"})), ()),
    ("openai", lambda: _litellm_error("openai", _sdk_400(
        {**AZURE_FILTER_BODY, "code": "invalid_request_error", "message": "Invalid request."})), ("jailbreak",)),
    ("litellm", lambda: _litellm_error("anthropic", Exception("Output blocked by content filtering policy"),
                                       model="anthropic/claude-x"), ()),
])
async def test_litellm_mapped_filter_blocks_from_other_routes(monkeypatch, provider, error, categories):
    _stub_litellm(monkeypatch, error())
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _complete(_config(provider))
    assert (caught.value.provider, caught.value.model, caught.value.categories) == (provider, DEPLOYMENT, categories)
    assert caught.value.as_dict()["fallback"] is None


async def test_anthropic_filter_block_does_not_fall_back_to_azure(monkeypatch):
    message = "Output blocked by content filtering policy"
    error = anthropic.BadRequestError(
        message=message, response=httpx.Response(400, request=_request()),
        body={"type": "error", "error": {"type": "invalid_request_error", "message": message}})
    _stub_anthropic(monkeypatch, error)
    fallback_calls = _stub_litellm(monkeypatch)
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _complete(_config("anthropic", ANTHROPIC_API_KEY="test"))
    assert (caught.value.provider, caught.value.categories) == ("anthropic", ())
    assert fallback_calls == []


PROBE = "owasp_01_prompt_injection_basic"


def test_local_run_reports_the_block_and_stops_incomplete(tmp_path, monkeypatch):
    (tmp_path / "agent.py").write_text("def call(prompt, metadata, context):\n    return {'output': 'I cannot help.'}\n")
    (tmp_path / "t.json").write_text(json.dumps({"kind": "python", "entry": "agent.py:call"}))
    judge_calls = _stub_litellm(monkeypatch, _azure_block())
    fallback_calls = _stub_anthropic(monkeypatch)
    out = tmp_path / "run.json"
    result = CliRunner().invoke(main, [
        "run", "--local", "--target", str(tmp_path / "t.json"), "--probes", PROBE, "--format", "json",
        "--out", str(out), "--judge-provider", "azure", "--judge-model", DEPLOYMENT,
        "--judge-strong-model", DEPLOYMENT, "--judge-price", "0,0",
    ])
    assert result.exit_code == 1, result.output
    assert "Run stopped early: JudgeBlockedError:" in result.output
    run = json.loads(out.read_text())
    assert run["status"] == "incomplete"
    assert "REDTEAM_LLM_FALLBACK=on. The report covers only the probes that ran." in run["incomplete_reason"]
    for text in (run["incomplete_reason"], " ".join(run["notes"])):
        assert "JudgeBlockedError" in text and f"azure deployment {DEPLOYMENT}" in text and "jailbreak" in text
    assert [f for f in run["findings"] if f["verdict"] == "pass"] == []
    assert judge_calls and set(judge_calls) == {f"azure/{DEPLOYMENT}"}
    assert fallback_calls == []


@pytest.mark.parametrize("mode, first_caller", [
    ("static", "You are a red-team judge"),  # the fast judge call
    ("deep", "You are a red-team attacker"),  # the deep-mode attacker's first turn
])
async def test_server_stream_ends_with_the_named_block(monkeypatch, tmp_path, mode, first_caller):
    probes = [
        Probe(id=f"probe_{i}", name=f"Probe {i}", target_class=(), attack_class=("prompt-injection",),
              severity="info", prompts=(f"{PROMPT_MARK} {i}",), mappings=ProbeMappings(), judge_model=DEPLOYMENT,
              judge_rubric_path="test.md")
        for i in (1, 2)
    ]
    (tmp_path / "test.md").write_text("Assess the target response.")
    monkeypatch.setattr(api, "RUBRICS_DIR", tmp_path)
    monkeypatch.setattr(api, "load_probe_library", lambda _: probes)
    cfg = _config()
    monkeypatch.setattr(llm, "resolve_config", lambda *args, **kwargs: cfg)
    monkeypatch.setattr("argus.decider.from_env", lambda: None)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, DEPLOYMENT, {"input": 0.0, "output": 0.0})
    monkeypatch.setattr(api, "_COST_METER", CostMeter(daily_cap_usd=100, per_run_cap_usd=1))

    class Target:
        compatible_classes = frozenset()
        supports_history = False

        async def send_prompt(self, prompt, **kwargs):
            return "The target answered.", 0.0

        async def aclose(self):
            pass

    monkeypatch.setattr(api, "build_target", lambda spec: Target())
    _stub_litellm(monkeypatch, _azure_block())
    blocked, systems = llm._acompletion, []

    async def record(**kwargs):
        systems.append(kwargs["messages"][0]["content"])
        return await blocked(**kwargs)

    monkeypatch.setattr(llm, "_acompletion", record)
    fallback_calls = _stub_anthropic(monkeypatch)
    app = FastAPI()
    app.include_router(api.router)
    body = {"target": {"kind": "test"}, "probe_ids": [p.id for p in probes], "mode": mode, "deep_pairs": 1}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1") as client:
        response = await client.post("/redteam/run", json=body)
    assert response.status_code == 200, response.text
    blocks = response.text.strip().split("\n\n")
    assert blocks[-1].startswith("event: error\ndata: ")
    error = json.loads(blocks[-1].split("data: ", 1)[1])
    assert error["type"] == "JudgeBlockedError"
    assert error["judge_blocked"] == {"provider": "azure", "model": DEPLOYMENT, "categories": ["jailbreak"],
                                      "fallback": "off"}
    assert PROMPT_MARK not in response.text
    events = [json.loads(b.split("data: ", 1)[1]) for b in blocks if "data: " in b]
    assert [e for e in events if "verdict" in e] == []
    assert len(systems) == 1 and systems[0].startswith(first_caller)
    assert fallback_calls == []


def _anthropic_filter_error() -> anthropic.BadRequestError:
    message = "Output blocked by content filtering policy"
    return anthropic.BadRequestError(message=message, response=httpx.Response(400, request=_request()), body=None)


async def _judge(cfg: llm.LLMConfig):
    from argus.judge import Judge

    return await Judge("", CostMeter(daily_cap_usd=100, per_run_cap_usd=100), cfg).judge(
        probe_name="p", attack_prompt=PROMPT_MARK, target_response="reply", rubric_text="rubric")


async def test_the_fast_judge_call_raises_the_block(monkeypatch):
    _stub_litellm(monkeypatch, _azure_block())
    _stub_anthropic(monkeypatch)
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _judge(_config())
    assert caught.value.categories == ("jailbreak",)


@pytest.mark.parametrize("strong_reply", ["block", "refusal"])
async def test_the_strong_judge_call_raises_the_block(monkeypatch, strong_reply):
    """A strong pass that is blocked, or refused and then blocked on the fallback, is never kept as a fast verdict."""
    fail = json.dumps({"verdict": "fail", "severity": "high", "confidence": 0.9, "reasoning": "leaked"})

    class Messages:
        async def create(self, **kwargs):
            if kwargs["model"] == "claude-haiku-4-5-20251001":
                return SimpleNamespace(content=[SimpleNamespace(text=fail)], stop_reason="end_turn",
                                       usage=SimpleNamespace(input_tokens=1, output_tokens=1))
            if strong_reply == "block":
                raise _anthropic_filter_error()
            return SimpleNamespace(content=[], stop_reason="refusal",
                                   usage=SimpleNamespace(input_tokens=1, output_tokens=0))

    monkeypatch.setattr(llm, "_anthropic_client", lambda api_key: SimpleNamespace(messages=Messages()))
    fallback_calls = _stub_litellm(monkeypatch, _azure_block())
    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"})
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await _judge(cfg)
    if strong_reply == "block":
        assert (caught.value.provider, caught.value.model) == ("anthropic", "claude-sonnet-4-6")
        assert fallback_calls == []
    else:
        assert (caught.value.provider, caught.value.categories) == ("azure", ("jailbreak",))


@pytest.mark.parametrize("module, call", [
    ("argus.persona_strategy", "_call_attacker_llm"),
    ("argus.iterative_pair", "_call_attacker_llm"),
    ("argus.iterative_tap", "_call_planner_llm"),
])
async def test_every_attacker_call_raises_the_block(monkeypatch, module, call):
    import importlib

    monkeypatch.setenv("REDTEAM_MODEL_PROVIDER", "azure")
    monkeypatch.setenv("REDTEAM_FAST_MODEL", DEPLOYMENT)
    _stub_litellm(monkeypatch, _azure_block())
    fallback_calls = _stub_anthropic(monkeypatch)
    with pytest.raises(llm.JudgeBlockedError):
        await getattr(importlib.import_module(module), call)("attacker system", PROMPT_MARK)
    assert fallback_calls == []


async def test_a_blocked_jev_explain_call_raises_instead_of_dropping_the_reason(monkeypatch):
    from argus import jev_judge

    cfg = llm.resolve_config({"REDTEAM_MODEL_PROVIDER": "jev", "TYPESAFE_API_KEY": "test",
                              "REDTEAM_EXPLAIN_MODEL": "explain-model"})
    _stub_litellm(monkeypatch, _azure_block())
    with pytest.raises(llm.JudgeBlockedError) as caught:
        await jev_judge._explain(cfg, None, "jev line", "fail", "p", PROMPT_MARK, "reply", "rubric")
    assert (caught.value.provider, caught.value.model) == ("litellm", "explain-model")
