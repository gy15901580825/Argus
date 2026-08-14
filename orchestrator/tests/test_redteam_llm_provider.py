"""Provider abstraction for the red-team LLM calls.

Before this, judge.py and the three attacker call sites each constructed
`anthropic.AsyncAnthropic` directly with hardcoded model ids, so the entire
red-team cost line — the product's largest — bypassed the Azure commitment the
rest of the stack runs on, and Anthropic was a single point of failure with no
equivalent of the planner's `fallback_client`.

Contract: `complete()` takes a ROLE (`fast` / `strong`), not a model id. The
provider resolves the role to a concrete model, and the caller records cost
against whatever model actually served the request.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from orchestrator.redteam import llm


# --------------------------------------------------------------------------
# Role resolution
# --------------------------------------------------------------------------

def test_anthropic_is_the_default_provider():
    """Deploying this must not silently move prod's judge to a different vendor."""
    cfg = llm.resolve_config(env={})
    assert cfg.provider == "anthropic"
    assert cfg.fast_model == "claude-haiku-4-5-20251001"
    assert cfg.strong_model == "claude-sonnet-4-6"


def test_azure_provider_resolves_azure_deployments():
    cfg = llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "azure"})
    assert cfg.provider == "azure"
    assert cfg.fast_model == "gpt-5.4-mini"


def test_models_are_individually_overridable():
    cfg = llm.resolve_config(env={
        "REDTEAM_MODEL_PROVIDER": "azure",
        "REDTEAM_FAST_MODEL": "gpt-5.4-nano",
        "REDTEAM_STRONG_MODEL": "gpt-5.4",
    })
    assert (cfg.fast_model, cfg.strong_model) == ("gpt-5.4-nano", "gpt-5.4")


def test_unknown_provider_is_rejected_at_config_time():
    with pytest.raises(ValueError, match="REDTEAM_MODEL_PROVIDER"):
        llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "bedrock"})


def test_escalation_is_a_noop_when_both_roles_resolve_to_one_model():
    """Azure ships a single chat deployment, so strong == fast unless the operator
    configures a second one. Judging twice with the same model buys nothing and
    costs real money."""
    cfg = llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "azure"})
    assert cfg.fast_model == cfg.strong_model
    assert cfg.escalation_is_meaningful is False

    anthropic_cfg = llm.resolve_config(env={})
    assert anthropic_cfg.escalation_is_meaningful is True


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

def _anthropic_response(text: str, in_tok: int = 100, out_tok: int = 20):
    resp = MagicMock()
    block = MagicMock()
    block.text = text
    resp.content = [block]
    resp.usage.input_tokens = in_tok
    resp.usage.output_tokens = out_tok
    return resp


def _litellm_response(text: str, in_tok: int = 100, out_tok: int = 20):
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message.content = text
    resp.usage.prompt_tokens = in_tok
    resp.usage.completion_tokens = out_tok
    return resp


@pytest.mark.asyncio
async def test_anthropic_path_returns_text_and_token_counts():
    cfg = llm.resolve_config(env={"ANTHROPIC_API_KEY": "sk-ant-x"})
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=_anthropic_response("hello", 11, 22))
    with patch.object(llm, "_anthropic_client", return_value=client):
        out = await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    assert out.text == "hello"
    assert (out.input_tokens, out.output_tokens) == (11, 22)
    assert out.model == "claude-haiku-4-5-20251001"


@pytest.mark.asyncio
async def test_azure_path_goes_through_litellm_and_maps_token_fields():
    cfg = llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "azure"})
    with patch.object(llm, "_acompletion", new=AsyncMock(return_value=_litellm_response("hi", 33, 44))) as m:
        out = await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    assert out.text == "hi"
    assert (out.input_tokens, out.output_tokens) == (33, 44)
    assert out.model == "gpt-5.4-mini"
    assert m.await_args.kwargs["model"] == "azure/gpt-5.4-mini"


@pytest.mark.asyncio
async def test_azure_call_never_sends_temperature():
    """gpt-5.4-mini rejects the parameter outright (CLAUDE.md pitfall #2)."""
    cfg = llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "azure"})
    with patch.object(llm, "_acompletion", new=AsyncMock(return_value=_litellm_response("x"))) as m:
        await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    assert "temperature" not in m.await_args.kwargs


@pytest.mark.asyncio
async def test_azure_sends_system_as_a_message_not_a_top_level_field():
    cfg = llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "azure"})
    with patch.object(llm, "_acompletion", new=AsyncMock(return_value=_litellm_response("x"))) as m:
        await llm.complete(cfg, role="fast", system="SYS", user="USR", max_tokens=50)
    msgs = m.await_args.kwargs["messages"]
    assert msgs[0] == {"role": "system", "content": "SYS"}
    assert msgs[1] == {"role": "user", "content": "USR"}


# --------------------------------------------------------------------------
# Cross-provider fallback — the single-point-of-failure fix
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_anthropic_failure_falls_back_to_azure():
    cfg = llm.resolve_config(env={"ANTHROPIC_API_KEY": "sk-ant-x"})
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RuntimeError("anthropic 529 overloaded"))
    with patch.object(llm, "_anthropic_client", return_value=client), \
         patch.object(llm, "_acompletion", new=AsyncMock(return_value=_litellm_response("from-azure"))) as m:
        out = await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    assert out.text == "from-azure"
    # Cost must be attributed to the model that actually served it.
    assert out.model == "gpt-5.4-mini"
    assert m.await_args.kwargs["model"] == "azure/gpt-5.4-mini"


@pytest.mark.asyncio
async def test_azure_failure_falls_back_to_anthropic():
    cfg = llm.resolve_config(env={"REDTEAM_MODEL_PROVIDER": "azure", "ANTHROPIC_API_KEY": "sk-ant-x"})
    client = MagicMock()
    client.messages.create = AsyncMock(return_value=_anthropic_response("from-anthropic"))
    with patch.object(llm, "_acompletion", new=AsyncMock(side_effect=RuntimeError("azure 429"))), \
         patch.object(llm, "_anthropic_client", return_value=client):
        out = await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    assert out.text == "from-anthropic"
    assert out.model == "claude-haiku-4-5-20251001"


@pytest.mark.asyncio
async def test_both_providers_failing_raises_with_both_causes_named():
    cfg = llm.resolve_config(env={"ANTHROPIC_API_KEY": "sk-ant-x"})
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RuntimeError("anthropic down"))
    with patch.object(llm, "_anthropic_client", return_value=client), \
         patch.object(llm, "_acompletion", new=AsyncMock(side_effect=RuntimeError("azure down"))):
        with pytest.raises(llm.AllProvidersFailed) as e:
            await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    assert "anthropic down" in str(e.value)
    assert "azure down" in str(e.value)


@pytest.mark.asyncio
async def test_fallback_can_be_disabled():
    """An operator running deliberately on one vendor should be able to fail loudly
    rather than silently spending on the other."""
    cfg = llm.resolve_config(env={"REDTEAM_LLM_FALLBACK": "off", "ANTHROPIC_API_KEY": "sk-ant-x"})
    assert cfg.fallback_enabled is False
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RuntimeError("anthropic down"))
    with patch.object(llm, "_anthropic_client", return_value=client), \
         patch.object(llm, "_acompletion", new=AsyncMock(return_value=_litellm_response("should-not-be-used"))) as m:
        with pytest.raises(llm.AllProvidersFailed):
            await llm.complete(cfg, role="fast", system="s", user="u", max_tokens=50)
    m.assert_not_awaited()
