"""Provider abstraction for red-team LLM calls (judge + attackers).

Every red-team LLM call used to construct `anthropic.AsyncAnthropic` inline with a
hardcoded model id. Two consequences: the product's largest cost line bypassed the
Azure commitment the rest of the stack runs on, and Anthropic was a single point of
failure with no equivalent of `planner/fallback_client.py`.

Callers here ask for a **role**, not a model:

    fast    judge's first pass, and every attacker/planner turn
    strong  the judge's escalation pass on high-severity findings

The provider resolves the role to a concrete model and reports back which model
actually served the request, so `CostMeter` bills the right rate even when a
fallback fired.

`openai` and `litellm` exist for users without an Anthropic key (`litellm` reaches
anything litellm speaks, e.g. a local Ollama model). They never fall back to another
vendor: a judge silently re-run on a different vendor would send the operator's
target traffic somewhere they did not choose, so failure surfaces instead.

Mirrors the naming of the planner's knobs (`PLANNER_MODEL_PROVIDER`,
`PLANNER_MODEL`, `PLANNER_FALLBACK_MODEL`).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Mapping, Optional

logger = logging.getLogger(__name__)

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_AZURE = "azure"
PROVIDER_OPENAI = "openai"
PROVIDER_LITELLM = "litellm"
_VALID_PROVIDERS = (PROVIDER_ANTHROPIC, PROVIDER_AZURE, PROVIDER_OPENAI, PROVIDER_LITELLM)

# Defaults per provider. Anthropic's are the models the judge shipped with; the
# defaults must not change behaviour for an operator who sets nothing.
_DEFAULTS = {
    PROVIDER_ANTHROPIC: {"fast": "claude-haiku-4-5-20251001", "strong": "claude-sonnet-4-6"},
    # Azure exposes a single chat deployment in this project's subscription, so
    # both roles land on it unless the operator configures a second one. See
    # `escalation_is_meaningful`.
    PROVIDER_AZURE: {"fast": "gpt-5.4-mini", "strong": "gpt-5.4-mini"},
    PROVIDER_OPENAI: {"fast": "gpt-5.6-luna", "strong": "gpt-5.6-terra"},
    # No litellm entry: the model string is user-supplied (REDTEAM_FAST_MODEL).
}


class AllProvidersFailed(RuntimeError):
    """Raised when the primary — and the fallback, if enabled — both failed."""


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    fast_model: str
    strong_model: str
    fallback_enabled: bool
    anthropic_api_key: Optional[str]
    openai_api_key: Optional[str] = None
    api_base: Optional[str] = None

    @property
    def fallback_provider(self) -> Optional[str]:
        # openai/litellm never fall back: see module docstring.
        if self.provider == PROVIDER_ANTHROPIC:
            return PROVIDER_AZURE
        if self.provider == PROVIDER_AZURE:
            return PROVIDER_ANTHROPIC
        return None

    def missing_credential(self) -> Optional[str]:
        """Name of the env var the chosen provider needs but lacks, else None."""
        if self.provider == PROVIDER_ANTHROPIC and not self.anthropic_api_key:
            return "ANTHROPIC_API_KEY"
        if self.provider == PROVIDER_OPENAI and not self.openai_api_key:
            return "OPENAI_API_KEY"
        return None

    @property
    def escalation_is_meaningful(self) -> bool:
        """False when both roles resolve to the same model.

        The judge escalates high-severity findings to a stronger model for a second
        opinion. If strong == fast that is the same model judging twice: no extra
        signal, double the cost and latency. The judge checks this and skips.
        """
        return self.fast_model != self.strong_model

    def model_for(self, role: str) -> str:
        if role == "fast":
            return self.fast_model
        if role == "strong":
            return self.strong_model
        raise ValueError(f"unknown role {role!r}; expected 'fast' or 'strong'")


@dataclass(frozen=True)
class Completion:
    text: str
    input_tokens: int
    output_tokens: int
    model: str  # the model that actually served the request, post-fallback


def credential_error(cfg: LLMConfig) -> Optional[str]:
    """Message for the missing credential of cfg's provider, or None. Shared by /redteam/run and run_local."""
    name = cfg.missing_credential()
    if name is None:
        return None
    return (
        f"{name} is not set (REDTEAM_MODEL_PROVIDER={cfg.provider}). "
        "Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or set REDTEAM_MODEL_PROVIDER "
        "to azure or litellm (see the README)."
    )


def resolve_config(env: Optional[Mapping[str, str]] = None) -> LLMConfig:
    env = os.environ if env is None else env
    provider = (env.get("REDTEAM_MODEL_PROVIDER") or "").strip().lower()
    if not provider:
        # Only an OpenAI key present: use it rather than demand an Anthropic one.
        if not env.get("ANTHROPIC_API_KEY") and env.get("OPENAI_API_KEY"):
            provider = PROVIDER_OPENAI
        else:
            provider = PROVIDER_ANTHROPIC
    if provider not in _VALID_PROVIDERS:
        raise ValueError(
            f"REDTEAM_MODEL_PROVIDER={provider!r} is not supported; "
            f"expected one of {list(_VALID_PROVIDERS)}"
        )
    if provider == PROVIDER_LITELLM:
        fast = env.get("REDTEAM_FAST_MODEL")
        if not fast:
            raise ValueError("REDTEAM_MODEL_PROVIDER=litellm requires REDTEAM_FAST_MODEL")
        strong = env.get("REDTEAM_STRONG_MODEL") or fast
    else:
        defaults = _DEFAULTS[provider]
        fast = env.get("REDTEAM_FAST_MODEL") or defaults["fast"]
        strong = env.get("REDTEAM_STRONG_MODEL") or defaults["strong"]
    return LLMConfig(
        provider=provider,
        fast_model=fast,
        strong_model=strong,
        fallback_enabled=env.get("REDTEAM_LLM_FALLBACK", "on").strip().lower() != "off",
        anthropic_api_key=env.get("ANTHROPIC_API_KEY"),
        openai_api_key=env.get("OPENAI_API_KEY"),
        api_base=env.get("REDTEAM_LLM_API_BASE") or None,
    )


# Indirection points so tests can patch without touching the SDKs.
def _anthropic_client(api_key: Optional[str]):
    import anthropic

    return anthropic.AsyncAnthropic(api_key=api_key)


async def _acompletion(**kwargs):
    import litellm

    # Stops litellm printing "Provider List" to stdout after every bare-model call.
    litellm.suppress_debug_info = True
    from litellm import acompletion

    return await acompletion(**kwargs)


async def _call_anthropic(cfg: LLMConfig, model: str, system: str, user: str, max_tokens: int) -> Completion:
    client = _anthropic_client(cfg.anthropic_api_key)
    resp = await client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return Completion(
        text=resp.content[0].text.strip(),
        input_tokens=resp.usage.input_tokens,
        output_tokens=resp.usage.output_tokens,
        model=model,
    )


async def _call_azure(cfg: LLMConfig, model: str, system: str, user: str, max_tokens: int) -> Completion:
    # No `temperature`: gpt-5.4-mini rejects the parameter outright.
    resp = await _acompletion(
        model=f"azure/{model}",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_tokens=max_tokens,
        stream=False,
    )
    usage = getattr(resp, "usage", None)
    return Completion(
        text=(resp.choices[0].message.content or "").strip(),
        input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
        output_tokens=getattr(usage, "completion_tokens", 0) or 0,
        model=model,
    )


async def _call_litellm(cfg: LLMConfig, model: str, system: str, user: str, max_tokens: int) -> Completion:
    # No `temperature`, same as azure: newer OpenAI models reject it.
    kwargs = {}
    if cfg.provider == PROVIDER_OPENAI:
        litellm_model = f"openai/{model}"
        kwargs["api_key"] = cfg.openai_api_key
    else:
        litellm_model = model
    if cfg.api_base:
        kwargs["api_base"] = cfg.api_base
    resp = await _acompletion(
        model=litellm_model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_tokens=max_tokens,
        stream=False,
        **kwargs,
    )
    usage = getattr(resp, "usage", None)
    return Completion(
        text=(resp.choices[0].message.content or "").strip(),
        input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
        output_tokens=getattr(usage, "completion_tokens", 0) or 0,
        model=model,
    )


_DISPATCH = {
    PROVIDER_ANTHROPIC: _call_anthropic,
    PROVIDER_AZURE: _call_azure,
    PROVIDER_OPENAI: _call_litellm,
    PROVIDER_LITELLM: _call_litellm,
}


async def complete(cfg: LLMConfig, *, role: str, system: str, user: str, max_tokens: int) -> Completion:
    """Run one completion for `role`, falling back to the other provider on failure.

    The returned `Completion.model` is whichever model served the request — record
    cost against that, not against the model you asked for.
    """
    errors: list[str] = []
    attempts = [(cfg.provider, cfg.model_for(role))]
    fb = cfg.fallback_provider
    if cfg.fallback_enabled and fb is not None:
        attempts.append((fb, _DEFAULTS[fb][role]))

    for provider, model in attempts:
        try:
            return await _DISPATCH[provider](cfg, model, system, user, max_tokens)
        except Exception as e:  # noqa: BLE001 — any provider error is a fallback trigger
            errors.append(f"{provider}/{model}: {type(e).__name__}: {e}")
            logger.warning("redteam LLM call failed on %s/%s: %s", provider, model, e)

    raise AllProvidersFailed(
        f"all providers failed for role={role!r}: " + " | ".join(errors)
    )
