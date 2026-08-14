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
_VALID_PROVIDERS = (PROVIDER_ANTHROPIC, PROVIDER_AZURE)

# Defaults per provider. Anthropic's are the models the judge shipped with; the
# defaults must not change behaviour for an operator who sets nothing.
_DEFAULTS = {
    PROVIDER_ANTHROPIC: {"fast": "claude-haiku-4-5-20251001", "strong": "claude-sonnet-4-6"},
    # Azure exposes a single chat deployment in this project's subscription, so
    # both roles land on it unless the operator configures a second one. See
    # `escalation_is_meaningful`.
    PROVIDER_AZURE: {"fast": "gpt-5.4-mini", "strong": "gpt-5.4-mini"},
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

    @property
    def fallback_provider(self) -> str:
        return PROVIDER_AZURE if self.provider == PROVIDER_ANTHROPIC else PROVIDER_ANTHROPIC

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


def resolve_config(env: Optional[Mapping[str, str]] = None) -> LLMConfig:
    env = os.environ if env is None else env
    provider = env.get("REDTEAM_MODEL_PROVIDER", PROVIDER_ANTHROPIC).strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise ValueError(
            f"REDTEAM_MODEL_PROVIDER={provider!r} is not supported; "
            f"expected one of {list(_VALID_PROVIDERS)}"
        )
    defaults = _DEFAULTS[provider]
    return LLMConfig(
        provider=provider,
        fast_model=env.get("REDTEAM_FAST_MODEL") or defaults["fast"],
        strong_model=env.get("REDTEAM_STRONG_MODEL") or defaults["strong"],
        fallback_enabled=env.get("REDTEAM_LLM_FALLBACK", "on").strip().lower() != "off",
        anthropic_api_key=env.get("ANTHROPIC_API_KEY"),
    )


# Indirection points so tests can patch without touching the SDKs.
def _anthropic_client(api_key: Optional[str]):
    import anthropic

    return anthropic.AsyncAnthropic(api_key=api_key)


async def _acompletion(**kwargs):
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


_DISPATCH = {PROVIDER_ANTHROPIC: _call_anthropic, PROVIDER_AZURE: _call_azure}


async def complete(cfg: LLMConfig, *, role: str, system: str, user: str, max_tokens: int) -> Completion:
    """Run one completion for `role`, falling back to the other provider on failure.

    The returned `Completion.model` is whichever model served the request — record
    cost against that, not against the model you asked for.
    """
    errors: list[str] = []
    attempts = [(cfg.provider, cfg.model_for(role))]
    if cfg.fallback_enabled:
        fb = cfg.fallback_provider
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
