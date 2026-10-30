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
import urllib.parse
from dataclasses import dataclass, replace
from typing import Mapping, Optional

logger = logging.getLogger(__name__)

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_AZURE = "azure"
PROVIDER_OPENAI = "openai"
PROVIDER_LITELLM = "litellm"
_VALID_PROVIDERS = (PROVIDER_ANTHROPIC, PROVIDER_AZURE, PROVIDER_OPENAI, PROVIDER_LITELLM)
PROVIDERS = _VALID_PROVIDERS

# The judge settings and the env vars they live in. CLI flags are written over these,
# so resolve_config stays the only place a judge is chosen.
JUDGE_ENV = {
    "provider": "REDTEAM_MODEL_PROVIDER",
    "model": "REDTEAM_FAST_MODEL",
    "strong_model": "REDTEAM_STRONG_MODEL",
    "api_base": "REDTEAM_LLM_API_BASE",
}

# litellm providers whose credentials its env check cannot see, so a refusal could be wrong:
# local servers need none; AWS profiles/roles, Google ADC and Azure AD or AZURE_OPENAI_API_KEY
# live outside the variables it checks. The pre-check refuses only when it is sure.
_LOCAL_PROVIDERS = frozenset({"ollama", "ollama_chat", "hosted_vllm", "vllm", "lm_studio", "llamafile",
                              "openai_like", "custom_openai", "xinference", "oobabooga", "lemonade"})
_AMBIENT_PREFIXES = ("bedrock", "sagemaker", "vertex_ai", "azure")
# Providers whose calls never send REDTEAM_LLM_API_BASE, and the setting they read instead.
NO_API_BASE = {PROVIDER_ANTHROPIC: "ANTHROPIC_BASE_URL", PROVIDER_AZURE: "AZURE_API_BASE"}

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

    def __init__(self, message: str, *, refusals: "list[ModelRefused] | None" = None):
        super().__init__(message)
        # Attempts where a model declined (stop_reason="refusal") rather than erroring.
        # They are billed, so callers meter them.
        self.refusals = list(refusals or [])
        self.refused = bool(self.refusals)


def record_refusals(meter, refusals) -> None:
    """Meter refused calls; they are billed like answered ones."""
    if meter is None or not refusals:
        return
    meter.record_many([(r.model, r.input_tokens, r.output_tokens) for r in refusals])


def record_completion(meter, out) -> None:
    """Meter every attempt of one completion, refused ones and the answer, before any cap check."""
    if meter is None:
        return
    meter.record_many([*((r.model, r.input_tokens, r.output_tokens) for r in out.refusals),
                       (out.model, out.input_tokens, out.output_tokens)])


class ModelRefused(RuntimeError):
    """The model declined the request (stop_reason="refusal")."""

    def __init__(self, message: str, *, model: str, input_tokens: int, output_tokens: int):
        super().__init__(message)
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


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
        """Name(s) of the env vars the chosen provider needs but lacks, comma-separated, else None."""
        if self.provider == PROVIDER_ANTHROPIC and not self.anthropic_api_key:
            return "ANTHROPIC_API_KEY"
        if self.provider == PROVIDER_OPENAI and not self.openai_api_key:
            return "OPENAI_API_KEY"
        if self.provider == PROVIDER_LITELLM:
            names: list[str] = []
            for model in dict.fromkeys((self.fast_model, self.strong_model)):
                names += [n for n in _litellm_missing_keys(model, self.api_base) if n not in names]
            return ", ".join(names) or None
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
    # Earlier attempts in this call that the model refused. They are billed too.
    refusals: tuple = ()


def missing_text(cfg: LLMConfig) -> Optional[str]:
    """`<NAME> is not set`, naming the model for litellm; None when nothing is missing."""
    name = cfg.missing_credential()
    if name is None:
        return None
    if cfg.provider == PROVIDER_LITELLM:
        models = " and ".join(dict.fromkeys((cfg.fast_model, cfg.strong_model)))
        # litellm lists every variable a provider can read (Gemini: either key will do).
        return f"litellm finds no credentials for {models}; it looks for {name}"
    return f"{name} is not set"


def credential_error(cfg: LLMConfig) -> Optional[str]:
    """Message for the missing credential of cfg's provider, or None. Shared by /redteam/run and run_local."""
    text = missing_text(cfg)
    if text is None:
        return None
    if cfg.provider == PROVIDER_LITELLM:
        return f"{text}. Set the variable your provider needs, or choose another judge (see the README)."
    return (
        f"{text} (REDTEAM_MODEL_PROVIDER={cfg.provider}). "
        "Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or set REDTEAM_MODEL_PROVIDER "
        "to azure or litellm (see the README)."
    )


def _litellm_missing_keys(model: str, api_base: Optional[str]) -> list[str]:
    """Env vars litellm says `model` needs and cannot find; [] whenever the answer could be wrong."""
    import litellm

    litellm.suppress_debug_info = True  # an unknown model would print litellm's provider list
    try:
        provider = litellm.get_llm_provider(model=model)[1]
    except Exception:  # noqa: BLE001 - litellm cannot route the name, so it cannot say what it needs
        return []
    if not provider or provider in _LOCAL_PROVIDERS or provider.startswith(_AMBIENT_PREFIXES):
        return []
    # A custom base usually means a gateway with its own auth, except on the openai route:
    # its SDK client refuses to start without OPENAI_API_KEY whatever the base.
    if api_base and provider != "openai":
        return []
    try:
        result = litellm.validate_environment(model=model)
    except Exception as e:  # noqa: BLE001 - a check that cannot run must not block the run
        logger.warning("litellm could not check credentials for %s: %s", model, e)
        return []
    return [str(n) for n in result.get("missing_keys") or []]


def judge_env(*, provider: Optional[str] = None, model: Optional[str] = None,
              strong_model: Optional[str] = None, api_base: Optional[str] = None,
              price: Optional[tuple[float, float]] = None,
              env: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """The env overrides for a judge chosen by flags; unset flags leave the env alone.

    `price` (USD per 1M tokens, input and output) is declared for the fast and strong
    models this choice resolves to. Raises ValueError when resolve_config would reject it.
    """
    from argus.cost_meter import price_env_names

    env = os.environ if env is None else env
    given = {"provider": provider, "model": model, "strong_model": strong_model, "api_base": api_base}
    out = {JUDGE_ENV[k]: v for k, v in given.items() if v is not None}
    cfg = resolve_config({**env, **out})
    if price is not None:
        for m in dict.fromkeys((cfg.fast_model, cfg.strong_model)):
            out.update(zip(price_env_names(m), (str(price[0]), str(price[1]))))
    return out


def judge_record(cfg: LLMConfig) -> dict:
    """The judge as data, for run.json. The api base keeps its host only: the URL can carry a key."""
    host = None
    # anthropic and azure never send REDTEAM_LLM_API_BASE, so naming it would record an unused endpoint.
    if cfg.api_base and cfg.provider not in NO_API_BASE:
        base = cfg.api_base if "//" in cfg.api_base else "//" + cfg.api_base
        try:
            u = urllib.parse.urlsplit(base)
            host = (u.hostname or "") + (f":{u.port}" if u.port else "")
        except ValueError:
            host = ""
        host = host or "set"
    fallback = cfg.fallback_provider if cfg.fallback_enabled else None
    return {"provider": cfg.provider, "fast_model": cfg.fast_model, "strong_model": cfg.strong_model,
            "api_base_host": host, "fallback_provider": fallback}


def describe(cfg: LLMConfig) -> str:
    """One line naming the judge, for the console and the report notes."""
    r = judge_record(cfg)
    text = f"{r['provider']}, fast {r['fast_model']}, strong {r['strong_model']}"
    if r["api_base_host"]:
        text += f", api base {r['api_base_host']}"
    if r["fallback_provider"]:
        text += f" (falls back to {r['fallback_provider']})"
    return text


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
    stop = getattr(resp, "stop_reason", None)
    if stop == "refusal":
        # Seen on attack-laden judge prompts; any partial text is not a usable answer.
        raise ModelRefused(
            f"anthropic declined the request (stop_reason={stop})",
            model=model, input_tokens=resp.usage.input_tokens, output_tokens=resp.usage.output_tokens,
        )
    texts = [b.text for b in resp.content if isinstance(getattr(b, "text", None), str)]
    if not texts:
        raise RuntimeError(f"anthropic returned no text (stop_reason={stop})")
    return Completion(
        text="\n".join(texts).strip(),
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
    refusals: list[ModelRefused] = []
    attempts = [(cfg.provider, cfg.model_for(role))]
    fb = cfg.fallback_provider
    if cfg.fallback_enabled and fb is not None:
        attempts.append((fb, _DEFAULTS[fb][role]))

    for provider, model in attempts:
        try:
            out = await _DISPATCH[provider](cfg, model, system, user, max_tokens)
            return replace(out, refusals=tuple(refusals)) if refusals else out
        except Exception as e:  # noqa: BLE001 — any provider error is a fallback trigger
            if isinstance(e, ModelRefused):
                refusals.append(e)
            errors.append(f"{provider}/{model}: {type(e).__name__}: {e}")
            logger.warning("redteam LLM call failed on %s/%s: %s", provider, model, e)

    raise AllProvidersFailed(
        f"all providers failed for role={role!r}: " + " | ".join(errors), refusals=refusals
    )
