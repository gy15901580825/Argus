"""The judge flags shared by every command that calls the LLM judge."""
from __future__ import annotations

import contextlib
import functools
import math
import os

import click
from click.core import ParameterSource

from argus import llm

PARAMS = ("judge_provider", "judge_model", "judge_strong_model", "judge_api_base", "judge_price")


def _parse_price(ctx: click.Context, param: click.Parameter, value: str | None):
    if value is None:
        return None
    parts = value.split(",")
    try:
        price = tuple(float(p) for p in parts)
    except ValueError:
        price = ()
    if len(price) != 2 or not all(math.isfinite(p) and p >= 0 for p in price):
        raise click.BadParameter("must be INPUT,OUTPUT: two numbers >= 0, USD per 1M tokens, e.g. 0.30,2.50")
    return price


_OPTIONS = [
    click.option("--judge-provider", "judge_provider", type=click.Choice(llm.PROVIDERS), default=None,
                 help="Judge provider (env REDTEAM_MODEL_PROVIDER). Default: anthropic, or openai when only "
                      "OPENAI_API_KEY is set. litellm reaches any model litellm supports and needs --judge-model."),
    click.option("--judge-model", "judge_model", default=None, metavar="MODEL",
                 help="Judge model for every verdict (env REDTEAM_FAST_MODEL). With litellm, a litellm model "
                      "string such as gemini/gemini-2.5-flash or ollama/qwen2.5:32b."),
    click.option("--judge-strong-model", "judge_strong_model", default=None, metavar="MODEL",
                 help="Model that re-checks high-severity verdicts (env REDTEAM_STRONG_MODEL). "
                      "Default: the provider's, or --judge-model with litellm."),
    click.option("--judge-api-base", "judge_api_base", default=None, metavar="URL",
                 help="Base URL for openai or litellm judges, such as a self-hosted OpenAI-compatible "
                      "server (env REDTEAM_LLM_API_BASE)."),
    click.option("--judge-price", "judge_price", default=None, callback=_parse_price, metavar="INPUT,OUTPUT",
                 help="USD per 1M input and output tokens for this run's judge models, for the cost estimate "
                      "and --per-run-cap (env REDTEAM_PRICE_<MODEL>_INPUT and _OUTPUT)."),
]


def typed_flags(ctx: click.Context) -> list[str]:
    """The judge flags given on the command line, as --flag names."""
    return ["--" + p.replace("_", "-") for p in PARAMS if ctx.get_parameter_source(p) == ParameterSource.COMMANDLINE]


@contextlib.contextmanager
def _env_applied(overrides: dict[str, str]):
    saved = {k: os.environ.get(k) for k in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def judge_options(f):
    """Add the judge flags. They are written over their env vars for the command's duration, so
    llm.resolve_config, which every judge, attacker and estimate reads, sees them."""

    @functools.wraps(f)
    def wrapper(*args, judge_provider, judge_model, judge_strong_model, judge_api_base, judge_price, **kwargs):
        overrides: dict[str, str] = {}
        typed = typed_flags(click.get_current_context())
        # `run` without --local: the server chooses its judge, so say that before judging the flags.
        if typed and kwargs.get("local") is False:
            verb = "needs" if len(typed) == 1 else "need"
            raise click.UsageError(f"{', '.join(typed)} {verb} --local; in server mode the server chooses the judge")
        if any(v is not None for v in (judge_provider, judge_model, judge_strong_model, judge_api_base, judge_price)):
            provider = judge_provider or os.environ.get(llm.JUDGE_ENV["provider"], "")
            if provider.strip().lower() == llm.PROVIDER_LITELLM and not (
                    judge_model or os.environ.get(llm.JUDGE_ENV["model"])):
                raise click.UsageError("the litellm judge needs a model: pass --judge-model, such as "
                                       "gemini/gemini-2.5-flash (or set REDTEAM_FAST_MODEL)")
            try:
                overrides = llm.judge_env(provider=judge_provider, model=judge_model, strong_model=judge_strong_model,
                                          api_base=judge_api_base, price=judge_price)
            except ValueError as e:
                raise click.UsageError(str(e)) from None
            cfg = llm.resolve_config({**os.environ, **overrides})
            if judge_api_base is not None and cfg.provider in llm.NO_API_BASE:
                raise click.UsageError(f"--judge-api-base applies to openai and litellm judges; the {cfg.provider} "
                                       f"judge reads its endpoint from {llm.NO_API_BASE[cfg.provider]}")
            if judge_price is not None and cfg.fast_model != cfg.strong_model:
                click.echo(f"Warning: --judge-price sets the same price for {cfg.fast_model} and {cfg.strong_model}. "
                           "If they differ, declare each with REDTEAM_PRICE_<MODEL>_INPUT and _OUTPUT.", err=True)
        with _env_applied(overrides):
            return f(*args, **kwargs)

    for option in reversed(_OPTIONS):
        wrapper = option(wrapper)
    return wrapper
