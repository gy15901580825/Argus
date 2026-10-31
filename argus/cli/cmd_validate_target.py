"""argus-probe validate-target — quick reachability check on a target endpoint."""

import asyncio
import json
from pathlib import Path

import click
import httpx
import yaml

from argus.cli import run_json
from argus.cli.target_loader import TargetLoadError, check_target_spec

# Kinds that answer a chat prompt. The others (A2A, MCP and vLLM servers, testbed agents, uploads)
# are checked by their probes, so a ping proves nothing about them.
_CHAT_KINDS = ("openai_compat", "anthropic_native", "custom_http", "web_chat")


def _failure(exc: Exception) -> str:
    from argus.runner import _named
    from argus.targets._base import TargetBlockedError

    if isinstance(exc, httpx.HTTPStatusError):
        return f"target returned {exc.response.status_code}: {exc.response.text[:200]}"
    if isinstance(exc, TargetBlockedError):
        return f"target withheld its reply: {exc}"
    code = getattr(exc, "status_code", None)  # SDK errors such as anthropic.APIStatusError
    if isinstance(code, int):
        return f"target returned {code}: {exc}"
    if isinstance(exc, httpx.RequestError):
        return f"network error: {_named(exc)}"
    return f"target request failed: {_named(exc)}"


async def _ping(target) -> str:
    try:
        text, _ = await target.send_prompt("ping")
        return text
    finally:
        await target.aclose()  # web_chat holds a browser


def _parse(text: str):
    # JSON first, as `run` reads it; YAML for specs written before `run` required JSON.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


@click.command()
@click.option("--target", "target_file", type=click.Path(exists=True, dir_okay=False), required=True)
def cmd_validate_target(target_file: str):
    """Send one prompt to a chat target the way `run` does and report whether it answered."""
    from argus.targets import build_target

    try:
        raw = _parse(Path(target_file).read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise click.ClickException(f"cannot read the target file as JSON or YAML: {e}")
    if isinstance(raw, dict) and "kind" not in raw:
        raw = {"kind": "openai_compat", **raw}  # specs written before `kind` existed
    try:
        spec, substituted = check_target_spec(raw)
    except TargetLoadError as e:
        raise click.ClickException(str(e))
    kind = spec["kind"]
    # The same masking as run's reports: expanded $VARs and secret-named fields.
    secrets = run_json.run_secrets(spec, substituted)

    def fail(message: str):
        raise click.ClickException(run_json.mask_text(message, secrets))

    try:
        target = build_target(spec)
    except Exception as e:  # spec values the adapter rejects (a bad JSONPath, a wrong type)
        fail(f"target spec invalid: {type(e).__name__}: {e}")
    if kind not in _CHAT_KINDS:
        raise click.UsageError(
            f"validate-target checks chat targets ({', '.join(_CHAT_KINDS)}), not {kind}. "
            f"Run its probes instead: argus-probe run --local --target {target_file} --probes all"
        )
    try:
        text = asyncio.run(_ping(target))
    except Exception as e:  # every failure is the answer this command exists to give
        fail(_failure(e))
    if not text.strip():
        fail("target replied, but the reply text is empty; check the response shape or path")
    where = raw.get("endpoint_url") or raw.get("request_url") or raw.get("url") or f"anthropic {raw['model']}"
    click.echo(run_json.mask_text(f"OK — target {where} replied with {len(text)} chars", secrets))
