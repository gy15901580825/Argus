"""argus-probe validate-target — quick reachability check on a target endpoint."""

import asyncio
from pathlib import Path

import click
import httpx
import yaml

from argus.cli.target_loader import TargetLoadError, check_target_spec

# Kinds that answer a chat prompt. The others (MCP and vLLM servers, testbed agents, uploads)
# are checked by their probes, so a ping proves nothing about them.
_CHAT_KINDS = ("openai_compat", "anthropic_native", "custom_http")


def _failure(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"target returned {exc.response.status_code}: {exc.response.text[:200]}"
    from argus.targets._base import TargetBlockedError

    if isinstance(exc, TargetBlockedError):
        return f"target withheld its reply: {exc}"
    code = getattr(exc, "status_code", None)  # SDK errors such as anthropic.APIStatusError
    if isinstance(code, int):
        return f"target returned {code}: {exc}"
    if isinstance(exc, httpx.RequestError):
        return f"network error: {exc or type(exc).__name__}"
    return f"target request failed: {type(exc).__name__}: {exc}"


@click.command()
@click.option("--target", "target_file", type=click.Path(exists=True), required=True)
def cmd_validate_target(target_file: str):
    """Send one prompt to a chat target the way `run` does and report whether it answered."""
    from argus.targets import build_target

    try:
        raw = yaml.safe_load(Path(target_file).read_text())
    except yaml.YAMLError as e:
        raise click.ClickException(f"target file is not valid JSON or YAML: {e}")
    if isinstance(raw, dict) and "kind" not in raw:
        raw = {"kind": "openai_compat", **raw}  # specs written before `kind` existed
    try:
        spec, _ = check_target_spec(raw)
    except TargetLoadError as e:
        raise click.ClickException(str(e))
    kind = spec["kind"]
    if kind not in _CHAT_KINDS:
        raise click.UsageError(
            f"validate-target checks chat targets ({', '.join(_CHAT_KINDS)}), not {kind}. "
            f"Run its probes instead: argus-probe run --local --target {target_file} --probes all"
        )
    try:
        target = build_target(spec)
    except (TypeError, ValueError) as e:
        raise click.ClickException(f"target spec invalid: {e}")
    try:
        text, _ = asyncio.run(target.send_prompt("ping"))
    except Exception as e:  # every failure is the answer this command exists to give
        raise click.ClickException(_failure(e))
    if not text.strip():
        raise click.ClickException("target replied, but the reply text is empty; check the response shape or path")
    where = spec.get("endpoint_url") or spec.get("request_url") or f"anthropic {spec['model']}"
    click.echo(f"OK — target {where} replied with {len(text)} chars")
