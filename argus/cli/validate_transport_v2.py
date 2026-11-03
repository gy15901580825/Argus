import asyncio
import json
from dataclasses import replace

import click

from argus.targets import build_target
from argus.targets.custom_http import run_log_from_metadata
from argus.cli.local_run import cleanup_lines
from argus_transport.runtime_v2 import TargetRunStopped
from argus_transport.spec_v2 import TransportContextV2, material_binding, provision_checklist
from argus_transport import (
    SafeReasonCode,
    TransportOutcome,
    TransportSpecV2,
    V2Run,
    execution_policy,
    local_transport_mode,
    parse_transport_spec,
    with_origin,
)


def validate(
    spec: dict, *, offline: bool, endpoint_override: str | None
) -> None:
    try:
        transport = build_target(spec).spec.transport
        if not isinstance(transport, TransportSpecV2):
            raise ValueError("version 2 transport required")
    except Exception as exc:
        raise click.ClickException(
            f"target spec invalid: {type(exc).__name__}"
        ) from exc
    if endpoint_override:
        try:
            transport = parse_transport_spec(
                with_origin(transport.to_dict(), endpoint_override)
            )
        except ValueError:
            raise click.UsageError(
                "version 2 endpoint override takes an origin such as http://127.0.0.1:8080"
            ) from None
    if offline:
        click.echo("spec.transport.version: 2 OK")
        click.echo(f"request.method: {transport.request.method}")
        click.echo("request.url: <configured endpoint>")
        for name, values in (
            ("request.placeholders", transport.request.placeholders),
            ("request.query", transport.request.query),
            ("let.run", transport.let.run),
            ("let.attempt", transport.let.attempt),
        ):
            if values:
                click.echo(f"{name}: {json.dumps(list(values))}")
        click.echo("requests.submit=0 requests.poll=0 requests.retry=0")
        if transport.lifecycle.provision is not None:
            click.echo("provision.manual (shown when a find step matches nothing):")
            for line in provision_checklist(transport, step_id=None, hint=None):
                click.echo(line)
        return

    async def execute_transport():
        with local_transport_mode():
            run = V2Run(transport, policy=execution_policy(transport))
            try:
                result = await run.attempt(TransportContextV2(
                    prompt="ping",
                    material="Argus validation sample." if material_binding(transport) != "none" else None,
                ))
            except TargetRunStopped as stopped:
                result = stopped
            finally:
                try:
                    await run.close()
                except TargetRunStopped as stopped:
                    result = stopped
            return result, run.ledger.counts, run.cleanup_report()

    result, requests, cleanup = asyncio.run(execute_transport())
    if not isinstance(result, TargetRunStopped) and result.outcome == TransportOutcome.SUCCEEDED:
        try:
            run_log_from_metadata(result.as_dict()["metadata"])
        except (ValueError, TypeError):
            result = replace(
                result,
                outcome=TransportOutcome.TARGET_ERROR,
                response_text=None,
                reason_code=SafeReasonCode.MAPPING_ERROR,
            )
    if isinstance(result, TargetRunStopped):
        cleanup_note = (
            "No further request was sent, cleanup included."
            if result.reason in {"stop_on_status", "alert", "unsafe_location", "credential_echo"}
            else "Configured cleanup remained enabled."
        )
        click.echo(f"Target stopped the run: {result}. {cleanup_note}")
        if result.reason == "not_provisioned":
            for line in getattr(result, "checklist", ()):
                click.echo(line)
    else:
        click.echo(f"HTTP.status: {result.http_status}")
        click.echo(f"outcome.selected: {result.matched_rule_id} -> {result.outcome.value}")
    names = ["submit", "poll", "retry"]
    if transport.lifecycle.run or transport.lifecycle.attempt:
        names.extend(["setup", "cleanup"])
    if transport.lifecycle.provision is not None:
        names.append("provision")
    click.echo(
        " ".join(
            f"requests.{name}={requests.get(name, 0)}"
            for name in names
        )
    )
    if cleanup is not None:
        for line in cleanup_lines(cleanup):
            click.echo(line)
    if isinstance(result, TargetRunStopped):
        raise click.ClickException(f"target stopped the run: {result}")
    if cleanup is not None and not cleanup["complete"]:
        raise click.ClickException("target cleanup incomplete")
    if result.outcome not in {TransportOutcome.SUCCEEDED, TransportOutcome.BLOCKED}:
        raise click.ClickException(
            f"transport.{result.reason_code.value}: {result.outcome.value}; check configured response paths"
        )
