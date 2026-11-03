import asyncio
import json
from dataclasses import replace

import click

from argus.targets import build_target
from argus.targets.custom_http import run_log_from_metadata
from argus_transport import (
    SafeReasonCode,
    TransportContext,
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
        return

    async def execute_transport():
        with local_transport_mode():
            return await V2Run(
                transport, policy=execution_policy(transport)
            ).attempt(TransportContext(prompt="ping"))

    result = asyncio.run(execute_transport())
    if result.outcome == TransportOutcome.SUCCEEDED:
        try:
            run_log_from_metadata(result.as_dict()["metadata"])
        except (ValueError, TypeError):
            result = replace(
                result,
                outcome=TransportOutcome.TARGET_ERROR,
                response_text=None,
                reason_code=SafeReasonCode.MAPPING_ERROR,
            )
    requests = result.diagnostics.get("requests", {})
    click.echo(f"HTTP.status: {result.http_status}")
    click.echo(f"outcome.selected: {result.matched_rule_id} -> {result.outcome.value}")
    click.echo(
        " ".join(
            f"requests.{name}={requests.get(name, 0)}"
            for name in ("submit", "poll", "retry")
        )
    )
    if result.outcome not in {TransportOutcome.SUCCEEDED, TransportOutcome.BLOCKED}:
        raise click.ClickException(
            f"transport.{result.reason_code.value}: {result.outcome.value}; check configured response paths"
        )
