import asyncio
from pathlib import Path
from dataclasses import replace

import click

from argus.drafting.draft import DraftState, artifact_destinations, choose_without_model, compile_draft, validate_server_origin, write_artifacts
from argus.drafting.openapi import DocumentError, catalog_operations, load_openapi
from argus.drafting.proposal import propose_choices
from argus.cli.validate_transport_v2 import validate
from argus.cli.verify_local import verify_local as verify_draft_local
from argus.drafting.scenario import read_scenario


@click.command("draft-target")
@click.option("--openapi", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--operation", help="Select a documented operation ID.")
@click.option("--server-origin", help="Select one origin declared in root servers.")
@click.option("--intent", default="Ask an agent a question, optionally with third-party material.", show_default=True)
@click.option("--no-model", is_flag=True, help="Use only deterministic local document extraction.")
@click.option("--verify-local", is_flag=True, help="Verify a temporary copy on an isolated loopback fake.")
@click.option("--scenario", "scenario_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Independent version-one scenario JSON for local semantic checks.")
def cmd_draft_target(input_path, out, operation, server_origin, intent, no_model, verify_local, scenario_path):
    """Draft a transport v2 target and review gaps from local OpenAPI 3.x."""
    if scenario_path is not None and not verify_local:
        raise click.UsageError("--scenario requires --verify-local.")
    if out.suffix.lower() != ".json":
        raise click.UsageError("--out must name a JSON file.")
    if not out.parent.is_dir():
        raise click.UsageError("--out parent directory must exist.")
    if server_origin is not None:
        try:
            validate_server_origin(server_origin)
        except (ValueError, TypeError):
            raise click.UsageError("--server-origin must be a bare HTTP(S) origin.") from None
    try:
        artifact_destinations(out)
        document = load_openapi(input_path)
        catalog = catalog_operations(document)
        if operation is not None and operation not in {op.id for op in catalog.operations}:
            raise click.UsageError("--operation must select a documented operation ID.")
        scenario = read_scenario(scenario_path, catalog=catalog) if scenario_path is not None else None
        local_result = None
        proposal = None
        if no_model:
            choices = choose_without_model(catalog, operation=operation, server_origin=server_origin, intent=intent)
        else:
            proposal = asyncio.run(propose_choices(catalog, operation=operation, server_origin=server_origin, intent=intent))
            choices = proposal.choices
        artifacts = compile_draft(catalog, choices)
        if proposal is not None:
            artifacts = artifacts.with_proposal(proposal.disclosure.to_dict())
        if artifacts.spec is not None:
            validate(artifacts.spec, offline=True, endpoint_override=None)
            artifacts = artifacts.validated()
        if verify_local:
            local_result = asyncio.run(verify_draft_local(artifacts.spec, catalog=catalog, scenario=scenario, gaps=artifacts.gaps))
            artifacts = replace(artifacts, provenance={**artifacts.provenance,
                "validation": {**artifacts.provenance.get("validation", {}), "local": local_result.as_dict()}})
        written = write_artifacts(artifacts, out)
    except (DocumentError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(f"draft.state: {artifacts.state.value}")
    click.echo(f"spec_written: {str(artifacts.spec is not None).lower()}")
    if proposal is not None:
        click.echo(f"model.status: {proposal.disclosure.status}")
    for path in written:
        click.echo(f"written: {path}")
    if local_result is not None:
        click.echo(f"local.status: {local_result.status}")
        for check in local_result.checks:
            click.echo(f"local.check: {check}")
        if local_result.status == "failed":
            raise click.exceptions.Exit(1)
    if artifacts.state != DraftState.READY or (local_result is not None and (local_result.status != "verified" or not local_result.cleanup_complete)):
        raise click.exceptions.Exit(3)
