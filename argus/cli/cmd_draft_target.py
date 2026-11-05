from pathlib import Path

import click

from argus.drafting.draft import DraftState, choose_without_model, compile_draft, validate_server_origin, write_artifacts
from argus.drafting.openapi import DocumentError, catalog_operations, load_openapi
from argus.cli.validate_transport_v2 import validate


@click.command("draft-target")
@click.option("--openapi", "input_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--operation", help="Select a documented operation ID.")
@click.option("--server-origin", help="Select one origin declared in root servers.")
@click.option("--intent", default="Ask an agent a question, optionally with third-party material.", show_default=True)
@click.option("--no-model", is_flag=True, help="Use only deterministic local document extraction.")
def cmd_draft_target(input_path, out, operation, server_origin, intent, no_model):
    """Draft a transport v2 target and review gaps from local OpenAPI 3.x."""
    if not no_model:
        raise click.UsageError("This skeleton requires --no-model; model choices are not implemented.")
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
        document = load_openapi(input_path)
        catalog = catalog_operations(document)
        if operation is not None and operation not in {op.id for op in catalog.operations}:
            raise click.UsageError("--operation must select a documented operation ID.")
        choices = choose_without_model(catalog, operation=operation, server_origin=server_origin, intent=intent)
        artifacts = compile_draft(catalog, choices)
        if artifacts.spec is not None:
            validate(artifacts.spec, offline=True, endpoint_override=None)
            artifacts = artifacts.validated()
        written = write_artifacts(artifacts, out)
    except (DocumentError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(f"draft.state: {artifacts.state.value}")
    click.echo(f"spec_written: {str(artifacts.spec is not None).lower()}")
    for path in written:
        click.echo(f"written: {path}")
    if artifacts.state != DraftState.READY:
        raise click.exceptions.Exit(3)
