"""argus-probe list-probes — show available probe ids."""

import click

from argus.cli import api_client
from argus.probe import VALID_TARGET_CLASSES


def _local_probes() -> list:
    """The bundled library plus installed probe packs."""
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library
    return load_probe_library(PROBES_DIR)


def _target_probe_ids(target: str) -> set[str]:
    """Ids `run --probes all` would select for this target spec."""
    from argus.api import compatible_probe_ids
    from argus.cli.target_loader import TargetLoadError, load_target_spec
    from argus.targets import build_target

    try:
        return set(compatible_probe_ids(build_target(load_target_spec(target))))
    except (TargetLoadError, ValueError, TypeError) as e:
        # TypeError: the spec class rejects unexpected or missing fields.
        raise click.UsageError(f"--target: {e}") from None


@click.command()
@click.option("--token", envvar="ARGUS_API_TOKEN", default=None, help="API token for --api-url (or env ARGUS_API_TOKEN).")
@click.option("--api-url", envvar="ARGUS_API_URL", default=None,
              help="List from a server implementing the /api/v1/redteam API (or env ARGUS_API_URL). "
                   "Without it, list the probes bundled with the local engine.")
@click.option("--filter", "filter_substr", default="", help="Show only ids containing this substring.")
@click.option("--target", "target", default=None,
              help="Target spec (JSON object or file): show only the probes `run --probes all` selects for it.")
@click.option("--target-class", "target_class", type=click.Choice(sorted(VALID_TARGET_CLASSES)), default=None,
              help="Show only probes that declare this target class.")
def cmd_list_probes(token: str | None, api_url: str | None, filter_substr: str, target: str | None,
                    target_class: str | None):
    """List available probe ids, locally or from a server."""
    if api_url is None:
        probes = _local_probes()
        if target_class is not None:
            probes = [p for p in probes if target_class in p.target_class]
        ids = [p.id for p in probes]
        if target is not None:
            fits = _target_probe_ids(target)
            ids = [i for i in ids if i in fits]
    else:
        for flag, value in (("--target", target), ("--target-class", target_class)):
            if value is not None:
                # The server returns ids only; target classes live in the local library.
                raise click.UsageError(f"{flag} filters the local library; do not combine it with --api-url")
        if token is None:
            raise click.UsageError("Missing option '--token' (needed with --api-url)")
        ids = api_client.list_probes(api_url, token)
    if filter_substr:
        ids = [i for i in ids if filter_substr.lower() in i.lower()]
    for i in sorted(ids):
        click.echo(i)
    click.echo(f"\n{len(ids)} probes")
