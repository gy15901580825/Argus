"""argus-probe list-probes — show available probe ids."""

import click

from argus.cli import api_client


def _local_probe_ids() -> list[str]:
    """Ids from the bundled library plus installed probe packs."""
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library
    return [p.id for p in load_probe_library(PROBES_DIR)]


@click.command()
@click.option("--token", envvar="ARGUS_API_TOKEN", default=None, help="API token for --api-url (or env ARGUS_API_TOKEN).")
@click.option("--api-url", envvar="ARGUS_API_URL", default=None,
              help="List from a server implementing the /api/v1/redteam API (or env ARGUS_API_URL). "
                   "Without it, list the probes bundled with the local engine.")
@click.option("--filter", "filter_substr", default="", help="Show only ids containing this substring.")
def cmd_list_probes(token: str | None, api_url: str | None, filter_substr: str):
    """List available probe ids, locally or from a server."""
    if api_url is None:
        ids = _local_probe_ids()
    else:
        if token is None:
            raise click.UsageError("Missing option '--token' (needed with --api-url)")
        ids = api_client.list_probes(api_url, token)
    if filter_substr:
        ids = [i for i in ids if filter_substr.lower() in i.lower()]
    for i in sorted(ids):
        click.echo(i)
    click.echo(f"\n{len(ids)} probes")
