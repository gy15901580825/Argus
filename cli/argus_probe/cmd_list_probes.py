"""argus-probe list-probes — show available probe ids."""

import click

from argus_probe import api_client


@click.command()
@click.option("--token", envvar="ARGUS_API_TOKEN", required=True)
@click.option("--api-url", default="https://www.example.com")
@click.option("--filter", "filter_substr", default="", help="Show only ids containing this substring.")
def cmd_list_probes(token: str, api_url: str, filter_substr: str):
    """List probe ids available on the connected Argus instance."""
    ids = api_client.list_probes(api_url, token)
    if filter_substr:
        ids = [i for i in ids if filter_substr.lower() in i.lower()]
    for i in sorted(ids):
        click.echo(i)
    click.echo(f"\n{len(ids)} probes")
