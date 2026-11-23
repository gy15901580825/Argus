"""argus-probe list-probes — show available probe ids."""

import click

from argus.cli import api_client
from argus.probe import VALID_TARGET_CLASSES, equivalent_target_classes
from argus.domains import DOMAINS


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
        return set(compatible_probe_ids(build_target(load_target_spec(target), trusted_code=True), include_opt_in=False))
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
              help="Show only probes that declare this target class or an equivalent name.")
@click.option("--domain", type=click.Choice(list(DOMAINS)), default=None,
              help="Show only local probes tagged with this registered domain.")
@click.option("--long", "long_output", is_flag=True,
              help="Show local probe ids, severity, judge requirement and name in aligned columns.")
@click.option("--no-judge", is_flag=True, help="Show only local probes that run without a judge key.")
def cmd_list_probes(token: str | None, api_url: str | None, filter_substr: str, target: str | None,
                    target_class: str | None, domain: str | None, long_output: bool, no_judge: bool):
    """List available probe ids, locally or from a server."""
    opt_in_ids = set()
    if api_url is None:
        probes = _local_probes()
        if domain is not None:
            probes = [p for p in probes if domain in p.domains]
        if target_class is not None:
            classes = equivalent_target_classes(target_class)
            probes = [p for p in probes if classes.intersection(p.target_class)]
        if no_judge:
            probes = [p for p in probes if not p.needs_judge]
        opt_in_ids = {p.id for p in probes if getattr(p, "opt_in", False)}
        by_id = {p.id: p for p in probes}
        ids = [p.id for p in probes]
        if target is not None:
            fits = _target_probe_ids(target)
            ids = [i for i in ids if i in fits]
    else:
        for flag, enabled in (("--long", long_output), ("--no-judge", no_judge)):
            if enabled:
                raise click.UsageError(f"{flag} needs probe metadata from the local library; do not combine it with --api-url")
        for flag, value in (("--target", target), ("--target-class", target_class), ("--domain", domain)):
            if value is not None:
                # The server returns ids only; target classes live in the local library.
                raise click.UsageError(f"{flag} filters the local library; do not combine it with --api-url")
        if token is None:
            raise click.UsageError("Missing option '--token' (needed with --api-url)")
        ids = api_client.list_probes(api_url, token)
    if filter_substr:
        ids = [i for i in ids if filter_substr.lower() in i.lower()]
    if long_output:
        rows = [("id", "severity", "judge", "name")]
        for i in sorted(ids):
            probe = by_id[i]
            rows.append((i, probe.severity, "yes" if probe.needs_judge else "no",
                         probe.name + (" [opt-in]" if i in opt_in_ids else "")))
        widths = [max(len(row[col]) for row in rows) for col in range(3)]
        for row in rows:
            click.echo("  ".join(row[col].ljust(widths[col]) for col in range(3)) + "  " + row[3])
    else:
        for i in sorted(ids):
            click.echo(i + (" [opt-in]" if i in opt_in_ids else ""))
    click.echo(f"\n{len(ids)} probes")
