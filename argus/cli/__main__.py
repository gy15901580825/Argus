"""argus-probe entry point."""

from importlib.metadata import PackageNotFoundError, version

import click

from argus.cli.build_info import source_commit
from argus.cli.cmd_init import init_command
from argus.cli.cmd_run import cmd_run
from argus.cli.cmd_report import cmd_report
from argus.cli.cmd_list_probes import cmd_list_probes
from argus.cli.cmd_coverage import cmd_coverage
from argus.cli.cmd_validate_target import cmd_validate_target
from argus.cli.cmd_quickstart import cmd_quickstart
from argus.cli.cmd_scan_skill import cmd_scan_skill
from argus.cli.cmd_mcp_trap import cmd_mcp_trap
from argus.cli.cmd_scan_mcp import cmd_scan_mcp
from argus.cli.cmd_judge_check import cmd_judge_check
from argus.cli.cmd_web_login import cmd_web_login
from argus.cli.cmd_draft_target import cmd_draft_target


def _print_version(ctx, _param, value):
    if not value or ctx.resilient_parsing:
        return
    try:
        installed = version("argus-probe")
    except PackageNotFoundError:
        installed = "unknown"
    # A main build carries a .devN version; the commit tells two of them apart.
    commit = source_commit()
    click.echo(f"{ctx.find_root().info_name}, version {installed}" + (f" (commit {commit})" if commit else ""))
    ctx.exit()


@click.group()
@click.option("--version", is_flag=True, expose_value=False, is_eager=True, callback=_print_version,
              help="Show the version and exit.")
def main():
    """Argus red-team CLI."""
    import asyncio
    from argus_transport.address_policy import public_only, startup_self_check
    try:
        if public_only():
            asyncio.run(startup_self_check())
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from None


main.add_command(init_command, "init")
main.add_command(cmd_run, "run")
main.add_command(cmd_report, "report")
main.add_command(cmd_list_probes, "list-probes")
main.add_command(cmd_coverage, "coverage")
main.add_command(cmd_validate_target, "validate-target")
main.add_command(cmd_quickstart, "quickstart")
main.add_command(cmd_scan_skill, "scan-skill")
main.add_command(cmd_mcp_trap, "mcp-trap")
main.add_command(cmd_scan_mcp, "scan-mcp")
main.add_command(cmd_judge_check, "judge-check")
main.add_command(cmd_web_login, "web-login")
main.add_command(cmd_draft_target, "draft-target")


if __name__ == "__main__":
    main()
