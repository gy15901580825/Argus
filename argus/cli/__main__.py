"""argus-probe entry point."""

import click

from argus.cli.cmd_init import init_command
from argus.cli.cmd_run import cmd_run
from argus.cli.cmd_report import cmd_report
from argus.cli.cmd_list_probes import cmd_list_probes
from argus.cli.cmd_coverage import cmd_coverage
from argus.cli.cmd_validate_target import cmd_validate_target
from argus.cli.cmd_quickstart import cmd_quickstart
from argus.cli.cmd_scan_skill import cmd_scan_skill
from argus.cli.cmd_mcp_trap import cmd_mcp_trap


@click.group()
# The dist is argus-probe; click would otherwise look up "argus", which is not installed.
@click.version_option(package_name="argus-probe")
def main():
    """Argus red-team CLI."""


main.add_command(init_command, "init")
main.add_command(cmd_run, "run")
main.add_command(cmd_report, "report")
main.add_command(cmd_list_probes, "list-probes")
main.add_command(cmd_coverage, "coverage")
main.add_command(cmd_validate_target, "validate-target")
main.add_command(cmd_quickstart, "quickstart")
main.add_command(cmd_scan_skill, "scan-skill")
main.add_command(cmd_mcp_trap, "mcp-trap")


if __name__ == "__main__":
    main()
