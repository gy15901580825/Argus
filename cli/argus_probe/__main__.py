"""argus-probe entry point."""

import click

from argus_probe.cmd_init import init_command
from argus_probe.cmd_run import cmd_run
from argus_probe.cmd_report import cmd_report
from argus_probe.cmd_list_probes import cmd_list_probes
from argus_probe.cmd_coverage import cmd_coverage
from argus_probe.cmd_validate_target import cmd_validate_target


@click.group()
@click.version_option()
def main():
    """Argus red-team CLI."""


main.add_command(init_command, "init")
main.add_command(cmd_run, "run")
main.add_command(cmd_report, "report")
main.add_command(cmd_list_probes, "list-probes")
main.add_command(cmd_coverage, "coverage")
main.add_command(cmd_validate_target, "validate-target")


if __name__ == "__main__":
    main()
