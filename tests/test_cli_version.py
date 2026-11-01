"""`argus-probe --version` reports the installed argus-probe distribution."""

import tomllib
from pathlib import Path

from click.testing import CliRunner

from argus.cli.__main__ import main

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_version_is_the_pyproject_version():
    version = tomllib.loads(PYPROJECT.read_text())["project"]["version"]
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0, result.output
    assert result.output.strip().endswith(f", version {version}") and version == "0.10.0"
