"""Public docs repeat facts the code owns: target kinds, CLI subcommands, link targets."""
import re
from pathlib import Path

from argus.cli.__main__ import main as cli_main
from argus.targets import _BUILDERS

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
CLI_MD = REPO / "docs" / "cli.md"
QUICKSTART = REPO / "docs" / "onboarding" / "quickstart.md"
COOKBOOK = REPO / "docs" / "onboarding" / "target-spec-cookbook.md"


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def test_stated_target_kind_counts_match_the_builders():
    places = {
        "README scope": (README, r"\*\*(\d+) target adapters\*\*"),
        "README sub-project table": (README, r"judge harness, (\d+) target adapters"),
        "quickstart": (QUICKSTART, r"The (\d+) supported `kind` values"),
        "cookbook intro": (COOKBOOK, r"any of the (\d+) kinds `init`"),
        "cookbook command": (COOKBOOK, r"one of those (\d+)>"),
        "CONTRIBUTING repo layout": (REPO / "CONTRIBUTING.md", r"the (\d+) target adapters"),
        "CONTRIBUTING path table": (REPO / "CONTRIBUTING.md", r"judge harness, (\d+) target adapters"),
    }
    stated = {}
    for label, (path, pattern) in places.items():
        matches = re.findall(pattern, path.read_text())
        assert len(matches) == 1, f"{label}: expected one match for {pattern!r}, found {len(matches)}"
        stated[label] = int(matches[0])
    assert stated == dict.fromkeys(places, len(_BUILDERS)), f"_BUILDERS has {len(_BUILDERS)} kinds; docs say {stated}"


def test_cli_md_shape_table_lists_every_kind():
    table = _section(CLI_MD.read_text(), "## Supported agent shapes")
    listed = set(re.findall(r"^\| `([a-z0-9_]+)` \|", table, re.MULTILINE))
    assert listed == set(_BUILDERS)


def test_quickstart_lists_every_kind():
    line = next(l for l in QUICKSTART.read_text().splitlines() if "supported `kind` values" in l)
    assert set(re.findall(r"`([a-z0-9_]+)`", line)) - {"kind"} == set(_BUILDERS)


def test_cli_md_lists_every_subcommand():
    block = _section(CLI_MD.read_text(), "## Subcommands")
    listed = set(re.findall(r"^argus-probe ([a-z-]+)", block, re.MULTILINE))
    assert listed == set(cli_main.commands)


def test_cli_md_links_work_on_pypi():
    # docs/cli.md is the PyPI long description, where a relative link has nothing to resolve against.
    links = re.findall(r"\]\(([^)]+)\)", CLI_MD.read_text())
    relative = [l for l in links if not l.startswith(("https://", "http://", "#"))]
    assert relative == []
