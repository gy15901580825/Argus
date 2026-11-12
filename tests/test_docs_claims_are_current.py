"""Public docs repeat facts the code owns: target kinds, CLI subcommands, link targets."""
import json
import re
from pathlib import Path

from argus.cli.__main__ import main as cli_main
from argus.targets import _BUILDERS, build_target

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
    listed = re.findall(r"^\| `([a-z0-9_]+)` \|", table, re.MULTILINE)
    assert sorted(listed) == sorted(_BUILDERS)


def test_quickstart_lists_every_kind():
    line = next(l for l in QUICKSTART.read_text().splitlines() if "supported `kind` values" in l)
    assert sorted(k for k in re.findall(r"`([a-z0-9_]+)`", line) if k != "kind") == sorted(_BUILDERS)


def test_cookbook_http_upload_examples_cover_both_render_url_locators():
    section = _section(COOKBOOK.read_text(), "## http_upload")
    blocks = re.findall(r"^```json\n(.*?)^```", section, re.MULTILINE | re.DOTALL)
    specs = [json.loads(block) for block in blocks]
    for spec in specs:
        build_target(spec)
    used = {key for spec in specs for key in ("render_url_jsonpath", "render_url_header") if key in spec}
    assert used == {"render_url_jsonpath", "render_url_header"}


def test_cli_md_lists_every_subcommand():
    block = _section(CLI_MD.read_text(), "## Subcommands")
    listed = re.findall(r"^argus-probe ([a-z-]+)", block, re.MULTILINE)
    assert sorted(listed) == sorted(cli_main.commands)


def test_cli_md_links_work_on_pypi():
    # docs/cli.md is the PyPI long description, where a relative link has nothing to resolve against.
    links = re.findall(r"\]\(([^)]+)\)", CLI_MD.read_text())
    relative = [l for l in links if not l.startswith(("https://", "http://", "#"))]
    assert relative == []


def _heading_slugs(path: Path) -> set[str]:
    slugs, seen, in_code = set(), {}, False
    for line in path.read_text().splitlines():
        if line.startswith("```"):
            in_code = not in_code
        m = None if in_code else re.match(r"#{1,6}\s+(.*)", line)
        if m:
            slug = re.sub(r"[^\w\- ]", "", m.group(1).strip().lower()).replace(" ", "-")
            n = seen.get(slug, 0)
            seen[slug] = n + 1
            slugs.add(slug if n == 0 else f"{slug}-{n}")
    return slugs


def test_cli_md_links_into_the_repo_resolve():
    prefix = "https://github.com/gy15901580825/Argus/blob/main/"
    broken = []
    for link in re.findall(r"\]\((" + re.escape(prefix) + r"[^)]+)\)", CLI_MD.read_text()):
        path, _, anchor = link[len(prefix):].partition("#")
        target = REPO / path
        if not target.exists() or (anchor and anchor not in _heading_slugs(target)):
            broken.append(link)
    own = [a for a in re.findall(r"\]\(#([^)]+)\)", CLI_MD.read_text()) if a not in _heading_slugs(CLI_MD)]
    assert broken + own == []
