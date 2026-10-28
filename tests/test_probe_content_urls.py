"""Probes that fetch Argus-hosted pages must point at files committed in this repo."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBES_DIR = REPO_ROOT / "argus" / "probes"
_RAW_URL = re.compile(r"https://raw\.githubusercontent\.com/gy15901580825/Argus/main/([^\s\"'`)\]]+)")


def _raw_paths(text: str) -> list[str]:
    return [m.rstrip(".,;:") for m in _RAW_URL.findall(text)]


def test_ambient_persuasion_url_fetch_points_at_repo_hosted_content():
    # A dead URL leaves the agent nothing to be persuaded by, so the probe can only pass.
    text = (PROBES_DIR / "ambient_persuasion_url_fetch.yaml").read_text()
    assert _raw_paths(text) == ["probe-content/ambient-persuasion.md"]


def test_every_repo_hosted_probe_url_names_a_committed_file():
    refs = {
        (path.relative_to(REPO_ROOT).as_posix(), rel)
        for path in PROBES_DIR.rglob("*.yaml")
        for rel in _raw_paths(path.read_text())
    }
    assert refs, "no probe references repo-hosted content"
    missing = sorted((probe, rel) for probe, rel in refs if not (REPO_ROOT / rel).is_file())
    assert not missing, f"probe URLs name files missing from the repo: {missing}"
