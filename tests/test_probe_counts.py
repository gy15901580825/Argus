"""Every probe count stated in the docs matches the library (scripts/probe_counts.py)."""
import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("probe_counts", ROOT / "scripts" / "probe_counts.py")
probe_counts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(probe_counts)


def test_stated_counts_match_the_library():
    errors = probe_counts.check()
    assert errors == [], "\n".join([*errors, probe_counts.FIX])


def test_families_cover_every_probe_once():
    counts = probe_counts.counts()
    parts = [n for key, n in counts.items() if key != "total" and key != "mcp_abuse"]
    assert sum(parts) == counts["total"]


@pytest.fixture
def copy_root(tmp_path):
    for rel in {rel for rel, _, _ in probe_counts.REGISTRY}:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, tmp_path / rel)
    return tmp_path


def _check(root):
    return probe_counts.check(root, ROOT / "argus" / "probes")


def test_check_catches_a_drifted_count_and_write_fixes_it(copy_root):
    total = probe_counts.counts()["total"]
    citation = copy_root / "CITATION.cff"
    citation.write_text(citation.read_text().replace(f"runs {total} red-team", f"runs {total - 1} red-team"))
    errors = _check(copy_root)
    assert any(e.startswith(f"CITATION.cff: states {total - 1} for total") for e in errors), errors
    assert probe_counts.write(copy_root, ROOT / "argus" / "probes") == ["CITATION.cff"]
    assert _check(copy_root) == []
    assert probe_counts.write(copy_root, ROOT / "argus" / "probes") == []


def test_check_catches_an_unregistered_stale_total(copy_root):
    total = probe_counts.counts()["total"]
    readme = copy_root / "README.md"
    readme.write_text(readme.read_text() + f"\nArgus now has {total - 1} bundled probes.\n")
    assert _check(copy_root) == [f"README.md: stale total '{total - 1} bundled probes', library has {total}"]


def test_check_reports_a_reworded_site(copy_root):
    cheatsheet = copy_root / "docs/onboarding/probe-id-cheatsheet.md"
    cheatsheet.write_text(cheatsheet.read_text().replace("Argus ships", "Argus includes"))
    errors = _check(copy_root)
    assert any(e.startswith("docs/onboarding/probe-id-cheatsheet.md: expected one match") for e in errors), errors
    with pytest.raises(ValueError, match="expected one match"):
        probe_counts.write(copy_root, ROOT / "argus" / "probes")


def test_unclassified_top_level_probe_is_an_error(tmp_path):
    shutil.copy(ROOT / "argus/probes/syscard_bon.yaml", tmp_path / "zz_new_family.yaml")
    with pytest.raises(ValueError, match="zz_new_family.yaml"):
        probe_counts.counts(tmp_path)
