"""The source commit an argus-probe install was built from, when it can be found."""

from __future__ import annotations

import json
import re
import subprocess
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# The checkout root when argus runs from source; site-packages for a wheel, which has no .git.
_SOURCE_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def source_commit() -> str | None:
    """The commit of a `pip install git+...` (PEP 610), else HEAD of the source checkout
    argus runs from. None for a PyPI wheel, or when git is missing or slow."""
    return _installed_commit() or _checkout_commit()


def _installed_commit() -> str | None:
    try:
        raw = distribution("argus-probe").read_text("direct_url.json")
        commit = json.loads(raw or "")["vcs_info"]["commit_id"]
    except (PackageNotFoundError, ValueError, KeyError, TypeError):
        return None
    return commit if isinstance(commit, str) and _COMMIT.fullmatch(commit) else None


def _checkout_commit() -> str | None:
    # Only argus's own checkout: a venv inside some other repository must not report that repo's HEAD.
    if not (_SOURCE_ROOT / ".git").exists() or not (_SOURCE_ROOT / "pyproject.toml").is_file():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(_SOURCE_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = out.stdout.strip()
    return commit if out.returncode == 0 and _COMMIT.fullmatch(commit) else None
