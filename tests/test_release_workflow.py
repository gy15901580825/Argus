"""Exercise the release gate before any package or image can be published."""
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "version,target,tag,allowed",
    [
        ("1.14.1", "pypi", "", True),
        ("1.14.1rc1", "pypi", "", True),
        ("1.14.1.dev0", "pypi", "", False),
        ("1.14.1dev0", "pypi", "", False),
        ("1.14.1.DEV0", "pypi", "", False),
        ("1.14.1+local", "pypi", "", False),
        ("1.14.1rc1.dev0", "pypi", "", False),
        ("1.14.1.dev0", "testpypi", "", True),
        ("1.14.1.dev0", "none", "", True),
        ("1.14.1", "none", "v1.14.1", True),
        ("1.14.1rc1", "none", "v1.14.1rc1", True),
        ("1.14.1.dev0", "none", "v1.14.1.dev0", False),
        ("1.14.1+local", "none", "v1.14.1+local", False),
        ("1.14.1", "none", "v1.14.0", False),
        ("1.14.1", "none", "1.14.1", False),
    ],
)
def test_release_gate(tmp_path, version, target, tag, allowed):
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n')
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_release_version.py")],
        cwd=tmp_path,
        env={**os.environ, "RELEASE_TARGET": target,
             "GITHUB_REF_TYPE": "tag" if tag else "branch", "GITHUB_REF_NAME": tag},
        capture_output=True, text=True, timeout=5,
    )
    assert (result.returncode == 0) is allowed, result.stdout + result.stderr
    if not allowed:
        assert "Refusing release:" in result.stderr


def test_shared_build_gates_both_publish_paths():
    jobs = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    steps = jobs["build"]["steps"]
    guards = [s for s in steps if "scripts/check_release_version.py" in s.get("run", "")]
    assert len(guards) == 1
    guard = guards[0]
    assert "if" not in guard
    assert guard["env"]["RELEASE_TARGET"] == "${{ inputs.target }}"
    assert steps.index(guard) < next(i for i, s in enumerate(steps) if s.get("name") == "Build sdist + wheel")
    assert "build" in jobs["publish-pypi"]["needs"]
    assert "build" in jobs["publish-image"]["needs"]
