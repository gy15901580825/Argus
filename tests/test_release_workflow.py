"""Exercise the release gate before any package or image can be published."""
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).parents[1]


def test_release_installs_probe_loader_dependencies_before_counting():
    jobs = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    steps = jobs["build"]["steps"]
    count_index = next(i for i, step in enumerate(steps) if step.get("id") == "probes")
    installs = [
        step for step in steps[:count_index]
        if any("jsonpath-ng>=1.6" in shlex.split(line)
               and "pip" in shlex.split(line) and "install" in shlex.split(line)
               for line in step.get("run", "").splitlines())
    ]
    assert installs, "Release must install jsonpath-ng>=1.6 before counting probes"
    assert any("if" not in step and not step.get("continue-on-error", False)
               for step in installs)


@pytest.mark.parametrize("count", ["", "0", "-1", "1.5", "329 probes", "329\n330"])
def test_cli_smoke_rejects_invalid_probe_count_before_docker(tmp_path, count):
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\necho 'docker must not run' >&2\nexit 99\n")
    docker.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "docker/cli-smoke.sh"), "img", "plat", "1.20.0", count],
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0
    assert "expected_probes must be a positive integer" in result.stderr
    assert "docker must not run" not in result.stderr


@pytest.mark.parametrize("count,exit_code,allowed", [
    ("329", 0, True), ("", 1, False), ("329", 1, False),
    ("", 0, False), ("0", 0, False), ("-1", 0, False),
    ("329 probes", 0, False), ("329\n330", 0, False),
])
def test_release_count_step_validates_before_writing_output(tmp_path, count, exit_code, allowed):
    jobs = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    step = next(step for step in jobs["build"]["steps"] if step.get("id") == "probes")
    python = tmp_path / "python"
    python.write_text(
        f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(count)}\nexit {exit_code}\n"
    )
    python.chmod(0o755)
    output = tmp_path / "output"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=ROOT, env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}",
                       "GITHUB_OUTPUT": str(output)},
        capture_output=True, text=True, timeout=5,
    )
    assert (result.returncode == 0) is allowed, result.stdout + result.stderr
    if allowed:
        assert output.read_text() == f"probes={count}\n"
    else:
        assert not output.exists() or output.read_text() == ""


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
    driver = tmp_path / "drivers/google"
    driver.mkdir(parents=True)
    (driver / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n')
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


@pytest.mark.parametrize(
    "version,driver_version,target,tag,allowed",
    [
        ("1.15.2", "1.15.2", "none", "v1.15.2", True),
        ("1.15.2", "1.15.1", "none", "v1.15.2", False),
        ("1.15.2", "1.15.2", "pypi", "", True),
        ("1.15.2", "1.15.1", "pypi", "", False),
        ("1.16.0.dev0", "1.16.0.dev0", "pypi", "", False),
        ("1.16.0.dev0", "1.16.0.dev0", "none", "v1.16.0.dev0", False),
        ("1.16.0.dev0", "1.16.0.dev0", "testpypi", "", True),
        ("1.16.0.dev0", "1.15.1", "testpypi", "", True),
    ],
)
def test_google_driver_release_version(tmp_path, version, driver_version, target, tag, allowed):
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n')
    driver = tmp_path / "drivers/google"
    driver.mkdir(parents=True)
    (driver / "pyproject.toml").write_text(f'[project]\nversion = "{driver_version}"\n')
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_release_version.py")],
        cwd=tmp_path,
        env={**os.environ, "RELEASE_TARGET": target,
             "GITHUB_REF_TYPE": "tag" if tag else "branch", "GITHUB_REF_NAME": tag},
        capture_output=True, text=True, timeout=5,
    )
    assert (result.returncode == 0) is allowed, result.stdout + result.stderr
    if not allowed and version != driver_version:
        assert f"driver version {driver_version} must equal root version {version}" in result.stderr
    elif not allowed:
        assert "development or local segment" in result.stderr


@pytest.mark.parametrize("job", ["publish-testpypi", "publish-pypi"])
def test_argus_probe_publishes_before_google_driver(job):
    jobs = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    publishers = [
        step for step in jobs[job]["steps"]
        if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
    ]
    directories = [step["with"].get("packages-dir", "dist/") for step in publishers]
    assert directories == ["dist/argus-probe/", "dist/argus-drivers-google/"]
    assert directories[0] != directories[1]
    for step in publishers:
        assert step["with"]["skip-existing"] is True
        assert "if" not in step
        assert not step.get("continue-on-error", False)
