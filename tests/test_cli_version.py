"""`argus-probe --version` and run.json say which build ran: the version, plus the commit when known."""

import json
import subprocess
import tomllib
from pathlib import Path

from click.testing import CliRunner
from packaging.version import Version

from argus.cli import build_info
from argus.cli.__main__ import main
from argus.cli.run_json import render_json

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
SHA = "0123456789abcdef0123456789abcdef01234567"


class _Dist:
    def __init__(self, direct_url):
        self._direct_url = direct_url

    def read_text(self, name):
        return self._direct_url if name == "direct_url.json" else None


def _commit(monkeypatch, *, direct_url=None, root=None, git=None):
    build_info.source_commit.cache_clear()
    monkeypatch.setattr(build_info, "distribution", lambda name: _Dist(direct_url))
    if root is not None:
        monkeypatch.setattr(build_info, "_SOURCE_ROOT", root)
    if git is not None:
        monkeypatch.setattr(build_info.subprocess, "run", git)
    try:
        return build_info.source_commit()
    finally:
        build_info.source_commit.cache_clear()


def test_package_carries_the_next_development_version():
    version = tomllib.loads(PYPROJECT.read_text())["project"]["version"]
    assert version == "1.20.1.dev0"
    driver = PYPROJECT.parent / "drivers/google/pyproject.toml"
    assert tomllib.loads(driver.read_text())["project"]["version"] == version
    assert Version(version) > Version("1.20.0")
    assert Version(version).is_devrelease


def test_version_without_a_commit_is_the_plain_line(monkeypatch):
    # docker/cli-smoke.sh matches this line exactly for the wheel image.
    monkeypatch.setattr("argus.cli.__main__.source_commit", lambda: None)
    monkeypatch.setattr("argus.cli.__main__.version", lambda name: "1.20.1.dev0")
    result = CliRunner().invoke(main, ["--version"], prog_name="argus-probe")
    assert result.exit_code == 0, result.output
    assert result.output == "argus-probe, version 1.20.1.dev0\n"


def test_version_names_the_commit_when_known(monkeypatch):
    monkeypatch.setattr("argus.cli.__main__.source_commit", lambda: SHA)
    monkeypatch.setattr("argus.cli.__main__.version", lambda name: "1.20.1.dev0")
    result = CliRunner().invoke(main, ["--version"], prog_name="argus-probe")
    assert result.output == f"argus-probe, version 1.20.1.dev0 (commit {SHA})\n"


def test_run_json_records_the_commit_only_when_known(monkeypatch):
    run = {"id": "r", "status": "completed", "target_spec": {}, "findings": []}
    monkeypatch.setattr("argus.cli.run_json.source_commit", lambda: SHA)
    record = json.loads(render_json(run))
    assert record["argus_commit"] == SHA
    keys = list(record)
    assert keys.index("argus_commit") == keys.index("argus_version") + 1
    monkeypatch.setattr("argus.cli.run_json.source_commit", lambda: None)
    assert "argus_commit" not in json.loads(render_json(run))


def test_pip_install_from_git_reports_the_pep610_commit(monkeypatch, tmp_path):
    direct_url = json.dumps({"url": "https://example.invalid/argus.git",
                             "vcs_info": {"vcs": "git", "commit_id": SHA}})
    assert _commit(monkeypatch, direct_url=direct_url, root=tmp_path) == SHA


def test_wheel_install_reports_no_commit(monkeypatch, tmp_path):
    archive = json.dumps({"url": "file:///tmp/argus_probe.whl", "archive_info": {}})

    def no_git(*a, **k):
        raise AssertionError("git must not run outside argus's own checkout")

    assert _commit(monkeypatch, direct_url=archive, root=tmp_path, git=no_git) is None
    assert _commit(monkeypatch, direct_url=None, root=tmp_path, git=no_git) is None


def test_source_checkout_reports_head(monkeypatch, tmp_path):
    (tmp_path / ".git").write_text("gitdir: elsewhere\n")  # a worktree's .git is a file
    (tmp_path / "pyproject.toml").write_text("")
    calls = []

    def git(cmd, **kwargs):
        calls.append((cmd, kwargs.get("timeout")))
        return subprocess.CompletedProcess(cmd, 0, stdout=SHA + "\n", stderr="")

    assert _commit(monkeypatch, root=tmp_path, git=git) == SHA
    assert calls == [(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], 2)]


def test_slow_or_missing_git_never_fails(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text("")

    def slow(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    def missing(cmd, **kwargs):
        raise FileNotFoundError("git")

    def garbage(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 128, stdout="", stderr="fatal: not a git repository")

    for git in (slow, missing, garbage):
        assert _commit(monkeypatch, root=tmp_path, git=git) is None
