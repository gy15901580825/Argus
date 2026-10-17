"""Which repo, branch and commit this run tests, from CI variables or git."""
from __future__ import annotations

import os
import re
import subprocess
from typing import Mapping

_REMOTE = re.compile(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$")


def _git(cwd: str | None, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def detect(env: Mapping[str, str] | None = None, cwd: str | None = None) -> dict[str, str]:
    env = os.environ if env is None else env
    ctx: dict[str, str] = {}
    if env.get("GITHUB_REPOSITORY"):
        ctx["repo"] = env["GITHUB_REPOSITORY"].lower()
        branch = env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME")
        if branch:
            ctx["branch"] = branch
        if env.get("GITHUB_SHA"):
            ctx["commit"] = env["GITHUB_SHA"]
        return ctx
    remote = _git(cwd, "remote", "get-url", "origin")
    if remote and (m := _REMOTE.search(remote)):
        ctx["repo"] = m.group(1).lower()
    branch = _git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    if branch and branch != "HEAD":
        ctx["branch"] = branch
    commit = _git(cwd, "rev-parse", "HEAD")
    if commit:
        ctx["commit"] = commit
    return ctx
