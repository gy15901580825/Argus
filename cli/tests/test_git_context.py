import subprocess

from argus_probe.git_context import detect


def test_github_pull_request_env():
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_HEAD_REF": "feat/x", "GITHUB_REF_NAME": "12/merge", "GITHUB_SHA": "abc"}
    assert detect(env, cwd="/") == {"repo": "o/r", "branch": "feat/x", "commit": "abc"}


def test_repo_name_is_lowercased_from_github_env():
    env = {"GITHUB_REPOSITORY": "Acme/Agent", "GITHUB_SHA": "abc"}
    assert detect(env, cwd="/")["repo"] == "acme/agent"


def test_github_push_env_uses_ref_name():
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_HEAD_REF": "", "GITHUB_REF_NAME": "main", "GITHUB_SHA": "abc"}
    assert detect(env, cwd="/") == {"repo": "o/r", "branch": "main", "commit": "abc"}


def test_falls_back_to_git(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "dev", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", "https://github.com/Acme/Agent.git"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-q", "--allow-empty", "-m", "x"], check=True)
    out = detect({}, cwd=str(tmp_path))
    assert out["repo"] == "acme/agent"
    assert out["branch"] == "dev"
    assert len(out["commit"]) == 40


def test_outside_git_and_ci_returns_empty(tmp_path):
    assert detect({}, cwd=str(tmp_path)) == {}
