# Releasing to PyPI

`.github/workflows/release.yml` builds `argus-probe` (`cli/`) and `argus-orchestrator` (`orchestrator/`) and publishes both with PyPI trusted publishing. GitHub Actions gets a short-lived OIDC token, so the repo stores no PyPI API token.

## One-time setup

1. Add a pending publisher for each project on each index. On pypi.org and test.pypi.org, open Account settings, then Publishing, then "Add a new pending publisher" (GitHub tab). Create four entries:

   | Index | PyPI project name | Owner | Repository | Workflow | Environment |
   |---|---|---|---|---|---|
   | pypi.org | `argus-probe` | `gy15901580825` | `Argus` | `release.yml` | `pypi` |
   | pypi.org | `argus-orchestrator` | `gy15901580825` | `Argus` | `release.yml` | `pypi` |
   | test.pypi.org | `argus-probe` | `gy15901580825` | `Argus` | `release.yml` | `testpypi` |
   | test.pypi.org | `argus-orchestrator` | `gy15901580825` | `Argus` | `release.yml` | `testpypi` |

2. In the GitHub repo, open Settings, then Environments, and create `pypi` and `testpypi`. You can add required reviewers to `pypi` so a tag push waits for approval before it uploads.

A pending publisher does not reserve the project name. Someone else can still register the name until the first upload succeeds, so do the first release soon after setup.

## Rehearsal on TestPyPI

1. In the Actions tab, open the Release workflow, click "Run workflow", pick the branch and leave `target` as `testpypi`.
2. When it finishes, install from TestPyPI in a clean venv. The extra index pulls dependencies from real PyPI, because most of them are not on TestPyPI.

```bash
python3.11 -m venv /tmp/argus-rc && . /tmp/argus-rc/bin/activate
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ "argus-probe[local]"
argus-probe --version
```

The TestPyPI job skips files that already exist, so you can re-run it without bumping versions.

## Release

1. Bump `version` in `cli/pyproject.toml`. Bump `orchestrator/pyproject.toml` too if the orchestrator changed, and keep the `argus-orchestrator` range in argus-probe's `local` extra in step with it.
2. Merge to `main`, then tag that commit with `v` plus the argus-probe version and push the tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The build job fails if the tag does not match the version in `cli/pyproject.toml`. The PyPI job skips files that already exist, so an unchanged argus-orchestrator version is skipped, not an error.
