# Releasing to PyPI

`.github/workflows/release.yml` builds `argus-probe` from the repo root `pyproject.toml` and publishes it with PyPI trusted publishing. GitHub Actions gets a short-lived OIDC token, so the repo stores no PyPI API token.

## One-time setup

1. Add a pending publisher for the project on each index. On pypi.org and test.pypi.org, open Account settings, then Publishing, then "Add a new pending publisher" (GitHub tab). Create two entries:

   | Index | PyPI project name | Owner | Repository | Workflow | Environment |
   |---|---|---|---|---|---|
   | pypi.org | `argus-probe` | `gy15901580825` | `Argus` | `release.yml` | `pypi` |
   | test.pypi.org | `argus-probe` | `gy15901580825` | `Argus` | `release.yml` | `testpypi` |

2. In the GitHub repo, open Settings, then Environments, and create `pypi` and `testpypi`. You can add required reviewers to `pypi` so a tag push waits for approval before it uploads.

A pending publisher does not reserve the project name. Someone else can still register the name until the first upload succeeds, so do the first release soon after setup.

## Rehearsal on TestPyPI

1. In the Actions tab, open the Release workflow, click "Run workflow", pick the branch and leave `target` as `testpypi`.
2. When it finishes, install from TestPyPI in a clean venv. Install the package from TestPyPI without dependencies first, then install the dependencies from PyPI. Pointing pip at both indexes at once fails, because TestPyPI hosts an unrelated `FASTAPI 1.0` sdist that pip picks over the real `fastapi` and that does not build.

```bash
python3.11 -m venv /tmp/argus-rc && . /tmp/argus-rc/bin/activate
pip install --no-deps --index-url https://test.pypi.org/simple/ argus-probe==0.2.0
pip install "argus-probe[local]==0.2.0"   # the empty extra must install without a warning
pip check
argus-probe --version
```

The TestPyPI job skips files that already exist, so you can re-run it without bumping versions.

Never upload to either index by hand with `twine`. A manual upload creates the project outside trusted publishing, so the pending publisher for that name can no longer be used, and you have to add the publisher on the existing project's Publishing page instead. It also uses up the version number, because an index never accepts the same version twice.

## Release

1. Bump `version` in `pyproject.toml` at the repo root. It is the only place the version is set: `argus-probe --version` and run.json read it from the installed package metadata.
2. Merge to `main`, then tag that commit with `v` plus the argus-probe version and push the tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The build job fails if the tag does not match the version in `pyproject.toml`.

`argus-orchestrator` (the engine as a separate package, import name `orchestrator.redteam`) stopped at 0.3.4 and gets no more releases. It stays installable from PyPI for code that still imports `orchestrator.redteam`.
