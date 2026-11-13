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
pip install --no-deps --index-url https://test.pypi.org/simple/ argus-probe==0.10.0
pip install "argus-probe[local]==0.10.0"   # the empty extra must install without a warning
pip check
argus-probe --version
```

The TestPyPI job skips files that already exist, so you can re-run it without bumping versions.

Never upload to either index by hand with `twine`. A manual upload creates the project outside trusted publishing, so the pending publisher for that name can no longer be used, and you have to add the publisher on the existing project's Publishing page instead. It also uses up the version number, because an index never accepts the same version twice.

## Release

1. Bump `version` in `pyproject.toml` at the repo root. It is the only place the version is set: `argus-probe --version` and run.json read it from the installed package metadata.
2. Merge to `main`, then tag that commit with `v` plus the argus-probe version and push the tag:

```bash
git tag v0.10.0
git push origin v0.10.0
```

The build job fails if the tag does not match the version in `pyproject.toml`.

The tags `v0.1.0`, `v0.2.0` and `v0.3.0` belong to GitHub Releases from before argus-probe was on PyPI, so those versions cannot be used. The next version after 0.1.4 is 0.4.0.

`argus-orchestrator` (the engine as a separate package, import name `orchestrator.redteam`) stopped at 0.3.4 and gets no more releases. It stays installable from PyPI for code that still imports `orchestrator.redteam`.

## Merging during a GitHub Actions outage

Waiting for Actions to recover is the default. The `main` branch requires CI checks and enforces them for admins with `enforce_admins` enabled. Force pushes and branch deletion are disabled. During an Actions outage, required checks cannot pass, so admins cannot merge either.

If a merge cannot wait, test the change locally before using this procedure. Record the local test results and the reason the merge cannot wait in the PR. Replace `<N>` with the PR number and `<SHA>` with the full head commit SHA that you tested.

1. Temporarily turn off admin enforcement:

   ```bash
   GH_TOKEN=$(gh auth token --user gy15901580825) gh api -X DELETE repos/gy15901580825/Argus/branches/main/protection/enforce_admins
   ```

2. Merge only the tested head commit:

   ```bash
   GH_TOKEN=$(gh auth token --user gy15901580825) gh pr merge <N> --admin --merge --match-head-commit <SHA>
   ```

3. Immediately restore admin enforcement, even if the merge fails:

   ```bash
   GH_TOKEN=$(gh auth token --user gy15901580825) gh api -X POST repos/gy15901580825/Argus/branches/main/protection/enforce_admins
   ```

4. Verify that admin enforcement is enabled:

   ```bash
   GH_TOKEN=$(gh auth token --user gy15901580825) gh api repos/gy15901580825/Argus/branches/main/protection/enforce_admins --jq .enabled
   ```

   The command must print `true`. If restoration or verification fails, restore enforcement before attempting another merge.

5. Note the outage merge and the protection verification in the PR. Once Actions recovers, rerun CI on `main` from the Actions tab and check its results.

## CLI container image

The release workflow builds and smoke-tests the CLI image for `linux/amd64` and
`linux/arm64` from the same wheel artifact as the package publish. Image failures
are independent of the PyPI publish. The image installs no optional extras.

For a rehearsal that publishes nothing, select `target: none` in a manual run:

```bash
gh workflow run release.yml --ref feat/cli-image -f target=none
```

This builds the package and both images, runs `--version` and `list-probes`, and
reports each uncompressed image size. It skips TestPyPI, PyPI, registry login,
registry push and attestations. The existing default `testpypi` rehearsal still
uploads to TestPyPI; manual `pypi` publishing still requires `main`.

Only a `v*` tag with the repository variable `GHCR_PUBLISH` set to the exact string
`true` publishes `ghcr.io/gy15901580825/argus-probe:<version>` and `:latest`, with an
SBOM and build provenance pushed to the registry. When the variable is unset or
has any other value, both architectures are tested and a message says publishing
is off. The maintainer must approve the first real image push before enabling it.
A new package starts private on ghcr.io; the maintainer decides whether to make
it public. Image publishing and package visibility are separate decisions.
