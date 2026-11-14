# Governance

This file describes who maintains Argus and how decisions, merges and releases happen.

## Roles

- **Maintainer.** `@gy15901580825`. The project currently has one maintainer, who is also the only entry in [`.github/CODEOWNERS`](.github/CODEOWNERS).
- **Contributors.** Anyone who opens an issue or a pull request.

Veyon Solutions sponsors Argus and holds the copyright (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)). The code is licensed under Apache 2.0.

## Decisions

The maintainer decides the roadmap, which probes are in scope, and what judge verdicts mean. Larger changes start as an issue, so the approach is agreed before anyone writes code. Disagreements are discussed on the issue or pull request. The maintainer makes the final call and explains it there.

## Merges

`.github/CODEOWNERS` requests a review from the maintainer on every pull request. A pull request is merged when all required CI checks pass and the maintainer approves it. Branch protection on `main` enforces the required checks for everyone, including admins. GitHub Actions runs on pull requests from first-time contributors wait for the maintainer to approve them. Expect a first reply within a week. The full rules are in [`CONTRIBUTING.md`](CONTRIBUTING.md#reviews-and-merges).

## Releases

The maintainer cuts releases. A pull request bumps the version in `pyproject.toml`. After it merges, the maintainer pushes an annotated `v*` tag on that commit. The [release workflow](.github/workflows/release.yml) checks that the tag matches the version, builds the package and publishes it to PyPI with trusted publishing, so the repository stores no PyPI upload token. The same workflow publishes the CLI container image to `ghcr.io/gy15901580825/argus-probe`. The maintainer publishes a GitHub Release with notes for each tag. Steps are in [`docs/runbooks/release.md`](docs/runbooks/release.md).

## AI-assisted development

The maintainer uses AI coding assistants to draft changes, and most of the maintainer's commits carry a `Co-Authored-By` trailer that names the assistant. The maintainer reviews every change and is accountable for every merge and release.

## Security and conduct

Report vulnerabilities in Argus privately, as described in [`SECURITY.md`](SECURITY.md). That file also gives the acknowledgement and fix targets. Conduct reports follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Becoming a maintainer

A contributor with a record of accepted, reviewed contributions over time can be invited by the existing maintainers. A new maintainer is added to this file and to `.github/CODEOWNERS` in a pull request.

## Changes to this document

Changes to this file are made by pull request and need a maintainer's approval.
