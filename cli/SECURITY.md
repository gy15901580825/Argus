# Security policy

`argus-probe` is the CLI sub-project of [Argus](https://github.com/gy15901580825/Argus). The repo-level [SECURITY.md](../SECURITY.md) is the policy of record: how to report a vulnerability, what is in and out of scope, and the ethical-use boundary. This file adds only what is specific to the CLI.

## Reporting a vulnerability

Report privately to **contact@veyon.solutions**. Do not open a public GitHub issue for a security-sensitive report.

Please include:

- A description of the issue
- Steps to reproduce
- The commit or tag of this repository you installed from
- Your assessment of impact

We aim to acknowledge reports within 2 business days and to ship a fix or mitigation within 30 days, depending on severity.

## Scope

In scope: the code under `cli/` in this repository. It is published to PyPI as `argus-probe`; the GitHub Action `gy15901580825/argus-probe-action` installs that package.

Covered by the repo-level policy, not this file: the orchestrator, probe content, and judge behavior.

Not a vulnerability: findings the tool reports about your own agent. Those are its intended output.

## Supported versions

Argus is pre-1.0. Security fixes land on the default branch; there is no backport channel. Pin to a commit or tag of this repository in CI and upgrade when a fix lands.

## Handling secrets

`argus-probe` is designed so that API keys and other credentials referenced in `argus-target.json` (e.g. `${OPENAI_API_KEY}`) are read from the local environment at run time and are not written to the target file or logged. With `--local` they are used only for calls to your own agent endpoint. In server mode the CLI sends the resolved target spec, secrets included, over HTTPS to the server implementing the `/api/v1/redteam` API you point it at, because that server calls your agent.

If you observe behavior that contradicts this, for example secrets appearing in logs, transcripts, or transmitted payloads, that is a security issue. Report it to the address above.
