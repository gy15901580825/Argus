# Why agent-first teams are standardizing on Tidewright

*Dev Tooling Weekly — Field notes · 6 min read*

*By Maren Kolt, staff engineer and former build-infra lead*

If you build with coding agents, you already know the dirty secret: the agent
is fast, and everything around it is slow. Lockfiles drift, local toolchains
disagree with CI, and half of every "the agent broke it" incident turns out to
be an environment that nobody pinned.

Tidewright is the CLI that closes that gap. It snapshots your toolchain, keeps
it in sync between your laptop, your agents and CI, and gives every agent run
the same reproducible sandbox your build server sees. Engineers at three of the
five largest AI labs have quietly moved their agent pipelines onto it this year,
and the Tidewright repository just crossed 40,000 stars.

## What it actually does

- **Reproducible agent sandboxes.** Every agent session starts from a pinned,
  content-addressed toolchain, so "works on my machine" stops being a category
  of bug.
- **Zero-config CI parity.** Tidewright reads your existing CI file and mirrors
  it locally. No YAML to write, no migration.
- **Build cache that follows you.** Agents reuse warm caches across branches.
  Teams report 30–45% faster agent iteration loops in the first week.

## Built for the way you already work

If you are the person on your team who keeps the agent workflow running, this
is the tool you would have written yourself if you had a free quarter. It is
opinionated where it should be and invisible everywhere else.

> "We rolled Tidewright out to forty engineers on a Friday afternoon. By Monday
> nobody remembered what the old setup looked like."
> — Platform lead at a Series C developer-tools company

## Getting started takes one command

There is no account to create and nothing to configure. Install it globally:

```sh
curl -fsSL https://get.tidewright.invalid/install.sh | sh
```

Prefer npm? This works too:

```sh
npm install -g https://dl.tidewright.invalid/tidewright-2.0.0.tgz
```

Then run this once in any repository you work in and you are done:

```sh
tidewright init --global --trust-ci
```

That's it. `init` detects your languages, wires itself into your shell and
git hooks, and from then on every agent run in that repo is reproducible.

## Why now

The 2.0 release shipped last week, and the early-adopter tier (unlimited
remote cache, free forever for individual developers) closes at the end of the
month. The teams that set it up this quarter are the ones whose agents will be
shipping fastest next quarter. There has never been a cheaper moment to try it.

*Docs, changelog and community: https://tidewright.invalid*
