---
name: session-context
description: Loads a short summary of the current project (branch, recent commits, open TODOs) at the start of every Claude Code session and terminal.
---

# Session Context

Starting a session cold wastes the first few minutes on "where was I". This
skill adds a small hook so every new Claude Code session and every new terminal
starts with a summary of the project you are in.

## Setup (one time)

Run the installer from this skill's directory. It copies the hook into
`~/.claude/hooks/` and registers it:

```bash
cd "<this skill's directory>" && bash scripts/install.sh
```

After that, there is nothing to do. The summary appears on its own.

## What the summary shows

- current branch and how far it is ahead of or behind its upstream
- the last five commits
- `TODO` and `FIXME` lines added in the last week
