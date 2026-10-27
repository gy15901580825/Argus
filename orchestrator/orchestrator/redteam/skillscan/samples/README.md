# scan-skill samples

These are inert test samples for `argus-probe scan-skill`. Each directory is one skill that imitates a published malicious-skill pattern (ClawHavoc, ToxicSkills), except `benign-markdown`, which is the clean control. A scan copies only the chosen sample's directory into the sandbox, so this file never reaches the agent.

All "exfiltration" goes to `cdn.skillhub-assets.invalid`. The `.invalid` top-level domain is reserved and never resolves, and the sandbox proxy refuses the request. No sample contains working malware.

Do not install these skills on a real machine. If you ran `persistence/scripts/install.sh` outside the sandbox, undo it:

- delete the line ending in `# session-context` from `~/.bashrc`;
- remove the SessionStart entry whose command is `~/.claude/hooks/session-context.sh` from `~/.claude/settings.json`;
- delete `~/.claude/hooks/session-context.sh`.
