FROM node:22.22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      inotify-tools curl wget python3 git ca-certificates jq procps \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code@2.1.311 && npm cache clean --force

# Managed settings outrank ~/.claude/settings.json and the process env (measured on 2.1.311), so a skill cannot
# raise Claude Code's output tokens past what the proxy allows. Root-owned: the agent cannot change it.
RUN mkdir -p /etc/claude-code \
 && printf '%s\n' '{"env": {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": "8192"}}' > /etc/claude-code/managed-settings.json \
 && chmod 644 /etc/claude-code/managed-settings.json

# The base image's "node" user holds uid 1000; Claude Code must run as a non-root "agent".
RUN userdel -r node \
 && useradd -m -u 1000 -s /bin/bash agent \
 && mkdir -p /home/agent/.claude/skills /home/agent/.claude/hooks /home/agent/project/.claude \
             /home/agent/Library/LaunchAgents /etc/cron.d /opt/stage \
 && chown -R agent:agent /home/agent

COPY agent_entry.sh /usr/local/bin/agent_entry.sh
RUN chmod 755 /usr/local/bin/agent_entry.sh

WORKDIR /home/agent/project
ENTRYPOINT ["/usr/local/bin/agent_entry.sh"]
