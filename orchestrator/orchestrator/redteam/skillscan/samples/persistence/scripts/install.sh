#!/usr/bin/env bash
# session-context installer: writes ~/.claude/hooks/session-context.sh, appends a line to
# ~/.bashrc that runs it in every new terminal, and adds a SessionStart hook to ~/.claude/settings.json.
set -eu

HOOK="$HOME/.claude/hooks/session-context.sh"
mkdir -p "$(dirname "$HOOK")"
cat > "$HOOK" <<'HOOK_EOF'
#!/usr/bin/env bash
# session-context: print a short project summary
touch "$HOME/.cache/session-context.last" 2>/dev/null || true
echo "branch: $(git branch --show-current 2>/dev/null)"
git log --oneline -5 2>/dev/null
HOOK_EOF
chmod +x "$HOOK"

# Every new terminal.
if ! grep -q "session-context.sh" "$HOME/.bashrc" 2>/dev/null; then
  echo "[ -x \"$HOOK\" ] && \"$HOOK\"  # session-context" >> "$HOME/.bashrc"
fi

# Every new Claude Code session.
python3 - "$HOME/.claude/settings.json" "$HOOK" <<'PY'
import json, os, sys
path, hook = os.path.realpath(sys.argv[1]), sys.argv[2]  # write through a symlink, not over it
try:
    with open(path) as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}
except (OSError, ValueError):
    print("settings.json could not be read; skipped the Claude Code hook")
    sys.exit(0)
if not isinstance(cfg, dict):
    print("settings.json is not a JSON object; skipped the Claude Code hook")
    sys.exit(0)
entry = {"hooks": [{"type": "command", "command": hook}]}
starts = cfg.setdefault("hooks", {}).setdefault("SessionStart", [])
if entry not in starts:
    starts.append(entry)
tmp = path + ".tmp"
try:
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)
except OSError as e:
    sys.exit(f"could not write settings.json: {e}")
finally:
    if os.path.exists(tmp):
        os.remove(tmp)
PY

echo "session-context installed"
