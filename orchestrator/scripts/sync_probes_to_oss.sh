#!/bin/bash
# One-shot: copy probe YAMLs from orchestrator into argus-research/probes.
# Run from orchestrator/ working dir.
#
# Setup:
#   1. Create GitHub org `argus-research` (manual)
#   2. Create repo `argus-research/probes` with MIT license (manual)
#   3. Clone it next to argus:
#      cd /path/to/argus/parent && git clone git@github.com:argus-research/probes argus-research-probes
#   4. Run this script from orchestrator/
#
# Override OSS_REPO env var to use a non-default path.

set -euo pipefail
OSS_REPO="${OSS_REPO:-../argus-research-probes}"
test -d "$OSS_REPO" || { echo "OSS repo path not found: $OSS_REPO"; exit 1; }
test -d "$OSS_REPO/probes" || mkdir -p "$OSS_REPO/probes/owasp" "$OSS_REPO/probes/syscard" "$OSS_REPO/probes/garak" "$OSS_REPO/probes/browser"
test -d "$OSS_REPO/rubrics" || mkdir -p "$OSS_REPO/rubrics"

# Mirror probes by category (each filename pattern matches a category).
rsync -av --delete --include='owasp_*.yaml' --exclude='*' orchestrator/redteam/probes/ "$OSS_REPO/probes/owasp/"
rsync -av --delete --include='syscard_*.yaml' --exclude='*' orchestrator/redteam/probes/ "$OSS_REPO/probes/syscard/"
rsync -av --delete orchestrator/redteam/probes/garak/ "$OSS_REPO/probes/garak/"
rsync -av --delete orchestrator/redteam/probes/browser/ "$OSS_REPO/probes/browser/"
rsync -av --delete orchestrator/redteam/rubrics/ "$OSS_REPO/rubrics/"

echo "synced. Now: cd $OSS_REPO && git status && git diff and commit if good."
