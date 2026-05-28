#!/usr/bin/env bash
# Push every key in a k8s Secret to Azure Key Vault.
# Mapping: k8s key UPPER_SNAKE_CASE -> KV name lower-kebab-case (KV doesn't allow underscores).
# Usage: ./sync-api-secret-to-kv.sh [namespace] [secret-name]
set -euo pipefail

VAULT="${VAULT:-<YOUR_KEY_VAULT>}"
NAMESPACE="${1:-default}"
SECRET_NAME="${2:-argus-api-service-secret}"

echo "Syncing $NAMESPACE/$SECRET_NAME -> $VAULT"

kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o json \
  | python3 -c '
import json, sys, base64
d = json.load(sys.stdin)
for k, v in sorted(d["data"].items()):
    decoded = base64.b64decode(v).decode("utf-8")
    kv_name = k.lower().replace("_", "-")
    print(f"{kv_name}\t{decoded}")
' \
  | while IFS=$'\t' read -r kv_name value; do
      echo "  -> $kv_name"
      az keyvault secret set --vault-name "$VAULT" --name "$kv_name" --value "$value" --output none
    done

echo "Done. KV now contains:"
az keyvault secret list --vault-name "$VAULT" --query "[].name" -o tsv | sort
