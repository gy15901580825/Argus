# Deployment Runbook

## Docker Images

Build and push to Azure ACR via the repo-root script:

```bash
# Single service
./build-and-push.sh <service_name> <tag>

# All services
./build-and-push.sh all 1.0.0
```

Run `az acr login --name <YOUR_ACR>` first — ACR tokens expire after ~3 hours.

### Registry rules

- **client_agent** → Docker Hub: `<your-gh-user>/client_agent:latest`
- **All other services** → Azure ACR: `<YOUR_ACR>.azurecr.io/argus/<service>:<tag>`

## AKS Deployment (Production)

```bash
# Helm install/upgrade (use -f values-azure.yaml for Azure overrides)
helm upgrade --install argus-<service> ./kubernets/charts/<service> \
  -f ./kubernets/charts/<service>/values.yaml \
  -f ./kubernets/charts/<service>/values-azure.yaml

# Quick image update (tag change only)
kubectl set image deployment/argus-<service> \
  argus-<service>=<YOUR_ACR>.azurecr.io/argus/<service>:<new_tag>

# Restart after pushing a new image under the same tag
kubectl rollout restart deployment/argus-<service>
```

## Frontend Deployment

`NEXT_PUBLIC_*` env vars (including `NEXT_PUBLIC_API_URL=https://www.example.com`) are baked in at Docker build time, so **any domain or env change requires a full image rebuild**:

```bash
./build-and-push.sh frontend <new_tag>
kubectl set image deployment/argus-frontend \
  argus-frontend=<YOUR_ACR>.azurecr.io/argus/frontend:<new_tag>
```

## Domain Change Checklist

When changing the production domain, update all of the following:

1. `kubernets/ingress-azure.yaml` — TLS host + ingress rule host
2. `frontend/Dockerfile` — `ARG NEXT_PUBLIC_API_URL` default
3. `frontend/src/lib/api.ts` — `API_BASE_URL` fallback
4. `frontend/src/components/OAuthTokenDialog.tsx` — WSS/HTTPS fallback URLs
5. DNS — A/CNAME record pointing to AKS Ingress External IP
6. TLS — `kubectl delete secret argus-tls` then re-apply ingress (cert-manager auto-renews)
7. Azure CIAM — Update SPA redirect URIs via `az rest --method PATCH` against Graph API

## Legacy (k3s) Environment

A secondary k3s environment exists on `asus-laptop` (KUBECONFIG=/home/test/.kube/config) with local registry `192.168.1.121:30500`. It uses the same Helm charts with default `values.yaml` (no `-azure` override).

### Wizard rollout (Phase 2)

The planner option-picker wizard is feature-flagged via `WIZARD_MODE_ENABLED`.
Default is `false` in both prod and dev. Rollout stages (see
`docs/superpowers/specs/2026-04-21-planner-option-picker-design.md` §11):

1. V13 migration applied.
2. Code deployed to dev, flag off. Free-text 5-scenario E2E still passes.
3. Flip `WIZARD_MODE_ENABLED=true` in `values-azure-dev.yaml`; helm upgrade
   argus-orchestrator-dev and argus-api-service-dev.
4. 24h dev observation — metrics meet §11.4 targets.
5. V13 migration on prod; deploy code, flag off.
6. Flip flag on in prod. 1h active watch + 24h passive.

Rollback: set `WIZARD_MODE_ENABLED=false` and helm upgrade. No schema revert.

## Secrets management (External Secrets Operator)

As of 2026-04-30, `api_service` credentials in **prod** are managed by External Secrets Operator pulling from Azure Key Vault `<YOUR_KEY_VAULT>`. Other services (orchestrator, testing-*, frontend, dev api-service) still use literal Secrets — follow-up plan covers them.

### Cluster prerequisites
- AKS OIDC issuer enabled (`az aks update --enable-oidc-issuer`)
- AKS Workload Identity enabled (`--enable-workload-identity`)
- UAMI `eso-kv-reader` in `<YOUR_RG_WESTUS>` with `Key Vault Secrets User` role on `<YOUR_KEY_VAULT>`
- Federated credential `eso-controller` binding the UAMI to ServiceAccount `external-secrets/external-secrets`

### Install ESO from scratch
```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
CLIENT_ID=$(az identity show -g <YOUR_RG_WESTUS> -n eso-kv-reader --query clientId -o tsv)
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace \
  -f kubernets/eso/values.yaml \
  --set 'serviceAccount.annotations.azure\.workload\.identity/client-id'="$CLIENT_ID"
kubectl apply -f kubernets/eso/cluster-secret-store.yaml
```
File `kubernets/eso/values.yaml` has the install contract documented inline (chart version pin, CRD lifecycle warning, identity-binding override pattern).

### ArgoCD prerequisite
The `argus` AppProject must whitelist `external-secrets.io/*` in `namespaceResourceWhitelist` for ArgoCD to manage ExternalSecret resources. See `kubernets/argocd/project.yaml`.

### Day-2 workflows
- Add a key, rotate a value, bootstrap KV from a live Secret → see `kubernets/DEV_DEPLOYMENT_GUIDE.md` § Secrets management.
- The bulk-sync helper `kubernets/scripts/sync-api-secret-to-kv.sh` reads a k8s Secret and pushes each key to KV under the kebab-case name convention; useful for cluster rebuilds.

### Reference
- Implementation plan: `docs/superpowers/plans/2026-04-29-eso-credentials-migration-api-service.md`
- The 2026-04-30 incident that triggered this migration is documented in commit `7ca6fec` (the `existingSecretName` band-aid that stabilized prod before ESO went live).
