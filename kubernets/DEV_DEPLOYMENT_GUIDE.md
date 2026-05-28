# Dev Environment Runbook

## Overview

- **URL**: https://dev.example.com
- **Namespace**: `dev` (AKS cluster `<YOUR_AKS_LEGACY>`)
- **Database**: `argus_dev` (same instance as prod)
- **Image tag convention**: `dev-latest` or `dev-<gitsha-short>`

## Day-to-day iteration

**Restart a single service:**
```bash
kubectl -n dev rollout restart deployment/argus-<svc>-dev
```

**Push a new image and roll out (backend services):**
```bash
./build-and-push.sh <service> dev-$(git rev-parse --short HEAD)
kubectl -n dev set image deployment/argus-<svc>-dev \
  argus-<svc>=<YOUR_ACR>.azurecr.io/argus/<service>:dev-<sha>
```

**Push a new image and roll out (frontend):**
The frontend must be rebuilt with build-args:
```bash
cd frontend
docker build \
  --build-arg NEXT_PUBLIC_API_URL=https://dev.example.com \
  --build-arg NEXT_PUBLIC_GA_MEASUREMENT_ID=<YOUR_GA_MEASUREMENT_ID> \
  --build-arg NEXT_PUBLIC_CIAM_TENANT_NAME=argus \
  --build-arg NEXT_PUBLIC_CIAM_CLIENT_ID=<YOUR_CLIENT_ID> \
  -t <YOUR_ACR>.azurecr.io/argus/frontend:dev-$(git rev-parse --short HEAD) .
docker push <YOUR_ACR>.azurecr.io/argus/frontend:dev-$(git rev-parse --short HEAD)
kubectl -n dev set image deployment/argus-frontend-dev \
  argus-frontend=<YOUR_ACR>.azurecr.io/argus/frontend:dev-<sha>
```

## View logs
```bash
kubectl -n dev logs -f deployment/argus-<svc>-dev
```

## Reset data
```bash
psql "host=<YOUR_PG_SERVER>... dbname=postgres" -c "DROP DATABASE argus_dev;"
psql "host=<YOUR_PG_SERVER>... dbname=postgres" -c "CREATE DATABASE argus_dev OWNER pgadmin;"
# Re-run Flyway
cd database && flyway migrate -url=... -user=pgadmin -password=...
```

## Temporarily shut down dev (save resources)
```bash
kubectl -n dev scale deployment --all --replicas=0
```
To bring it back up: `--replicas=1`.

## Comparison with prod
| Aspect | prod | dev |
|---|---|---|
| URL | https://www.example.com | https://dev.example.com |
| Namespace | default | dev |
| DB | argus | argus_dev |
| Helm release | argus-<svc> | argus-<svc>-dev |
| Image tag | version number | dev-latest / dev-<sha> |
| test-runner | test-runner ns (shared) | same (cross-ns call) |

## Troubleshooting

**Pod fails to start**: `kubectl -n dev describe pod <name>` to inspect Events.
**Secret missing a key**: `kubectl -n dev get secret argus-dev-secrets -o yaml`; recreate if necessary.
**TLS certificate Ready=False**: check `kubectl -n dev describe certificate argus-dev-tls`; usually DNS hasn't propagated or Let's Encrypt rate-limited.
**Frontend calling the prod API**: the frontend image's build-arg is wrong; rebuild the image.
**CIAM callback failing**: `az ad app show --id 865329eb-... --query spa.redirectUris`; confirm it includes `https://dev.example.com`.

## Secrets management — api-service (prod, ESO mode) — as of 2026-04-30

`api_service` credentials are synced from Azure Key Vault by the External Secrets Operator. When `externalSecrets.enabled=true`, the Helm chart renders an ExternalSecret CRD; ESO pulls the matching KV secrets into the cluster Secret `argus-api-service-secret` (the deployment env references this Secret name).

**Add a new secret key:**
1. Push to KV: `az keyvault secret set --vault-name <YOUR_KEY_VAULT> --name <kebab-case-name> --file <(printf '%s' "$value")` (pass the value via a file to keep it out of the process list)
2. In `charts/api_service/values.yaml`, add a mapping under `externalSecrets.keyMap`: `NEW_KEY_NAME: kebab-case-name`
3. In `templates/deployment.yaml`, add the env reference (use the existing fullname-secret expression for `secretKeyRef.name`)
4. helm upgrade (in prod this is driven by ArgoCD sync; ESO reconciles automatically afterward)

**Rotate a secret value (no schema change):**
1. `az keyvault secret set --vault-name <YOUR_KEY_VAULT> --name <name> --file <tmpfile>`
2. Force an ESO refresh: `kubectl annotate externalsecret argus-api-service-secret -n default force-sync=$(date +%s) --overwrite` (otherwise wait up to 1h)
3. `kubectl rollout restart deploy argus-api-service` (env is bound at pod startup, so the pod must restart to pick up the new value)
4. End-to-end connectivity check (R2 as an example):
   ```bash
   POD=$(kubectl get pod -n default -l app.kubernetes.io/instance=argus-api-service -o jsonpath='{.items[0].metadata.name}')
   kubectl exec -n default "$POD" -- python3 -c 'import os,boto3; s3=boto3.client("s3", endpoint_url=f"https://{os.environ[\"R2_ACCOUNT_ID\"]}.r2.cloudflarestorage.com", aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"], aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"], region_name="auto"); print(s3.head_bucket(Bucket=os.environ["R2_BUCKET_NAME"]))'
   ```

**Bootstrap KV (one-shot fill from an existing live Secret, used when rebuilding a cluster):**
```bash
./scripts/sync-api-secret-to-kv.sh <namespace> <secret-name>
```
The KV naming convention (UPPER_SNAKE_CASE → lower-kebab-case) is documented in the script header.

**dev is out of ESO scope:** The dev api-service uses `existingSecretName: argus-dev-secrets` to share the dev 31-key Secret (also used by orchestrator + testing-*). That Secret is created once by `dev-secret-create.sh` and does not go through ESO. To modify a dev secret, run `kubectl edit/patch secret argus-dev-secrets -n dev` directly (ArgoCD will not overwrite it because the chart does not render the Secret).

## Fully tear down the dev environment

```bash
# Delete every Helm release
for svc in api-service orchestrator frontend testing-api-service testing-web-ui-service; do
  helm uninstall argus-$svc-dev -n dev
done
# Delete the Ingress
kubectl delete -f kubernets/ingress-azure-dev.yaml
# Delete Secrets and the namespace
kubectl delete namespace dev
# Delete the database
psql "...dbname=postgres" -c "DROP DATABASE argus_dev;"
# Delete the DNS record manually
# Remove the dev URL from CIAM redirectUris manually
```

prod is entirely unaffected (different ns, different Ingress, different DB).

## References
- Design doc: `docs/superpowers/specs/2026-04-16-azure-dev-env-design.md`
- Implementation plan: `docs/superpowers/plans/2026-04-16-azure-dev-env.md`
