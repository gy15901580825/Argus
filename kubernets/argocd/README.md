# ArgoCD manifests for Argus

Two environments on the same AKS cluster (`<YOUR_AKS_LEGACY>`):

| Env  | Namespace | Release name              | Values file               | Domain                       | Sync mode   |
|------|-----------|---------------------------|---------------------------|------------------------------|-------------|
| prod | `default` | `argus-<svc>`         | `values-azure.yaml`       | `https://www.example.com`  | **manual**  |
| dev  | `dev`     | `argus-<svc>-dev`     | `values-azure-dev.yaml`   | `https://dev.example.com`  | auto + prune + self-heal |

Six services deploy to AKS. `client_agent` runs on edge/client machines — not managed by ArgoCD.

## Files

- `project.yaml` — `AppProject argus`. Scopes source repo + destination namespaces.
- `appset-prod.yaml` — `ApplicationSet argus-prod`. List generator fans out to 6 prod Applications.
- `appset-dev.yaml` — `ApplicationSet argus-dev`. Same, for dev.
- `bootstrap.sh` — installs ArgoCD (argo-helm chart) + applies the three manifests above.
- `ingress.yaml` — (optional) exposes ArgoCD UI at `https://argocd.example.com` via the shared NGINX Ingress + cert-manager. Apply only after re-running bootstrap with `ARGOCD_SERVER_INSECURE=true`.

## Bootstrap (one-time per cluster)

```bash
# Make sure kubectl points at the right cluster
kubectl config current-context    # expect <YOUR_AKS_LEGACY>

./argocd/bootstrap.sh
```

Then grab the admin password and open the UI:

```bash
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath='{.data.password}' | base64 -d; echo

kubectl -n argocd port-forward svc/argocd-server 8080:443
# → https://localhost:8080  (user: admin)
```

## (Optional) Expose ArgoCD UI at argocd.example.com

```bash
# 1. Re-run bootstrap with insecure mode (TLS terminated by NGINX Ingress instead of argocd-server)
ARGOCD_SERVER_INSECURE=true ./argocd/bootstrap.sh

# 2. Add Cloudflare DNS A record: argocd.example.com → 4.144.5.209 (proxied)

# 3. Apply the Ingress (cert-manager auto-issues a Let's Encrypt cert)
kubectl apply -f argocd/ingress.yaml

# 4. Watch cert issuance
kubectl -n argocd describe certificate argocd-tls
```

Then open https://argocd.example.com (admin password from `argocd-initial-admin-secret`).
**Change the admin password immediately** — Settings → Accounts → admin → Update Password.

## How CI and ArgoCD interact

1. Service repo CI (e.g. `api_service`) on push to `main`:
   - builds image, pushes to ACR with tag `YYYYMMDD-{sha7}`
   - commits `image.tag: "..."` bump to `charts/<svc>/values-azure.yaml` in **this** repo
2. ArgoCD notices the commit on `main`, re-renders the chart, and:
   - **dev** Application: auto-sync (prunes removed resources, heals manual drift)
   - **prod** Application: stays `OutOfSync` until you click Sync (or `argocd app sync`)

## Promoting dev → prod

Today: the CI bumps **only** `values-azure.yaml`. Dev values (`values-azure-dev.yaml`) are not touched
by default and keep whatever image.tag you last set (e.g. `dev-latest`). If you want dev to track
commits as well, extend the CI workflow to also bump dev values when the push is to a `dev` branch —
or use ArgoCD Image Updater to watch the ACR repository directly for dev.

## Flipping prod to auto-sync later

Edit `appset-prod.yaml`:

```yaml
syncPolicy:
  automated:
    prune: true
    selfHeal: true
```

then `kubectl apply -f argocd/appset-prod.yaml`.

## Known chart gaps

- `charts/testing_web_fetch_service/` has no `values-azure.yaml` or `values-azure-dev.yaml`.
  The ApplicationSet uses `ignoreMissingValueFiles: true`, so sync will still work from base
  `values.yaml`, but you should add the overrides if you want env-specific image tags /
  resource limits there.
- `charts/client_agent/` does not exist (edge service, not deployed to AKS).

## Useful commands

```bash
# See everything ArgoCD thinks it's managing
kubectl -n argocd get applications,applicationsets

# Diff current cluster state vs git for one app
argocd app diff argus-api_service-prod

# Force sync one app
argocd app sync argus-api_service-dev

# Hard refresh (re-read git, ignore cache)
argocd app get argus-frontend-prod --hard-refresh
```
