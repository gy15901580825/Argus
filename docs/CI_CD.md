# Argus CI/CD Pipeline

Argus uses a polyrepo layout (one independent GitHub repo per service). CI/CD has two halves:
**GitHub Actions** (build, test, push image, bump values) + **ArgoCD** (GitOps that pulls the kubernets repo state and rolls it out to AKS).

## Topology

```
[7 service repos]              [kubernets repo]              [AKS <YOUR_AKS_LEGACY>]
  api_service                   charts/                        namespace: default (prod)
  orchestrator                    <svc>/              namespace: dev     (dev)
  client_agent       ──CI──>      values.yaml          ──ArgoCD──> Helm release
  frontend                        values-azure.yaml                 argus-<svc>      (prod)
  testing_api_service             values-azure-dev.yaml             argus-<svc>-dev  (dev)
  testing_web_fetch_service     argocd/
  testing_web_ui_service          project.yaml
                                  appset-prod.yaml
                                  appset-dev.yaml
```

> `client_agent` runs on client-side edge machines and is not deployed to AKS (not listed in any ApplicationSet), but it still uses the same CI pipeline to push images.

## Service-repo CI (`.github/workflows/ci.yml`)

**Triggers**: `pull_request` or `push` to `main` / `dev`

### Job 1 — `test` (runs on both PR and push)

- **Python services** (api_service / orchestrator / client_agent / testing_*)
  `setup-python@v5` (3.11) → `pip install -r requirements-dev.txt` → `pytest --cov` → upload coverage artifact
- **frontend**
  `setup-node@v4` (22) → `npm ci` → `lint` → `prettier --check` → `vitest run` → `npm run build`

### Job 2 — `build-and-deploy` (only on `push` to `main` / `dev`, depends on `test` passing)

#### 2.1 Resolve environment variables (by branch)

| Branch | target | tag                | floating_tag | values_file              |
|--------|--------|--------------------|--------------|--------------------------|
| `main` | prod   | `YYYYMMDD-{sha7}`  | `latest`     | `values-azure.yaml`      |
| `dev`  | dev    | `dev-{sha7}`       | `dev-latest` | `values-azure-dev.yaml`  |

#### 2.2 Log in to the image registry

| Service         | Registry   | Image name                                        |
|-----------------|------------|---------------------------------------------------|
| `client_agent`  | Docker Hub | `<your-gh-user>/client_agent`                      |
| Other 6 services | Azure ACR (OIDC) | `<YOUR_ACR>.azurecr.io/argus/<svc>` |

#### 2.3 Build and push images

`docker/build-push-action@v6`:

- Tags both `tag` and `floating_tag` simultaneously
- Buildcache is bucketed per environment: `buildcache-prod` / `buildcache-dev`, to keep prod and dev from polluting each other
- **frontend special**: `NEXT_PUBLIC_API_URL` is injected as a build-arg (prod=`https://www.example.com`, dev=`https://dev.example.com`), because Next.js bakes it into the JS bundle at build time and it cannot be changed at runtime

#### 2.4 Bump values in the kubernets repo

```bash
# Use PAT (KUBERNETS_REPO_TOKEN) to checkout the kubernets repo @ main
# Update image.tag in charts/<svc>/<values_file>
yq -i ".image.tag = \"$NEW_TAG\"" "$FILE"
git commit -m "ci(<svc>): <target> bump to <tag>"
git push origin main
```

If the tag hasn't changed (a repeat build), the commit is skipped.

## ArgoCD (GitOps)

All manifests live in `kubernets/argocd/`.

### `project.yaml` — `AppProject argus`

- Source repo restricted to `<your-gh-user>/kubernets`
- Destination namespaces restricted to `default` / `dev` / `test-runner`
- Acts as an RBAC boundary that prevents Applications from being mistakenly installed into another namespace

### `appset-prod.yaml` — `ApplicationSet argus-prod`

- List generator enumerates 6 services (api_service, orchestrator, frontend, testing_api_service, testing_web_fetch_service, testing_web_ui_service)
- Each service is rendered into an Application:
  - `namespace=default`
  - Release name `argus-<svc>`
  - values = `values.yaml + values-azure.yaml`
- **Manual sync** (`automated: null`) — ArgoCD UI shows `OutOfSync`; an operator must click Sync or run `argocd app sync` to roll out

### `appset-dev.yaml` — `ApplicationSet argus-dev`

- Same 6 services
- `namespace=dev`, release `argus-<svc>-dev`, values = `values.yaml + values-azure-dev.yaml`
- **Auto sync**: `automated.prune=true` + `selfHeal=true`
  - prune: if a resource is deleted from git, it is also deleted from the cluster
  - selfHeal: manual `kubectl edit` changes are reverted

### `bootstrap.sh` (one-time script)

```bash
./argocd/bootstrap.sh
# Installs ArgoCD (argo-helm 7.7.11) → applies the project + both appsets
```

## End-to-end release

### dev: fully automated

```
Developer pushes to the dev branch
   ↓ (GitHub Actions, ~3-5 min)
test job → build-and-deploy job
   ↓
Image pushed to ACR/Docker Hub: <repo>:dev-{sha7} + dev-latest
   ↓
The kubernets repo main branch receives a commit:
  image.tag in charts/<svc>/values-azure-dev.yaml is updated to dev-{sha7}
   ↓ (ArgoCD polls, ~1-3 min)
ApplicationSet re-renders → Application becomes OutOfSync
   ↓ (auto-sync triggers)
helm upgrade → rolling update in the AKS dev namespace
   ↓
https://dev.example.com is live
```

### prod: semi-automated

The `main` branch follows the same flow, but the last step stops at `OutOfSync` and waits for an operator to click Sync before going to prod.

```bash
argocd app sync argus-api_service-prod
# Or click Sync in the UI
```

## Key design points

1. **GitOps single source of truth**: cluster state = current state of the kubernets repo. To roll back, just `git revert` that bump commit — no `kubectl rollout undo` needed.
2. **Manual sync for prod**: keeps a human gate to avoid accidental hot-fix pushes. Flipping the `automated` block in `appset-prod.yaml` switches it to auto.
3. **dev / prod share one chart**: stack overrides via `-f values.yaml -f values-azure[-dev].yaml`; CI only changes the one `image.tag` line.
4. **Cache bucketed per environment**: `buildcache-prod` / `buildcache-dev` are managed separately, avoiding cross-pollution.
5. **Image tags are immutable**: `YYYYMMDD-{sha7}` / `dev-{sha7}` always points to that exact commit; `latest` / `dev-latest` are floating tags, only used for local / debugging.

## Common operations

```bash
# List all apps currently managed by ArgoCD
kubectl -n argocd get applications,applicationsets

# Diff an app against git
argocd app diff argus-api_service-prod

# Force sync
argocd app sync argus-api_service-dev

# Force refresh (re-read git, bypass cache)
argocd app get argus-frontend-prod --hard-refresh

# Roll back prod: from the kubernets repo
git revert <bump-commit-sha>
git push origin main
# ArgoCD will show OutOfSync; click Sync to complete the rollback
```

## Known gaps

- `charts/client_agent/` does not exist (edge service, not on AKS). The client_agent CI will attempt a bump, and **the first push to main will error out at the bump step** — either add a chart, or remove the bump stage from that service's CI.
- `charts/testing_web_fetch_service/templates/deployment.yaml:45-51` drops the `GOOGLE_API_KEY` env when `existingSecretName` is set (the `if not` branch has no `else` referencing the existing secret); the dev environment will be missing this variable until the template is patched.
- The `testing_web_fetch_service` chart does not support `extraEnv` (other charts do); if dev needs injections like `ENVIRONMENT=dev`, the chart must be extended first.

## Secret-naming landmine (must-read before integrating with ArgoCD)

The three chart families in the dev environment use inconsistent secret-key naming conventions. `argus-dev-secrets` (31 keys) stores every alias redundantly to satisfy them all:

| chart                      | Expected key naming                      |
|----------------------------|------------------------------------------|
| orchestrator               | `AZURE_API_*` (litellm) + `R2_*`         |
| testing_{api,web-ui}       | `AZURE_OPENAI_*` + `CLOUDFLARE_R2_*`     |
| api_service                | `AZURE_OPENAI_*` + `R2_*` (in a separate secret `argus-api-service-dev-secret` because the chart does not support an external secret) |

When a new chart needs to reference secrets, reuse the existing key names first to avoid introducing yet another convention.

## File index

- Service repo: `<service>/.github/workflows/ci.yml`
- ArgoCD manifests: `kubernets/argocd/{project,appset-prod,appset-dev}.yaml`
- Bootstrap: `kubernets/argocd/bootstrap.sh`
- Chart values: `kubernets/charts/<svc>/{values,values-azure,values-azure-dev}.yaml`
- Operator runbooks: `kubernets/{DEPLOYMENT_GUIDE,DEV_DEPLOYMENT_GUIDE}.md`
- ArgoCD README: `kubernets/argocd/README.md`
