# Argus Kubernetes Deployment Guide

This document helps you understand and deploy all components of the Argus system to a K3s cluster.

## 📁 Directory Structure

```
kubernets/
├── charts/                          # Helm Charts (recommended deployment method)
│   ├── orchestrator/     # Orchestrator service
│   ├── api_service/      # API service
│   └── testing_api_service/ # API testing service
├── yamls/                           # Native Kubernetes YAML files
│   ├── apisix/                      # APISIX Gateway config (exported from cluster)
│   ├── postgresql/                  # PostgreSQL config (exported from cluster)
│   │   └── backup-cronjob.yaml       # PostgreSQL automatic backup CronJob
│   └── kong-gateway/                # Kong API Gateway config (legacy)
├── export-configs.sh                # Script to export APISIX and PostgreSQL configs
├── backup-postgres.sh               # PostgreSQL backup script
└── view-deployment.sh                # Script for quick inspection of deployment config
```

## 🎯 Deployment Method Comparison

### Method 1: Helm Charts (Recommended)

**Pros:**
- More flexible configuration management (via `values.yaml`)
- Supports parameterized configuration
- Easy version management and upgrades
- Supports dependency management

**Use case:** Production environments and any scenario requiring flexible configuration.

### Method 2: Native YAML Files

**Pros:**
- Simple and direct
- Easy to understand and debug
- Suitable for quick testing

**Use case:** Development testing and simple deployments.

## 📊 Service Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    APISIX Gateway                       │
│              (yamls/apisix/)                            │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐
│ Orchestrator │  │ API Service  │  │ Testing API  │
│   (8081)     │  │   (8881)     │  │  (8000)     │
└──────────────┘  └──────────────┘  └─────────────┘
        │                 │
        └─────────┬───────┘
                  │
         ┌────────▼────────┐
         │  PostgreSQL DB  │
         │ (yamls/postgresql/) │
         └─────────────────┘
```

**Note:** The system uses APISIX as the API Gateway (replacing Kong). The configuration has been exported from the cluster into the `yamls/apisix/` directory.

## 🔍 How to Inspect and Understand the Deployment

### 1. Inspect Helm Chart Structure

Each Helm Chart contains the following files:

```
charts/<service>/
├── Chart.yaml              # Chart metadata (name, version, etc.)
├── values.yaml              # Default configuration values (most important config file)
└── templates/               # Kubernetes resource templates
    ├── _helpers.tpl         # Template helper functions
    ├── deployment.yaml      # Deployment configuration
    ├── service.yaml         # Service configuration
    ├── secret.yaml          # Secret configuration
    └── serviceaccount.yaml   # ServiceAccount configuration
```

**Key files:**

- **`values.yaml`**: The most important configuration file. It contains:
  - Image repository and tag
  - Replica count
  - Environment variables
  - Secret configuration
  - Resource limits
  - Service type

- **`templates/deployment.yaml`**: Defines how Pods run.
  - Container image
  - Environment variable injection
  - Health checks
  - Resource limits

- **`templates/service.yaml`**: Defines how the service is exposed.
  - Service type (ClusterIP/NodePort/LoadBalancer)
  - Port mappings

### 2. Commands to View Configuration

```bash
# List all Helm charts
ls -la kubernets/charts/

# View the configuration of a specific service
cat kubernets/charts/orchestrator/values.yaml

# View the rendered YAML (without actually deploying)
helm template argus-orchestrator \
  ./kubernets/charts/orchestrator \
  --namespace default

# View all Kubernetes resources
kubectl get all -n default
```

### 3. Understanding Key Configuration Items

#### Image Configuration
```yaml
image:
  repository: registry.registry.svc.cluster.local:5000/argus/orchestrator
  tag: "1.0.0"
  pullPolicy: IfNotPresent
```

#### Environment Variables
```yaml
env:
  DATABASE_URL: "postgresql+asyncpg://..."
  GEMINI_MODEL_NAME: "gemini-3-pro-preview"
```

#### Secret Configuration
```yaml
secrets:
  existingSecretName: ""  # Use an existing Secret
  # or
  googleApiKey: ""          # Configure directly in values.yaml (not recommended for production)
```

## 🚀 Deployment Steps

### Step 1: Prepare Secrets

```bash
# Create the database Secret
kubectl create secret generic argus-db-secret \
  --from-literal=DATABASE_URL="postgresql+asyncpg://user:pass@host:port/db" \
  --namespace default

# Create the API Key Secret
kubectl create secret generic argus-secrets \
  --from-literal=GOOGLE_API_KEY="your-key" \
  --namespace default
```

### Step 2: Update values.yaml

Edit each service's `values.yaml` to configure:
- Image repository (already updated to `registry.registry.svc.cluster.local:5000`)
- Secret references
- Environment variables
- Resource limits

### Step 3: Deploy the Services

```bash
# Deploy Orchestrator
helm install argus-orchestrator \
  ./kubernets/charts/orchestrator \
  --namespace default \
  --create-namespace

# Deploy API Service
helm install argus-api-service \
  ./kubernets/charts/api_service \
  --namespace default

# Deploy Testing API Service
helm install argus-testing-api-service \
  ./kubernets/charts/testing_api_service \
  --namespace default
```

### Step 4: Verify the Deployment

```bash
# List all deployments
helm list -n default

# Check Pod status
kubectl get pods -n default

# Check Services
kubectl get svc -n default

# View logs
kubectl logs -l app.kubernetes.io/name=argus-orchestrator -n default
```

## 📝 Configuration File Reference

### Orchestrator Service

**Primary function:** AI agent orchestration service.

**Key configuration:**
- Port: 8081
- Dependencies: Google API Key, MCP tool service
- Environment variables: `MCP_API_TESTING_URL`, `GEMINI_MODEL_NAME`

**View configuration:**
```bash
cat kubernets/charts/orchestrator/values.yaml
```

### API Service

**Primary function:** User authentication, agent registration, token management.

**Key configuration:**
- Port: 8881
- Dependencies: PostgreSQL database
- Environment variables: `DATABASE_URL`

**View configuration:**
```bash
cat kubernets/charts/api_service/values.yaml
```

### Testing API Service

**Primary function:** API testing service that provides MCP tools.

**Key configuration:**
- Port: 8000
- Dependencies: Google API Key, Cloudflare R2
- Environment variables: `FASTMCP_HOST`, `FASTMCP_PORT`

**View configuration:**
```bash
cat kubernets/charts/testing_api_service/values.yaml
```

## 🔧 Common Operations

### Update Configuration

```bash
# Edit values.yaml
vim kubernets/charts/orchestrator/values.yaml

# Upgrade the deployment
helm upgrade argus-orchestrator \
  ./kubernets/charts/orchestrator \
  --namespace default
```

### View the Live Running Configuration

```bash
# View Deployment
kubectl get deployment argus-orchestrator -n default -o yaml

# Inspect Pod environment variables
kubectl describe pod <pod-name> -n default

# View Secret
kubectl get secret argus-db-secret -n default -o yaml
```

### Debugging Issues

```bash
# View Pod logs
kubectl logs <pod-name> -n default

# Exec into the Pod for debugging
kubectl exec -it <pod-name> -n default -- /bin/bash

# View events
kubectl get events -n default --sort-by='.lastTimestamp'
```

## 📚 Related Documentation

- [Docker Registry Usage](../DOCKER_REGISTRY.md)
- [Helm Official Documentation](https://helm.sh/docs/)
- [Kubernetes Official Documentation](https://kubernetes.io/docs/)

## 🆘 FAQ

### Q: How do I know which Secrets need to be configured?

A: Check the `env` section in `templates/deployment.yaml`. Every entry referenced via `secretKeyRef` needs to be configured.

### Q: How do I change a service port?

A: Update `service.port` in `values.yaml` and `containerPort` in `deployment.yaml`.

### Q: How do I add a new environment variable?

A: Add it under the `env` section in `values.yaml`, then reference it in `templates/deployment.yaml`.

### Q: How can I see which resources a Helm Chart will create?

A: Use the `helm template` command:
```bash
helm template release-name ./chart-path --debug
```

## 🔄 Exporting Existing Deployment Configurations

If APISIX and PostgreSQL are already deployed in your cluster, you can use the script to export their configuration:

### Export Configuration

```bash
# Export configuration from the default namespace
./export-configs.sh

# Export configuration from a specific namespace
./export-configs.sh production
```

**What is exported:**
- APISIX Gateway: Deployments, Services, ConfigMaps, Secrets, Ingress
- PostgreSQL: StatefulSets/Deployments, Services, ConfigMaps, Secrets, PVCs

**Output locations:**
- `yamls/apisix/` — APISIX-related configuration
- `yamls/postgresql/` — PostgreSQL-related configuration

**Using the exported configuration:**
```bash
# Inspect the exported configuration
cat yamls/apisix/deployment-*.yaml
cat yamls/postgresql/statefulset-*.yaml

# Restore the configuration (use with caution)
kubectl apply -f yamls/apisix/
kubectl apply -f yamls/postgresql/
```

## 💾 PostgreSQL Data Backup

### Backup Methods

#### Method 1: Use the Backup Script (Recommended)

```bash
# Basic backup (default namespace)
./backup-postgres.sh

# Specify namespace and backup directory
./backup-postgres.sh default /path/to/backups

# Back up all databases
BACKUP_MODE=all ./backup-postgres.sh
```

**Backup file naming:**
- Single database: `argus_YYYYMMDD_HHMMSS.sql.gz`
- Full-cluster backup: `postgres_all_YYYYMMDD_HHMMSS.sql.gz`
- Backup manifest: `backup_manifest_YYYYMMDD_HHMMSS.txt`

#### Method 2: Direct backup via `kubectl exec`

```bash
# 1. Find the PostgreSQL Pod
POD_NAME=$(kubectl get pods -l app=postgresql -o jsonpath='{.items[0].metadata.name}')

# 2. Back up a single database
kubectl exec -n default $POD_NAME -- pg_dump -U postgres argus > backup.sql

# 3. Back up all databases
kubectl exec -n default $POD_NAME -- pg_dumpall -U postgres > backup_all.sql

# 4. Compress the backup
gzip backup.sql
```

#### Method 3: Automatic Backup (CronJob)

```bash
# Deploy the automatic backup CronJob
kubectl apply -f yamls/postgresql/backup-cronjob.yaml

# Check CronJob status
kubectl get cronjob postgres-backup

# View backup job execution history
kubectl get jobs | grep postgres-backup

# Manually trigger a backup (for testing)
kubectl create job --from=cronjob/postgres-backup postgres-backup-manual-$(date +%s)
```

**CronJob configuration notes:**
- Defaults to running a backup daily at 02:00
- Automatically prunes backups older than 7 days
- Backups are stored in the PVC `postgres-backup-pvc`
- The schedule can be modified in `yamls/postgresql/backup-cronjob.yaml`

#### Method 4: Back Up the PVC (Persistent Volume)

```bash
# 1. Find the PostgreSQL PVC
kubectl get pvc -n default | grep postgres

# 2. Create a snapshot (if the StorageClass supports it)
kubectl apply -f - <<EOF
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: postgres-snapshot-$(date +%s)
  namespace: default
spec:
  source:
    persistentVolumeClaimName: postgres-pvc
EOF
```

### Restore from Backup

```bash
# 1. Find the PostgreSQL Pod
POD_NAME=$(kubectl get pods -l app=postgresql -o jsonpath='{.items[0].metadata.name}')

# 2. Restore a single database
kubectl exec -i -n default $POD_NAME -- psql -U postgres -d argus < backup.sql

# 3. Restore from a compressed file
gunzip -c backup.sql.gz | kubectl exec -i -n default $POD_NAME -- psql -U postgres -d argus

# 4. Restore all databases
kubectl exec -i -n default $POD_NAME -- psql -U postgres < backup_all.sql
```

### Backup Best Practices

1. **Regular backups**
   - Production: automatic daily backups
   - Development: weekly backups
   - Use a CronJob for automation

2. **Backup verification**
   - Periodically test restoring from backup files
   - Verify backup file integrity
   - Check that backup file sizes look reasonable

3. **Backup storage**
   - Local storage: PVC or hostPath
   - Off-site storage: S3, NFS, object storage
   - Multiple replicas: keep copies in multiple locations

4. **Backup retention policy**
   - Daily backups: retain 7 days
   - Weekly backups: retain 4 weeks
   - Monthly backups: retain 12 months

5. **Security measures**
   - Encrypt backup files (they contain sensitive data)
   - Restrict access permissions on backup files
   - Periodically prune expired backups

6. **Monitoring and alerting**
   - Monitor backup job execution status
   - Configure alerts for backup failures
   - Track backup storage usage

### Backup Script Usage Examples

```bash
# Show backup-script help
./backup-postgres.sh

# Back up to a specific directory
./backup-postgres.sh default ./backups

# List backup files
ls -lh backups/

# View the backup manifest
cat backups/backup_manifest_*.txt
```

### Disaster Recovery Flow

1. **Identify the issue**
   ```bash
   kubectl get pods -l app=postgresql
   kubectl logs <postgres-pod>
   ```

2. **Pick a backup**
   ```bash
   ls -lt backups/ | head -5
   ```

3. **Restore the data**
   ```bash
   ./backup-postgres.sh  # First, back up the current state (if any)
   # Then restore the chosen backup
   ```

4. **Verify the restore**
   ```bash
   kubectl exec <postgres-pod> -- psql -U postgres -d argus -c "SELECT COUNT(*) FROM users;"
   ```
