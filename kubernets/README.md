# Argus Kubernetes Deployment

Kubernetes deployment configuration and Helm Charts.

## 📚 Documentation

- **[Deployment Guide](./DEPLOYMENT_GUIDE.md)** — Detailed deployment instructions and configuration reference
- **[Quick Inspection Script](./view-deployment.sh)** — Quickly inspect service configuration

## 🚀 Quick Start

### Inspect the Deployment

```bash
# Show an overview of all services
./view-deployment.sh

# Show the configuration of a specific service
./view-deployment.sh orchestrator
./view-deployment.sh api_service
./view-deployment.sh testing_api_service

# Show full details for all services
./view-deployment.sh all
```

### Deploy the Services

#### Method 1: Use the Deployment Script (Recommended)

```bash
# Deploy all services with Helm
./deploy.sh helm all default

# Deploy a single service with Helm
./deploy.sh helm orchestrator default
./deploy.sh helm api_service default
./deploy.sh helm testing_api_service default

# Deploy with kubectl (renders the Helm chart first, then applies with kubectl)
./deploy.sh kubectl all default
./deploy.sh kubectl orchestrator default
```

#### Method 2: Use Helm Manually

```bash
# Deploy Orchestrator
helm install argus-orchestrator \
  ./charts/orchestrator \
  --namespace default \
  --create-namespace

# Deploy API Service
helm install argus-api-service \
  ./charts/api_service \
  --namespace default

# Deploy Testing API Service
helm install argus-testing-api-service \
  ./charts/testing_api_service \
  --namespace default
```

#### Method 3: Use kubectl (via Helm template)

```bash
# Render the Helm chart to YAML
helm template argus-orchestrator \
  ./charts/orchestrator \
  --namespace default > orchestrator.yaml

# Deploy with kubectl
kubectl apply -f orchestrator.yaml -n default
```

### Uninstall Services

```bash
# Uninstall via the script
./undeploy.sh helm all default

# Or uninstall manually
helm uninstall argus-orchestrator -n default
helm uninstall argus-api-service -n default
helm uninstall argus-testing-api-service -n default
```

## 📁 Directory Structure

```
kubernets/
├── charts/                    # Helm Charts
│   ├── orchestrator/
│   ├── api_service/
│   └── testing_api_service/
├── yamls/                     # Native Kubernetes YAML
│   ├── apisix/                # APISIX Gateway config (exported from cluster)
│   ├── postgresql/            # PostgreSQL config (exported from cluster)
│   └── kong-gateway/         # Kong API Gateway config (legacy)
├── DEPLOYMENT_GUIDE.md        # Detailed deployment guide
├── view-deployment.sh         # Quick inspection script
├── export-configs.sh          # Export APISIX and PostgreSQL config
├── deploy.sh                  # Deployment script (supports Helm and kubectl)
└── undeploy.sh                # Uninstallation script
```

## 🔄 Exporting Existing Deployment Configurations

If APISIX and PostgreSQL are already deployed in your cluster, you can use the script to export their configuration:

```bash
# Export configuration from the default namespace
./export-configs.sh

# Export configuration from a specific namespace
./export-configs.sh production
```

The exported configuration files are saved to:
- `yamls/apisix/` — APISIX Gateway configuration
- `yamls/postgresql/` — PostgreSQL configuration

## 💾 PostgreSQL Data Backup

### Method 1: Backup via `kubectl exec` (Recommended)

```bash
# 1. Find the PostgreSQL Pod name
kubectl get pods -n default | grep postgres

# 2. Get database connection info (from a Secret or ConfigMap)
kubectl get secret postgresql-secret -n default -o jsonpath='{.data}' | base64 -d

# 3. Run the backup (replace POD_NAME and database name)
POD_NAME=$(kubectl get pods -n default -l app=postgresql -o jsonpath='{.items[0].metadata.name}')
DB_NAME="argus"  # Replace with your database name
BACKUP_FILE="postgres_backup_$(date +%Y%m%d_%H%M%S).sql"

# Back up a single database
kubectl exec -n default $POD_NAME -- pg_dump -U postgres $DB_NAME > $BACKUP_FILE

# Back up all databases
kubectl exec -n default $POD_NAME -- pg_dumpall -U postgres > postgres_all_$(date +%Y%m%d_%H%M%S).sql
```

### Method 2: Automatic Backup via CronJob

Create a backup CronJob (see the script below).

### Method 3: Back Up the PVC (Persistent Volume)

```bash
# 1. Find the PostgreSQL PVC
kubectl get pvc -n default | grep postgres

# 2. Create a backup Pod that mounts the PVC
kubectl run postgres-backup-$(date +%s) \
  --image=postgres:15 \
  --restart=Never \
  --overrides='
{
  "spec": {
    "containers": [{
      "name": "backup",
      "image": "postgres:15",
      "command": ["sh", "-c", "tar czf /backup/data.tar.gz /var/lib/postgresql/data && echo Backup completed"],
      "volumeMounts": [{
        "mountPath": "/var/lib/postgresql/data",
        "name": "postgres-data",
        "readOnly": true
      }, {
        "mountPath": "/backup",
        "name": "backup"
      }]
    }],
    "volumes": [{
      "name": "postgres-data",
      "persistentVolumeClaim": {
        "claimName": "postgres-pvc"  # Replace with your PVC name
      }
    }, {
      "name": "backup",
      "hostPath": {
        "path": "/tmp/postgres-backup",
        "type": "DirectoryOrCreate"
      }
    }]
  }
}'
```

### Method 4: Use `pg_dump` via the Service

```bash
# 1. Port-forward the PostgreSQL Service
kubectl port-forward svc/postgresql 5432:5432 -n default &

# 2. Run the backup locally
PGPASSWORD=your_password pg_dump -h localhost -U postgres -d argus > backup.sql

# 3. Stop the port-forward
kill %1
```

### Restoring Data

```bash
# Restore a single database
POD_NAME=$(kubectl get pods -n default -l app=postgresql -o jsonpath='{.items[0].metadata.name}')
kubectl exec -i -n default $POD_NAME -- psql -U postgres -d argus < backup.sql

# Restore all databases
kubectl exec -i -n default $POD_NAME -- psql -U postgres < postgres_all_backup.sql
```

### Automatic Backup Script

See the [backup-postgres.sh](./backup-postgres.sh) script for setting up automatic backups.

## 🔍 Understanding the Configuration Files

Key files in each Helm Chart:

- **`values.yaml`** — Configuration values (image, ports, environment variables, etc.)
- **`templates/deployment.yaml`** — Pod deployment configuration
- **`templates/service.yaml`** — Service exposure configuration
- **`templates/secret.yaml`** — Secret configuration

For detailed explanations, see [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md).

## 📋 Quick Reference

### Export Configuration

```bash
# Export APISIX and PostgreSQL config
./export-configs.sh

# Export a specific namespace
./export-configs.sh production
```

### PostgreSQL Backup

```bash
# Manual backup
./backup-postgres.sh

# Back up to a specific directory
./backup-postgres.sh default /path/to/backups

# Set up automatic backups (CronJob)
kubectl apply -f yamls/postgresql/backup-cronjob.yaml
```

### Inspect Backups

```bash
# List all backups
ls -lh backups/

# View the backup manifest
cat backups/backup_manifest_*.txt
```

## 🔐 Important Notes

1. **Back up regularly**: We recommend running an automatic daily PostgreSQL backup.
2. **Verify backups**: Periodically test restoring from backup files.
3. **Off-site storage**: Copy backup files to other locations (S3, NFS, etc.).
4. **Secret management**: Ensure sensitive information such as database passwords is stored securely.
5. **Backup retention**: We recommend keeping at least 7–30 days of backups.

## 📖 More Information

- [PostgreSQL Official Backup Documentation](https://www.postgresql.org/docs/current/backup.html)
- [Kubernetes CronJob Documentation](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
