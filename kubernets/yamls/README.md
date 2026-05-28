# Kubernetes YAML Configuration Files

This directory contains native YAML configuration files exported from the Kubernetes cluster.

## 📁 Directory Structure

```
yamls/
├── apisix/              # APISIX Gateway config (exported from cluster)
├── postgresql/          # PostgreSQL config (exported from cluster)
│   └── backup-cronjob.yaml  # PostgreSQL automated backup CronJob
└── kong-gateway/        # Kong API Gateway config (legacy; replaced by APISIX)
```

## 🔄 Exporting Configuration

Use the `export-configs.sh` script to export config from the cluster:

```bash
cd ..
./export-configs.sh [namespace]
```

Exported files include:
- Deployments/StatefulSets
- Services
- ConfigMaps
- Secrets (note: Secret data is base64-encoded)
- PersistentVolumeClaims
- Ingress

## 📝 Using the Exported Configuration

### Viewing Configuration

```bash
# View APISIX config
cat apisix/deployment-*.yaml

# View PostgreSQL config
cat postgresql/statefulset-*.yaml
```

### Restoring Configuration

```bash
# Restore APISIX config (if needed)
kubectl apply -f apisix/

# Restore PostgreSQL config (proceed with caution)
kubectl apply -f postgresql/
```

**Notes**:
- Understand the impact before restoring
- Secret files contain sensitive data — keep them secure
- Validate in a test environment first

## 💾 PostgreSQL Backups

### Manual Backup

```bash
# Use the backup script
../backup-postgres.sh default ./backups
```

### Automated Backup

Use a CronJob for automated backups:

```bash
# Deploy the automated backup CronJob
kubectl apply -f postgresql/backup-cronjob.yaml

# Check CronJob status
kubectl get cronjob postgres-backup

# View backup jobs
kubectl get jobs | grep postgres-backup
```

### Backup File Locations

- **Manual backups**: saved by default under `../backups/`
- **CronJob backups**: saved under the path mounted from PVC `postgres-backup-pvc`

### Restoring a Backup

```bash
# 1. Find the PostgreSQL Pod
POD_NAME=$(kubectl get pods -l app=postgresql -o jsonpath='{.items[0].metadata.name}')

# 2. Restore the database
kubectl exec -i $POD_NAME -- psql -U postgres -d argus < backups/argus_YYYYMMDD_HHMMSS.sql

# Or restore from a compressed file
gunzip -c backups/argus_YYYYMMDD_HHMMSS.sql.gz | kubectl exec -i $POD_NAME -- psql -U postgres -d argus
```

## 🔐 Security Notes

1. **Secret files**: contain sensitive data — do not commit to public repos
2. **Backup files**: contain database data — store encrypted
3. **Access control**: restrict access to the backup directory
4. **Routine cleanup**: delete expired backup files to save space

## 📚 Related Documentation

- [Main README](../README.md) — deployment and backup instructions
- [Deployment Guide](../DEPLOYMENT_GUIDE.md) — detailed deployment documentation
