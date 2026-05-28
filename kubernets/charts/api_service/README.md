# Argus API Service Helm Chart

## Pre-deployment Setup

### 1. Build the Docker Image

```bash
cd api_service
docker build --network=host -t 192.168.1.121:30500/argus/api_service:1.0.0 .
docker push 192.168.1.121:30500/argus/api_service:1.0.0
```

### 2. Configure the Database Connection

**Option 1: Use the Secret from Helm values (recommended for dev/test)**

Edit `values.yaml`:
```yaml
secrets:
  databaseUrl: "postgresql+asyncpg://user:password@host:port/dbname"
  existingSecretName: ""
```

**Option 2: Use an existing Kubernetes Secret (recommended for production)**

First create the Secret:
```bash
kubectl create secret generic argus-db-secret \
  --from-literal=DATABASE_URL="postgresql+asyncpg://user:password@host:port/dbname"
```

Then reference it in `values.yaml`:
```yaml
secrets:
  databaseUrl: ""
  existingSecretName: "argus-db-secret"
```

**Option 3: Set directly in values.yaml (not recommended for production)**

```yaml
env:
  DATABASE_URL: "postgresql+asyncpg://user:password@host:port/dbname"
```

### 3. Deploy to K3s

```bash
# Install
helm install argus-api-service ./kubernets/charts/api_service \
  --namespace default \
  --create-namespace \
  -f values.yaml

# Or use a custom values file
helm install argus-api-service ./kubernets/charts/api_service \
  --namespace default \
  --create-namespace \
  -f my-values.yaml

# Upgrade
helm upgrade argus-api-service ./kubernets/charts/api_service \
  --namespace default \
  -f values.yaml

# Uninstall
helm uninstall argus-api-service --namespace default
```

## Configuration Reference

### Required Configuration

- **DATABASE_URL**: PostgreSQL connection string
  - Format: `postgresql+asyncpg://user:password@host:port/dbname`
  - Can be supplied via Secret or environment variable

### Optional Configuration

- **replicaCount**: number of Pod replicas (default: 1)
- **service.type**: Service type (default: ClusterIP)
- **resources**: resource limits and requests
- **autoscaling**: autoscaling configuration

## Verifying the Deployment

```bash
# Check Pod status
kubectl get pods -l app.kubernetes.io/name=argus-api-service

# Check the Service
kubectl get svc -l app.kubernetes.io/name=argus-api-service

# View logs
kubectl logs -l app.kubernetes.io/name=argus-api-service

# Test the API (with port-forwarding)
kubectl port-forward svc/argus-api-service 8881:8881
curl http://localhost:8881/docs
```

## Notes

1. **Database connectivity**: ensure the K3s cluster can reach the PostgreSQL database
2. **Network policy**: configure a NetworkPolicy to allow database access if required
3. **Health check**: defaults to the `/docs` endpoint for health checks
4. **Secret management**: for production, use an external secret management system (e.g. Sealed Secrets, External Secrets Operator)
