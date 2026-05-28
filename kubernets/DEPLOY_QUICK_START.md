# Quick Deployment Guide

This document covers the simplest deployment paths.

## 🚀 One-shot deploy all services

```bash
cd kubernets

# Deploy all services with Helm (recommended)
./deploy.sh helm all default

# Or deploy with kubectl
./deploy.sh kubectl all default
```

## 📦 Deploy a single service

```bash
# Deploy Orchestrator
./deploy.sh helm orchestrator default

# Deploy API Service
./deploy.sh helm api_service default

# Deploy Testing API Service
./deploy.sh helm testing_api_service default
```

## 🔍 Check deployment status

```bash
# List all Pods
kubectl get pods -n default

# List all Services
kubectl get svc -n default

# List Helm Releases (if using Helm)
helm list -n default

# View service logs
kubectl logs -l app.kubernetes.io/name=argus-orchestrator -n default
```

## 🗑️ Uninstall services

```bash
# Uninstall all services
./undeploy.sh helm all default

# Uninstall a single service
./undeploy.sh helm orchestrator default
```

## ⚙️ Pre-deployment setup

### 1. Create required Secrets

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

### 2. Update values.yaml (optional)

To customize configuration, edit the appropriate `charts/<service>/values.yaml`:

```bash
# Edit the config
vim charts/orchestrator/values.yaml
```

### 3. Ensure images are built and pushed

```bash
# Build and push images (from the project root)
cd ..
./build-and-push.sh all 1.0.0
```

## 📋 Recommended deployment order

1. **PostgreSQL** (if not already running)
2. **API Service** (provides auth and Agent registration)
3. **Testing API Service** (provides MCP tools)
4. **Orchestrator** (depends on the other services)

## 🔧 Deployment methods

### Helm method (recommended)

- **Pros**:
  - Supports version management
  - Easy to upgrade and roll back
  - More flexible configuration management

- **Usage**: `./deploy.sh helm <service> <namespace>`

### kubectl method

- **Pros**:
  - No Helm dependency
  - Lets you inspect the rendered YAML
  - Good for debugging

- **Usage**: `./deploy.sh kubectl <service> <namespace>`
- **Output**: Rendered YAML is saved in the `rendered/` directory

## 🆘 FAQ

### Q: Deployment fails with an image-pull error.

A: Make sure:
1. The image has been pushed to the registry
2. K3s can reach the registry
3. The image address in `values.yaml` is correct

### Q: Pod stays in Pending forever.

A: Check:
1. Whether the node has enough resources: `kubectl describe node`
2. Whether the PVC was created successfully: `kubectl get pvc`
3. Inspect Pod events: `kubectl describe pod <pod-name>`

### Q: How do I inspect the deployed configuration?

A:
```bash
# View the Helm-rendered config
helm get manifest argus-orchestrator -n default

# Or view the live resource
kubectl get deployment argus-orchestrator -n default -o yaml
```

### Q: How do I update a deployment?

A:
```bash
# Upgrade with Helm
helm upgrade argus-orchestrator \
  ./charts/orchestrator \
  --namespace default

# Or redeploy via the script
./deploy.sh helm orchestrator default
```

## 📚 More information

- [Detailed deployment guide](./DEPLOYMENT_GUIDE.md)
- [Configuration inspection script](./view-deployment.sh)
- [Docker Registry notes](../DOCKER_REGISTRY.md)
