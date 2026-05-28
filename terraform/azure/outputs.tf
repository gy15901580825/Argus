# ---------------------------------------------------------------------------
# Outputs — used by CI/CD and Helm deployments
# ---------------------------------------------------------------------------

# AKS
output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.this.name
}

output "aks_resource_group" {
  value = azurerm_resource_group.this.name
}

output "aks_kube_config_command" {
  value = "az aks get-credentials --resource-group ${azurerm_resource_group.this.name} --name ${azurerm_kubernetes_cluster.this.name}"
}

# ACR
output "acr_login_server" {
  value       = azurerm_container_registry.this.login_server
  description = "Use this as image registry in Helm values, e.g. <login_server>/argus/api_service:latest"
}

output "acr_name" {
  value = azurerm_container_registry.this.name
}

# PostgreSQL
output "pg_fqdn" {
  value       = azurerm_postgresql_flexible_server.this.fqdn
  description = "PostgreSQL hostname — accessible only from AKS VNet"
}

output "pg_connection_string" {
  value     = "postgresql+asyncpg://${var.pg_admin_user}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/${var.pg_database_name}?sslmode=require"
  sensitive = true
}

# Key Vault
output "keyvault_name" {
  value = azurerm_key_vault.this.name
}

output "keyvault_uri" {
  value = azurerm_key_vault.this.vault_uri
}

output "workload_identity_client_id" {
  value       = azurerm_user_assigned_identity.kv_reader.client_id
  description = "Use as azure.workload_identity/client-id annotation on K8s ServiceAccount"
}

# Quick-start
output "next_steps" {
  value = <<-EOT

    === Argus AKS post-deployment steps ===

    1. Fetch kubeconfig:
       az aks get-credentials -g ${azurerm_resource_group.this.name} -n ${azurerm_kubernetes_cluster.this.name}

    2. Push images to ACR:
       az acr login -n ${azurerm_container_registry.this.name}
       docker tag 192.168.1.121:30500/argus/api_service:latest ${azurerm_container_registry.this.login_server}/argus/api_service:latest
       docker push ${azurerm_container_registry.this.login_server}/argus/api_service:latest

    3. Install the NGINX Ingress Controller:
       helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
       helm install ingress-nginx ingress-nginx/ingress-nginx --namespace ingress-nginx --create-namespace

    4. Run Flyway database migrations:
       flyway -url=jdbc:postgresql://${azurerm_postgresql_flexible_server.this.fqdn}:5432/${var.pg_database_name} -user=${var.pg_admin_user} -password=<password> -locations=filesystem:database/sql migrate

    5. Deploy the Helm charts (update image.repository in values.yaml to the ACR address)

  EOT
}

# ---------------------------------------------------------------------------
# Microsoft Entra External ID (CIAM)
# ---------------------------------------------------------------------------
output "ciam_authority" {
  value       = "https://${var.ciam_tenant_name}.ciamlogin.com/"
  description = "CIAM authority URL for frontend MSAL config"
}

output "ciam_frontend_client_id" {
  value       = azuread_application.ciam_frontend.client_id
  description = "CIAM frontend SPA client ID (NEXT_PUBLIC_CIAM_CLIENT_ID)"
}

output "ciam_backend_client_id" {
  value       = azuread_application.ciam_backend.client_id
  description = "CIAM backend API client ID"
}

output "ciam_backend_client_secret" {
  value       = azuread_application_password.ciam_backend.value
  sensitive   = true
  description = "CIAM backend API client secret"
}

# ---------------------------------------------------------------------------
# Test Runner
# ---------------------------------------------------------------------------
output "test_runner_node_pool_name" {
  value       = azurerm_kubernetes_cluster_node_pool.test_runner.name
  description = "Name of the test runner node pool"
}

output "test_runner_service_endpoint" {
  value       = "http://${kubernetes_service.test_runner.metadata[0].name}.${kubernetes_namespace.test_runner.metadata[0].name}.svc.cluster.local:8000"
  description = "Internal service endpoint for the test runner"
}
