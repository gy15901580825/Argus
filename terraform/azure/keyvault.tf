# ---------------------------------------------------------------------------
# Azure Key Vault — stores API keys and secrets for workloads
# ---------------------------------------------------------------------------
resource "azurerm_key_vault" "this" {
  name                       = "kv-${var.project}-${var.env}"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  enable_rbac_authorization  = true
  tags                       = local.tags
}

# Terraform operator can manage secrets
resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ---------------------------------------------------------------------------
# Workload Identity — AKS pods read secrets via CSI driver
# ---------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "kv_reader" {
  name                = "id-${var.project}-kv-reader-${var.env}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "kv_reader" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.kv_reader.principal_id
}

resource "azurerm_federated_identity_credential" "kv_reader" {
  name                = "fed-${var.project}-kv-reader"
  resource_group_name = azurerm_resource_group.this.name
  parent_id           = azurerm_user_assigned_identity.kv_reader.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject             = "system:serviceaccount:default:${var.project}-workload" # K8s ServiceAccount
}

# ---------------------------------------------------------------------------
# Populate secrets
# ---------------------------------------------------------------------------
resource "azurerm_key_vault_secret" "openai_api_key" {
  count        = var.openai_api_key != "" ? 1 : 0
  name         = "openai-api-key"
  value        = var.openai_api_key
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "anthropic_api_key" {
  count        = var.anthropic_api_key != "" ? 1 : 0
  name         = "anthropic-api-key"
  value        = var.anthropic_api_key
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "google_api_key" {
  count        = var.google_api_key != "" ? 1 : 0
  name         = "google-api-key"
  value        = var.google_api_key
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "r2_access_key_id" {
  count        = var.r2_access_key_id != "" ? 1 : 0
  name         = "r2-access-key-id"
  value        = var.r2_access_key_id
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "r2_secret_access_key" {
  count        = var.r2_secret_access_key != "" ? 1 : 0
  name         = "r2-secret-access-key"
  value        = var.r2_secret_access_key
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "pg_connection_string" {
  name         = "pg-connection-string"
  value        = "postgresql+asyncpg://${var.pg_admin_user}:${var.pg_admin_password}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/${var.pg_database_name}?sslmode=require"
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

# B2C secrets are managed in b2c_apps.tf (auto-populated from app registrations)
