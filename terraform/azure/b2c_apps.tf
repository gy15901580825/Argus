# ---------------------------------------------------------------------------
# Microsoft Entra External ID — App Registrations
# Requires ciam_tenant_id to be set after manual tenant creation
# ---------------------------------------------------------------------------


provider "azuread" {
  alias     = "ciam"
  tenant_id = var.ciam_tenant_id
}

# ---------------------------------------------------------------------------
# Backend API App Registration
# ---------------------------------------------------------------------------
resource "azuread_application" "ciam_backend" {
  provider     = azuread.ciam
  display_name = "${var.project}-backend-${var.env}"

  sign_in_audience = "AzureADandPersonalMicrosoftAccount"

  # Application ID URI — used as audience in token requests
  identifier_uris = ["api://${var.project}-backend-${var.env}"]

  # Enable ROPC flow (Resource Owner Password Credentials) for client_agent
  fallback_public_client_enabled = true

  api {
    requested_access_token_version = 2

    oauth2_permission_scope {
      admin_consent_description  = "Access Argus API"
      admin_consent_display_name = "api.access"
      id                         = "00000000-0000-0000-0000-000000000001"
      type                       = "Admin"
      value                      = "api.access"
      enabled                    = true
    }
  }

  web {
    redirect_uris = ["https://jwt.ms/"] # For testing only
  }
}

resource "azuread_service_principal" "ciam_backend" {
  provider  = azuread.ciam
  client_id = azuread_application.ciam_backend.client_id
}

resource "azuread_application_password" "ciam_backend" {
  provider       = azuread.ciam
  application_id = azuread_application.ciam_backend.id
  display_name   = "terraform-managed"
  end_date       = "2027-01-01T00:00:00Z"
}

# ---------------------------------------------------------------------------
# Frontend SPA App Registration
# ---------------------------------------------------------------------------
resource "azuread_application" "ciam_frontend" {
  provider     = azuread.ciam
  display_name = "${var.project}-frontend-${var.env}"

  sign_in_audience = "AzureADandPersonalMicrosoftAccount"

  api {
    requested_access_token_version = 2
  }

  single_page_application {
    redirect_uris = [
      "https://www.iraylink.space/auth-redirect",
      "https://www.iraylink.space/callback",
      "http://localhost:3000/auth-redirect",
      "http://localhost:3000/callback",
    ]
  }

  # Request api.access permission on backend API
  required_resource_access {
    resource_app_id = azuread_application.ciam_backend.client_id

    resource_access {
      id   = "00000000-0000-0000-0000-000000000001" # api.access
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "ciam_frontend" {
  provider  = azuread.ciam
  client_id = azuread_application.ciam_frontend.client_id
}

# ---------------------------------------------------------------------------
# Admin consent — grant frontend delegated permission on backend API
# ---------------------------------------------------------------------------
resource "azuread_service_principal_delegated_permission_grant" "frontend_to_backend" {
  provider                         = azuread.ciam
  service_principal_object_id      = azuread_service_principal.ciam_frontend.object_id
  resource_service_principal_object_id = azuread_service_principal.ciam_backend.object_id
  claim_values                     = ["api.access"]
}

# ---------------------------------------------------------------------------
# Store secrets in Key Vault
# ---------------------------------------------------------------------------
resource "azurerm_key_vault_secret" "ciam_backend_client_id" {
  name         = "ciam-backend-client-id"
  value        = azuread_application.ciam_backend.client_id
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "ciam_backend_client_secret" {
  name         = "ciam-backend-client-secret"
  value        = azuread_application_password.ciam_backend.value
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "ciam_frontend_client_id" {
  name         = "ciam-frontend-client-id"
  value        = azuread_application.ciam_frontend.client_id
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

# Store CIAM tenant info in Key Vault for Helm deployments
resource "azurerm_key_vault_secret" "ciam_tenant_name" {
  name         = "ciam-tenant-name"
  value        = var.ciam_tenant_name
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}

resource "azurerm_key_vault_secret" "ciam_tenant_id" {
  name         = "ciam-tenant-id"
  value        = var.ciam_tenant_id
  key_vault_id = azurerm_key_vault.this.id
  depends_on   = [azurerm_role_assignment.kv_admin]
}
