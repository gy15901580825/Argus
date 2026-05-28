# ---------------------------------------------------------------------------
# Azure Container Registry
# ---------------------------------------------------------------------------
resource "azurerm_container_registry" "this" {
  name                = "${replace(var.project, "-", "")}${replace(var.env, "-", "")}acr" # must be globally unique, alphanumeric
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "Basic" # upgrade to Standard when image count grows
  admin_enabled       = false   # use managed identity, not admin credentials
  tags                = local.tags
}
