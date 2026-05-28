# ---------------------------------------------------------------------------
# Azure Database for PostgreSQL — Flexible Server
# ---------------------------------------------------------------------------
resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "pg-${var.project}-${var.env}"
  location                      = azurerm_resource_group.this.location
  resource_group_name           = azurerm_resource_group.this.name
  version                       = "16"
  sku_name                      = var.pg_sku
  storage_mb                    = var.pg_storage_mb
  administrator_login           = var.pg_admin_user
  administrator_password        = var.pg_admin_password
  delegated_subnet_id           = azurerm_subnet.pg.id
  private_dns_zone_id           = azurerm_private_dns_zone.pg.id
  public_network_access_enabled = false
  backup_retention_days         = 7
  geo_redundant_backup_enabled  = false
  zone                          = "1"
  tags                          = local.tags

  depends_on = [
    azurerm_private_dns_zone_virtual_network_link.pg,
  ]
}

resource "azurerm_postgresql_flexible_server_database" "app" {
  name      = var.pg_database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# Allow Azure services (AKS pods) to connect
resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  server_id = azurerm_postgresql_flexible_server.this.id
  name      = "azure.extensions"
  value     = "UUID-OSSP,PG_TRGM"
}
