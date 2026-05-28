# ---------------------------------------------------------------------------
# AKS Cluster
# ---------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster" "this" {
  name                = "aks-${var.project}-${var.env}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  dns_prefix          = "${var.project}-${var.env}"
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Free" # "Standard" for prod SLA

  tags = local.tags

  # --- System Node Pool (API services + lightweight workloads) ---
  default_node_pool {
    name                        = "system"
    vm_size                     = var.system_pool_vm_size
    node_count                  = var.system_pool_node_count
    vnet_subnet_id              = azurerm_subnet.aks.id
    os_disk_size_gb             = 64
    max_pods                    = 50
    type                        = "VirtualMachineScaleSets"

    temporary_name_for_rotation = "systemtmp"

    node_labels = {
      "workload" = "system"
    }

    upgrade_settings {
      max_surge = "33%"
    }
  }

  # --- Identity ---
  identity {
    type = "SystemAssigned"
  }

  # --- Network (Azure CNI for better pod networking) ---
  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    service_cidr      = "10.20.0.0/16"
    dns_service_ip    = "10.20.0.10"
    load_balancer_sku = "standard"

    load_balancer_profile {
      managed_outbound_ip_count = 1
    }
  }

  # --- OIDC / Workload Identity (for Key Vault integration) ---
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  # --- Monitoring ---
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  }

  # --- Auto-upgrade ---
  automatic_channel_upgrade = "patch"

  lifecycle {
    ignore_changes = [
      default_node_pool[0].node_count, # allow manual/autoscaler changes
    ]
  }
}

/*
# ---------------------------------------------------------------------------
# Browser Automation Node Pool (Chromium-heavy workloads)
# ---------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster_node_pool" "browser" {
  name                  = "browser"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  vm_size               = var.browser_pool_vm_size
  vnet_subnet_id        = azurerm_subnet.aks.id
  os_disk_size_gb       = 128 # Chromium images are large
  max_pods              = 30
  zones                 = ["1", "2"]

  # --- Autoscaling ---
  enable_auto_scaling = true
  min_count           = var.browser_pool_min_count
  max_count           = var.browser_pool_max_count

  node_labels = {
    "workload" = "browser-automation"
  }

  node_taints = [
    "workload=browser-automation:NoSchedule"
  ]

  upgrade_settings {
    max_surge = "33%"
  }

  tags = local.tags
}
*/

# ---------------------------------------------------------------------------
# Role: AKS → ACR pull permission
# ---------------------------------------------------------------------------
resource "azurerm_role_assignment" "aks_acr_pull" {
  principal_id                     = azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                            = azurerm_container_registry.this.id
  skip_service_principal_aad_check = true
}
