variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = "<YOUR_SUBSCRIPTION_ID>"
}

variable "project" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "argus"
}

variable "env" {
  description = "Environment (dev / staging / prod)"
  type        = string
  default     = "dev"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastasia"
}

# ---------------------------------------------------------------------------
# AKS
# ---------------------------------------------------------------------------
variable "kubernetes_version" {
  description = "Kubernetes version for AKS"
  type        = string
  default     = "1.30"
}

variable "system_pool_vm_size" {
  description = "VM SKU for the system node pool"
  type        = string
  default     = "Standard_D2s_v5" # 2 vCPU, 8 GiB
}

variable "system_pool_node_count" {
  description = "Node count for system pool"
  type        = number
  default     = 2
}

variable "browser_pool_vm_size" {
  description = "VM SKU for the browser automation node pool"
  type        = string
  default     = "Standard_D4s_v5" # 4 vCPU, 16 GiB
}

variable "browser_pool_min_count" {
  description = "Min nodes for browser pool (autoscale)"
  type        = number
  default     = 1
}

variable "browser_pool_max_count" {
  description = "Max nodes for browser pool (autoscale)"
  type        = number
  default     = 3
}

# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
variable "pg_sku" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "B_Standard_B1ms" # Burstable 1 vCPU, 2 GiB
}

variable "pg_storage_mb" {
  description = "PostgreSQL storage in MB"
  type        = number
  default     = 32768 # 32 GiB
}

variable "pg_admin_user" {
  description = "PostgreSQL admin username"
  type        = string
  default     = "pgadmin"
}

variable "pg_admin_password" {
  description = "PostgreSQL admin password"
  type        = string
  sensitive   = true
}

variable "pg_database_name" {
  description = "Application database name"
  type        = string
  default     = "argus"
}

# ---------------------------------------------------------------------------
# Secrets (stored in Key Vault, passed at plan time)
# ---------------------------------------------------------------------------
variable "openai_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "google_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "r2_access_key_id" {
  type      = string
  sensitive = true
  default   = ""
}

variable "r2_secret_access_key" {
  type      = string
  sensitive = true
  default   = ""
}

# ---------------------------------------------------------------------------
# Microsoft Entra External ID (CIAM)
# ---------------------------------------------------------------------------
variable "ciam_tenant_id" {
  description = "Entra External ID tenant ID (set after manual tenant creation in Azure Portal)"
  type        = string
  default     = ""
}

variable "ciam_tenant_name" {
  description = "Entra External ID tenant subdomain (e.g. yourtenant-dev — the part before .onmicrosoft.com)"
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Test Runner
# ---------------------------------------------------------------------------
variable "test_runner_vm_size" {
  description = "VM SKU for test runner node pool. B-series recommended for burst workloads."
  type        = string
  default     = "Standard_B2as_v2" # 2 vCPU, 8GB RAM, ~$45/month
}

variable "test_runner_min_count" {
  description = "Minimum node count (0 = scale to zero when idle)"
  type        = number
  default     = 0
}

variable "test_runner_max_count" {
  description = "Maximum node count"
  type        = number
  default     = 2
}

variable "test_runner_image" {
  description = "Docker image for the test runner"
  type        = string
  default     = "<YOUR_ACR>.azurecr.io/argus/test_runner:1.0.0"
}

variable "test_runner_max_concurrent_browsers" {
  description = "Max concurrent Playwright browser instances (each ~500MB RAM)"
  type        = number
  default     = 2
}

variable "test_runner_api_service_url" {
  description = "Internal URL of the API service"
  type        = string
  default     = "http://argus-api-service.default.svc.cluster.local:8881"
}
