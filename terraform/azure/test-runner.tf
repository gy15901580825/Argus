# ---------------------------------------------------------------------------
# Test Runner — Dedicated node pool + K8s workload for remote test execution
# Cost-optimized B-series VM with scale-to-zero for burst test workloads
# ---------------------------------------------------------------------------

# ---------- Test Runner Node Pool ----------
resource "azurerm_kubernetes_cluster_node_pool" "test_runner" {
  name                  = "testrunner"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  vm_size               = var.test_runner_vm_size
  os_disk_size_gb       = 50
  os_disk_type          = "Managed"

  vnet_subnet_id = azurerm_subnet.aks.id

  # Scale to 0 when idle to save cost
  enable_auto_scaling = true
  min_count           = var.test_runner_min_count
  max_count           = var.test_runner_max_count

  node_labels = {
    "argus/role" = "test-runner"
  }

  node_taints = [
    "workload=test-runner:NoSchedule"
  ]

  tags = local.tags
}

# ---------- Namespace ----------
resource "kubernetes_namespace" "test_runner" {
  metadata {
    name = "test-runner"
    labels = {
      "app.kubernetes.io/part-of" = "argus"
      "purpose"                   = "test-execution"
    }
  }
}

# ---------- Secrets ----------
resource "kubernetes_secret" "test_runner_secrets" {
  metadata {
    name      = "test-runner-secrets"
    namespace = kubernetes_namespace.test_runner.metadata[0].name
  }

  data = {
    "anthropic-api-key" = var.anthropic_api_key
    "google-api-key"    = var.google_api_key
  }

  type = "Opaque"
}

# ---------- Deployment ----------
resource "kubernetes_deployment" "test_runner" {
  metadata {
    name      = "test-runner"
    namespace = kubernetes_namespace.test_runner.metadata[0].name
    labels = {
      app = "test-runner"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "test-runner"
      }
    }

    template {
      metadata {
        labels = {
          app = "test-runner"
        }
      }

      spec {
        node_selector = {
          "argus/role" = "test-runner"
        }

        toleration {
          key      = "workload"
          operator = "Equal"
          value    = "test-runner"
          effect   = "NoSchedule"
        }

        container {
          name  = "test-runner"
          image = var.test_runner_image

          resources {
            requests = {
              cpu    = "500m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "1500m"
              memory = "4Gi"
            }
          }

          port {
            container_port = 8000
            name           = "http"
          }

          env {
            name  = "PYTHONUNBUFFERED"
            value = "1"
          }

          env {
            name = "ANTHROPIC_API_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.test_runner_secrets.metadata[0].name
                key  = "anthropic-api-key"
              }
            }
          }

          env {
            name = "GOOGLE_API_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.test_runner_secrets.metadata[0].name
                key  = "google-api-key"
              }
            }
          }

          env {
            name  = "API_SERVICE_URL"
            value = var.test_runner_api_service_url
          }

          env {
            name  = "PLAYWRIGHT_BROWSERS_PATH"
            value = "/ms-playwright"
          }

          env {
            name  = "MAX_CONCURRENT_BROWSERS"
            value = tostring(var.test_runner_max_concurrent_browsers)
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }

          volume_mount {
            name       = "test-output"
            mount_path = "/app/output"
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 30
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 10
          }
        }

        volume {
          name = "tmp"
          empty_dir {
            size_limit = "2Gi"
          }
        }

        volume {
          name = "test-output"
          empty_dir {
            size_limit = "1Gi"
          }
        }
      }
    }
  }

  depends_on = [azurerm_kubernetes_cluster_node_pool.test_runner]
}

# ---------- Service ----------
resource "kubernetes_service" "test_runner" {
  metadata {
    name      = "test-runner"
    namespace = kubernetes_namespace.test_runner.metadata[0].name
  }

  spec {
    selector = {
      app = "test-runner"
    }

    port {
      port        = 8000
      target_port = 8000
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}
