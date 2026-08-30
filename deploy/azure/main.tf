# =========================================================================
# CertManager — Azure Deployment (OpenTofu)
# =========================================================================
# Deploys: Resource Group, PostgreSQL Flexible Server, Redis Cache,
#          Azure Container Registry, Container Apps (API + Worker + Scheduler)
#
# Usage:
#   cp terraform.tfvars.example terraform.tfvars
#   tofu init
#   tofu plan
#   tofu apply
# =========================================================================

# =========================================================================
# Resource Group
# =========================================================================
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
}

# =========================================================================
# Log Analytics Workspace
# =========================================================================
resource "azurerm_log_analytics_workspace" "main" {
  name                = "certmanager-${var.environment}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# =========================================================================
# Application Insights
# =========================================================================
resource "azurerm_application_insights" "main" {
  name                = "certmanager-${var.environment}-appinsights"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  application_type    = "web"
  workspace_id        = azurerm_log_analytics_workspace.main.id
}

# =========================================================================
# PostgreSQL Flexible Server
# =========================================================================
resource "azurerm_postgresql_flexible_server" "main" {
  name                = "certmanager-${var.environment}-pg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  administrator_login    = var.db_username
  administrator_password = var.db_password

  version    = "16"
  sku_name   = var.postgres_sku
  storage_mb = var.postgres_storage_gb * 1024

  storage_auto_grow = "Enabled"

  backup_retention_days = var.environment == "production" ? 30 : 7
  geo_redundant_backup  = var.environment == "production"

  high_availability {
    mode = var.environment == "production" ? "ZoneRedundant" : "Disabled"
  }

  delegated_subnet_id    = null
  private_dns_zone_id    = null
  public_network_access_enabled = true

  # Allow Azure services
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = var.db_name
  server_id = azurerm_postgresql_flexible_server.main.id
}

# =========================================================================
# Redis Cache
# =========================================================================
resource "azurerm_redis_cache" "main" {
  name                = "certmanager-${var.environment}-redis"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  capacity            = var.redis_capacity
  family              = "C"
  sku_name            = var.redis_sku
  enable_non_ssl_port = false

  minimum_tls_version = "1.2"
}

# =========================================================================
# Azure Container Registry
# =========================================================================
resource "azurerm_container_registry" "main" {
  name                = "certmanager${var.environment}acr"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = var.acr_sku
  admin_enabled       = true
}

# =========================================================================
# Container Apps Environment
# =========================================================================
resource "azurerm_container_app_environment" "main" {
  name                = "certmanager-${var.environment}-env"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}

# =========================================================================
# Common secrets and env vars
# =========================================================================
locals {
  common_env = [
    { name = "CERTMGMT_ENVIRONMENT", value = var.environment },
    { name = "CERTMGMT_LOG_FORMAT", value = "json" },
    { name = "CERTMGMT_DATABASE_URL", value = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}" },
    { name = "CERTMGMT_REDIS_URL", value = "redis://${azurerm_redis_cache.main.hostname}:6379/0" },
  ]

  common_secrets = [
    { name = "certmanager-secret-key", value = var.secret_key },
  ]

  api_env = concat(local.common_env, [
    { name = "CERTMGMT_API_HOST", value = "0.0.0.0" },
    { name = "CERTMGMT_API_PORT", value = "8000" },
  ])
}

# =========================================================================
# Container App: API
# =========================================================================
resource "azurerm_container_app" "api" {
  name                         = "certmanager-api-${var.environment}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"
  }

  identity {
    type = "SystemAssigned"
  }

  secret {
    name  = "certmanager-secret-key"
    value = var.secret_key
  }

  secret {
    name  = "db-password"
    value = var.db_password
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = ""
  }

  template {
    container {
      name   = "api"
      image  = "${azurerm_container_registry.main.login_server}/certmanager-api:latest"
      cpu    = var.container_cpu
      memory = var.container_memory

      env {
        name  = "CERTMGMT_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "CERTMGMT_LOG_FORMAT"
        value = "json"
      }
      env {
        name  = "CERTMGMT_API_HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "CERTMGMT_API_PORT"
        value = "8000"
      }
      env {
        name  = "CERTMGMT_CORS_ORIGINS"
        value = "[\"https://${azurerm_container_app.api.latest_revision_fqdn}\"]"
      }
      env {
        name  = "CERTMGMT_ENCRYPTION_KEY"
        value = ""
      }
      env {
        name  = "CERTMGMT_DATABASE_URL"
        value = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}"
      }
      env {
        name  = "CERTMGMT_REDIS_URL"
        value = "redis://${azurerm_redis_cache.main.hostname}:6379/0"
      }
      env {
        name        = "CERTMGMT_SECRET_KEY"
        secret_name = "certmanager-secret-key"
      }

      liveness_probe {
        path                    = "/api/health"
        port                    = 8000
        transport               = "HTTP"
        initial_delay           = 15
        interval_seconds        = 15
        timeout                 = 5
        failure_count_threshold = 3
      }

      readiness_probe {
        path                    = "/api/health"
        port                    = 8000
        transport               = "HTTP"
        initial_delay           = 5
        interval_seconds        = 5
        timeout                 = 2
        success_count_threshold = 1
      }
    }

    max_replicas = var.api_replicas * 4
    min_replicas = var.api_replicas

    http_scale_rule {
      name                = "http-requests"
      concurrent_requests = 50
    }
  }
}

# =========================================================================
# Container App: Worker
# =========================================================================
resource "azurerm_container_app" "worker" {
  name                         = "certmanager-worker-${var.environment}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  secret {
    name  = "certmanager-secret-key"
    value = var.secret_key
  }

  secret {
    name  = "db-password"
    value = var.db_password
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = ""
  }

  template {
    container {
      name    = "worker"
      image   = "${azurerm_container_registry.main.login_server}/certmanager-worker:latest"
      cpu     = var.container_cpu
      memory  = var.container_memory
      args    = ["celery", "-A", "certmanager.workers.celery_app", "worker", "--loglevel=info", "--concurrency=4"]

      env {
        name  = "CERTMGMT_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "CERTMGMT_LOG_FORMAT"
        value = "json"
      }
      env {
        name  = "CERTMGMT_DATABASE_URL"
        value = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}"
      }
      env {
        name  = "CERTMGMT_REDIS_URL"
        value = "redis://${azurerm_redis_cache.main.hostname}:6379/0"
      }
      env {
        name        = "CERTMGMT_SECRET_KEY"
        secret_name = "certmanager-secret-key"
      }
    }

    max_replicas = var.worker_replicas * 4
    min_replicas = var.worker_replicas
  }
}

# =========================================================================
# Container App: Scheduler (Celery Beat)
# =========================================================================
resource "azurerm_container_app" "scheduler" {
  name                         = "certmanager-scheduler-${var.environment}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  secret {
    name  = "certmanager-secret-key"
    value = var.secret_key
  }

  secret {
    name  = "db-password"
    value = var.db_password
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = ""
  }

  template {
    container {
      name    = "scheduler"
      image   = "${azurerm_container_registry.main.login_server}/certmanager-worker:latest"
      cpu     = "0.25"
      memory  = "0.5Gi"
      args    = ["celery", "-A", "certmanager.workers.celery_app", "beat", "--loglevel=info"]

      env {
        name  = "CERTMGMT_ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "CERTMGMT_LOG_FORMAT"
        value = "json"
      }
      env {
        name  = "CERTMGMT_DATABASE_URL"
        value = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}"
      }
      env {
        name  = "CERTMGMT_REDIS_URL"
        value = "redis://${azurerm_redis_cache.main.hostname}:6379/0"
      }
      env {
        name        = "CERTMGMT_SECRET_KEY"
        secret_name = "certmanager-secret-key"
      }
    }

    max_replicas = 1
    min_replicas = 1
  }
}

# =========================================================================
# Role assignment: allow Container Apps to pull from ACR
# =========================================================================
resource "azurerm_role_assignment" "acr_pull_api" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.api.identity[0].principal_id
}

resource "azurerm_role_assignment" "acr_pull_worker" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.worker.identity[0].principal_id
}
