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

  auto_grow_enabled = true

  backup_retention_days = var.environment == "production" ? 30 : 7

  # Geo-redundant backup is only supported together with zone-redundant HA,
  # so it follows the same toggle.
  geo_redundant_backup_enabled = var.postgres_high_availability

  # Zone-redundant HA is not available on the burstable B-series SKUs. It is
  # opt-in via var.postgres_high_availability and requires a General Purpose
  # or Memory Optimized SKU (e.g. GP_Standard_D2s_v3).
  dynamic "high_availability" {
    for_each = var.postgres_high_availability ? [1] : []
    content {
      mode = "ZoneRedundant"
    }
  }

  public_network_access_enabled = true
}

# Allow the Container Apps environment's static outbound IP.
resource "azurerm_postgresql_flexible_server_firewall_rule" "container_apps" {
  name             = "allow-container-apps"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = azurerm_container_app_environment.main.static_ip_address
  end_ip_address   = azurerm_container_app_environment.main.static_ip_address
}

# Non-production only: allow all Azure services through (the broad 0.0.0.0
# rule). Production restricts access to the container app rule above plus
# var.allowed_db_ips.
resource "azurerm_postgresql_flexible_server_firewall_rule" "azure_services" {
  count            = var.environment != "production" ? 1 : 0
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Additional IPs, e.g. operator workstations that run migrations.
resource "azurerm_postgresql_flexible_server_firewall_rule" "additional" {
  count            = length(var.allowed_db_ips)
  name             = "allow-db-${count.index}"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = var.allowed_db_ips[count.index]
  end_ip_address   = var.allowed_db_ips[count.index]
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

  capacity             = var.redis_capacity
  family               = "C"
  sku_name             = var.redis_sku
  non_ssl_port_enabled = false

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
# Common environment variables
# =========================================================================
# The application reads pydantic-settings nested env vars with the "__"
# delimiter: CERTMGMT_DATABASE__URL, CERTMGMT_SECURITY__SECRET_KEY, etc.
# Flat names (CERTMGMT_DATABASE_URL) are silently ignored by the backend.
locals {
  database_url      = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}"
  database_url_sync = "postgresql+psycopg2://${var.db_username}:${var.db_password}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}"
  # Azure Redis requires TLS (port 6380) and the access key.
  redis_url = "rediss://:${azurerm_redis_cache.main.primary_access_key}@${azurerm_redis_cache.main.hostname}:6380/0"

  common_env = [
    { name = "CERTMGMT_ENVIRONMENT", value = var.environment },
    { name = "CERTMGMT_LOG_FORMAT", value = "json" },
    { name = "CERTMGMT_DATABASE__URL", value = local.database_url },
    { name = "CERTMGMT_DATABASE__URL_SYNC", value = local.database_url_sync },
    { name = "CERTMGMT_REDIS__URL", value = local.redis_url },
  ]

  api_env = concat(local.common_env, [
    { name = "CERTMGMT_API_HOST", value = "0.0.0.0" },
    { name = "CERTMGMT_API_PORT", value = "8000" },
    { name = "CERTMGMT_CORS__ORIGINS", value = jsonencode(["https://${var.public_domain}"]) },
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
    external_enabled           = true
    target_port                = 8000
    transport                  = "http"
    allow_insecure_connections = false

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
    # Point DNS for var.public_domain at the assigned FQDN
    # (azurerm_container_app.api.latest_revision_fqdn). To bind the custom
    # domain directly on the Container App, add a custom_domain block with
    # a managed certificate:
    # custom_domain {
    #   name                     = var.public_domain
    #   certificate_binding_type = "SniEnabled"
    #   certificate_id           = var.managed_certificate_id
    # }
  }

  identity {
    type = "SystemAssigned"
  }

  secret {
    name  = "certmanager-secret-key"
    value = var.secret_key
  }

  secret {
    name  = "certmanager-encryption-key"
    value = var.encryption_key
  }

  secret {
    name  = "certmanager-agent-psk"
    value = var.agent_psk
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = "" # use the SystemAssigned identity granted AcrPull below
  }

  template {
    container {
      name   = "api"
      image  = "${azurerm_container_registry.main.login_server}/certmanager-api:latest"
      cpu    = var.container_cpu
      memory = var.container_memory

      dynamic "env" {
        for_each = local.api_env
        content {
          name  = env.value.name
          value = env.value.value
        }
      }

      env {
        name        = "CERTMGMT_SECURITY__SECRET_KEY"
        secret_name = "certmanager-secret-key"
      }
      env {
        name        = "CERTMGMT_SECURITY__ENCRYPTION_KEY"
        secret_name = "certmanager-encryption-key"
      }
      env {
        name        = "CERTMGMT_AGENT__PSK"
        secret_name = "certmanager-agent-psk"
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

  identity {
    type = "SystemAssigned"
  }

  secret {
    name  = "certmanager-secret-key"
    value = var.secret_key
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = "" # use the SystemAssigned identity granted AcrPull below
  }

  template {
    container {
      name   = "worker"
      image  = "${azurerm_container_registry.main.login_server}/certmanager-worker:latest"
      cpu    = var.container_cpu
      memory = var.container_memory
      args   = ["celery", "-A", "certmanager.workers.celery_app", "worker", "--loglevel=info", "--concurrency=4"]

      dynamic "env" {
        for_each = local.common_env
        content {
          name  = env.value.name
          value = env.value.value
        }
      }

      env {
        name        = "CERTMGMT_SECURITY__SECRET_KEY"
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

  identity {
    type = "SystemAssigned"
  }

  secret {
    name  = "certmanager-secret-key"
    value = var.secret_key
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = "" # use the SystemAssigned identity granted AcrPull below
  }

  template {
    container {
      name   = "scheduler"
      image  = "${azurerm_container_registry.main.login_server}/certmanager-worker:latest"
      cpu    = "0.25"
      memory = "0.5Gi"
      args   = ["celery", "-A", "certmanager.workers.celery_app", "beat", "--loglevel=info"]

      dynamic "env" {
        for_each = local.common_env
        content {
          name  = env.value.name
          value = env.value.value
        }
      }

      env {
        name        = "CERTMGMT_SECURITY__SECRET_KEY"
        secret_name = "certmanager-secret-key"
      }
    }

    max_replicas = 1
    min_replicas = 1
  }
}

# =========================================================================
# Role assignments: allow Container Apps to pull from ACR
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

resource "azurerm_role_assignment" "acr_pull_scheduler" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_container_app.scheduler.identity[0].principal_id
}
