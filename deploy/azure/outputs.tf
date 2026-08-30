output "api_fqdn" {
  description = "API Container App FQDN"
  value       = azurerm_container_app.api.latest_revision_fqdn
}

output "api_url" {
  description = "Full API URL"
  value       = "https://${azurerm_container_app.api.latest_revision_fqdn}"
}

output "database_fqdn" {
  description = "PostgreSQL server FQDN"
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "redis_hostname" {
  description = "Redis Cache hostname"
  value       = azurerm_redis_cache.main.hostname
}

output "container_registry" {
  description = "ACR login server"
  value       = azurerm_container_registry.main.login_server
}

output "push_commands" {
  description = "Docker push commands for initial deploy"
  value = <<-EOT
    # Login to ACR:
    az acr login --name ${azurerm_container_registry.main.name}

    # Build and push API:
    docker build -f docker/Dockerfile.api -t certmanager-api .
    docker tag certmanager-api:latest ${azurerm_container_registry.main.login_server}/certmanager-api:latest
    docker push ${azurerm_container_registry.main.login_server}/certmanager-api:latest

    # Build and push Worker:
    docker build -f docker/Dockerfile.worker -t certmanager-worker .
    docker tag certmanager-worker:latest ${azurerm_container_registry.main.login_server}/certmanager-worker:latest
    docker push ${azurerm_container_registry.main.login_server}/certmanager-worker:latest
  EOT
}

output "run_migrations" {
  description = "Command to run database migrations after first deploy"
  value = <<-EOT
    az containerapp exec \
      --name ${azurerm_container_app.api.name} \
      --resource-group ${azurerm_resource_group.main.name} \
      --command "python -m alembic -c alembic/alembic.ini upgrade head && python -m certmanager.cli seed"
  EOT
}
