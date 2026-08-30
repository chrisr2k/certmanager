output "api_fqdn" {
  description = "API Container App FQDN — point DNS for public_domain at this name"
  value       = azurerm_container_app.api.latest_revision_fqdn
}

output "public_domain" {
  description = "Configured public domain for the application"
  value       = var.public_domain
}

output "api_url" {
  description = "Full API URL (requires DNS for public_domain to resolve)"
  value       = "https://${var.public_domain}"
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
  value       = <<-EOT
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
  value       = <<-EOT
    az containerapp exec \
      --name ${azurerm_container_app.api.name} \
      --resource-group ${azurerm_resource_group.main.name} \
      --command "python -m certmanager.cli migrate && python -m certmanager.cli seed"
  EOT
}
