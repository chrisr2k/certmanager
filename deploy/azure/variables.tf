# =========================================================================
# Required
# =========================================================================
variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "Environment must be staging or production"
  }
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus2"
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "certmanager"
}

# =========================================================================
# Database
# =========================================================================
variable "postgres_sku" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "postgres_storage_gb" {
  description = "PostgreSQL storage in GB"
  type        = number
  default     = 32
}

variable "db_username" {
  description = "Database admin username"
  type        = string
  default     = "certmanager"
}

variable "db_password" {
  description = "Database admin password"
  type        = string
  sensitive   = true
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "certmanager"
}

# =========================================================================
# Redis
# =========================================================================
variable "redis_sku" {
  description = "Redis Cache SKU"
  type        = string
  default     = "Basic"
}

variable "redis_capacity" {
  description = "Redis Cache capacity"
  type        = number
  default     = 1
}

# =========================================================================
# Security
# =========================================================================
variable "secret_key" {
  description = "Application secret key for JWT signing"
  type        = string
  sensitive   = true
}

variable "agent_psk" {
  description = "Pre-shared key for agent registration"
  type        = string
  sensitive   = true
  default     = ""
}

# =========================================================================
# Compute
# =========================================================================
variable "api_replicas" {
  description = "API container replicas"
  type        = number
  default     = 2
}

variable "worker_replicas" {
  description = "Worker container replicas"
  type        = number
  default     = 2
}

variable "container_cpu" {
  description = "CPU cores per container"
  type        = string
  default     = "0.5"
}

variable "container_memory" {
  description = "Memory per container"
  type        = string
  default     = "1.0Gi"
}

# =========================================================================
# Container Registry
# =========================================================================
variable "acr_sku" {
  description = "Azure Container Registry SKU"
  type        = string
  default     = "Basic"
}
