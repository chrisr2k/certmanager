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
  description = "PostgreSQL Flexible Server SKU. Zone-redundant HA (see postgres_high_availability) requires General Purpose or Memory Optimized, e.g. GP_Standard_D2s_v3"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "postgres_high_availability" {
  description = "Enable zone-redundant high availability and geo-redundant backup. Requires a General Purpose/Memory Optimized SKU and a region with availability zones"
  type        = bool
  default     = false
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
  description = "Pre-shared key for agent registration (required in production)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "encryption_key" {
  description = "Base64-encoded 32-byte AES-256 key for credential encryption (required in production)"
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

# =========================================================================
# Networking / DNS
# =========================================================================
variable "public_domain" {
  description = "Public domain name for the application (used for CORS origins and DNS)"
  type        = string
  default     = "certmanager.example.com"
}

variable "allowed_db_ips" {
  description = "Additional public IPs allowed to reach PostgreSQL, e.g. operator workstations that run migrations"
  type        = list(string)
  default     = []
}
