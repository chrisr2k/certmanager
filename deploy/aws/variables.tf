# =========================================================================
# Required
# =========================================================================
variable "environment" {
  description = "Deployment environment (staging, production)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "Environment must be staging or production"
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# =========================================================================
# Database
# =========================================================================
variable "db_instance_class" {
  description = "RDS PostgreSQL instance class"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "RDS storage in GB"
  type        = number
  default     = 20
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "certmanager"
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "certmanager"
}

variable "db_password" {
  description = "Database master password (set via tfvars or env var TF_VAR_db_password)"
  type        = string
  sensitive   = true
}

# =========================================================================
# Redis
# =========================================================================
variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t4g.micro"
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

variable "encryption_key" {
  description = "Base64-encoded 32-byte AES-256 key for credential encryption"
  type        = string
  sensitive   = true
  default     = ""
}

# =========================================================================
# Compute
# =========================================================================
variable "api_replicas" {
  description = "Number of API task replicas"
  type        = number
  default     = 2
}

variable "worker_replicas" {
  description = "Number of worker task replicas"
  type        = number
  default     = 2
}

variable "container_cpu" {
  description = "CPU units for Fargate tasks"
  type        = number
  default     = 512
}

variable "container_memory" {
  description = "Memory for Fargate tasks in MiB"
  type        = number
  default     = 1024
}

# =========================================================================
# Networking
# =========================================================================
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "certmanager.example.com"
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS (leave empty for HTTP only)"
  type        = string
  default     = ""
}
