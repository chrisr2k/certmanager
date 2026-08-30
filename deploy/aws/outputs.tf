output "alb_dns_name" {
  description = "ALB DNS name — access the API here"
  value       = aws_lb.main.dns_name
}

output "api_url" {
  description = "Full API URL"
  value       = "https://${var.domain_name}"
}

output "database_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.main.address
}

output "database_port" {
  description = "RDS PostgreSQL port"
  value       = aws_db_instance.main.port
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = aws_elasticache_cluster.main.cache_nodes[0].address
}

output "ecs_cluster" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecr_api_repo" {
  description = "ECR repository URL for API image"
  value       = aws_ecr_repository.api.repository_url
}

output "ecr_worker_repo" {
  description = "ECR repository URL for worker image"
  value       = aws_ecr_repository.worker.repository_url
}

output "push_commands" {
  description = "Docker push commands for initial deploy"
  value = <<-EOT
    # Build and push API image:
    docker build -f docker/Dockerfile.api -t certmanager-api .
    aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com
    docker tag certmanager-api:latest ${aws_ecr_repository.api.repository_url}:latest
    docker push ${aws_ecr_repository.api.repository_url}:latest

    # Build and push Worker image:
    docker build -f docker/Dockerfile.worker -t certmanager-worker .
    docker tag certmanager-worker:latest ${aws_ecr_repository.worker.repository_url}:latest
    docker push ${aws_ecr_repository.worker.repository_url}:latest
  EOT
}
