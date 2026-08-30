# =========================================================================
# CertManager — AWS Deployment (OpenTofu)
# =========================================================================
# Deploys: VPC, RDS PostgreSQL, ElastiCache Redis, ECR repos,
#          ECS Fargate (API + Worker + Scheduler), ALB
#
# Usage:
#   cp terraform.tfvars.example terraform.tfvars   # edit values
#   tofu init
#   tofu plan
#   tofu apply
# =========================================================================

# --- Secrets Manager ---
resource "aws_secretsmanager_secret" "db_password" {
  name        = "certmanager/${var.environment}/db-password"
  description = "CertManager RDS master password"
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.db_password
}

resource "aws_secretsmanager_secret" "secret_key" {
  name        = "certmanager/${var.environment}/secret-key"
  description = "CertManager JWT signing secret"
}

resource "aws_secretsmanager_secret_version" "secret_key" {
  secret_id     = aws_secretsmanager_secret.secret_key.id
  secret_string = var.secret_key
}

resource "random_bytes" "encryption_key" {
  length = 32
}

resource "aws_secretsmanager_secret" "encryption_key" {
  name        = "certmanager/${var.environment}/encryption-key"
  description = "Base64-encoded 32-byte AES-256 key for credential encryption"
}

resource "aws_secretsmanager_secret_version" "encryption_key" {
  secret_id     = aws_secretsmanager_secret.encryption_key.id
  secret_string = var.encryption_key != "" ? var.encryption_key : random_bytes.encryption_key.base64
}

resource "random_password" "agent_psk" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "agent_psk" {
  name        = "certmanager/${var.environment}/agent-psk"
  description = "CertManager agent pre-shared key"
}

resource "aws_secretsmanager_secret_version" "agent_psk" {
  secret_id     = aws_secretsmanager_secret.agent_psk.id
  secret_string = var.agent_psk != "" ? var.agent_psk : random_password.agent_psk.result
}

# =========================================================================
# Networking
# =========================================================================
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "certmanager-${var.environment}" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "certmanager-${var.environment}-public-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "certmanager-${var.environment}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "certmanager-${var.environment}-public" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# =========================================================================
# Security Groups
# =========================================================================
resource "aws_security_group" "alb" {
  name        = "certmanager-alb-${var.environment}"
  description = "ALB security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  name        = "certmanager-ecs-${var.environment}"
  description = "ECS Fargate tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "certmanager-db-${var.environment}"
  description = "RDS PostgreSQL"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
}

resource "aws_security_group" "redis" {
  name        = "certmanager-redis-${var.environment}"
  description = "ElastiCache Redis"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }
}

# =========================================================================
# RDS PostgreSQL
# =========================================================================
resource "aws_db_subnet_group" "main" {
  name       = "certmanager-${var.environment}"
  subnet_ids = aws_subnet.public[*].id

  tags = { Name = "certmanager-${var.environment}" }
}

resource "aws_db_instance" "main" {
  identifier = "certmanager-${var.environment}"

  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  publicly_accessible    = false

  multi_az                = var.environment == "production"
  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  deletion_protection = var.environment == "production"
  skip_final_snapshot = var.environment != "production"

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = { Name = "certmanager-${var.environment}" }
}

# =========================================================================
# ElastiCache Redis
# =========================================================================
resource "aws_elasticache_subnet_group" "main" {
  name       = "certmanager-${var.environment}"
  subnet_ids = aws_subnet.public[*].id
}

resource "aws_elasticache_cluster" "main" {
  cluster_id           = "certmanager-${var.environment}"
  engine               = "redis"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]
  port               = 6379

  tags = { Name = "certmanager-${var.environment}" }
}

# =========================================================================
# ECR Repositories
# =========================================================================
resource "aws_ecr_repository" "api" {
  name                 = "certmanager-api"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "worker" {
  name                 = "certmanager-worker"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 20
      }
      action = { type = "expire" }
    }]
  })
}

# =========================================================================
# ECS Fargate — Cluster + Services
# =========================================================================
resource "aws_ecs_cluster" "main" {
  name = "certmanager-${var.environment}"
}

# --- IAM Roles ---
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_execution" {
  name               = "certmanager-ecs-execution-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_task_secrets" {
  name = "certmanager-secrets-${var.environment}"
  role = aws_iam_role.ecs_task_execution.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = [
        aws_secretsmanager_secret.db_password.arn,
        aws_secretsmanager_secret.secret_key.arn,
        aws_secretsmanager_secret.encryption_key.arn,
        aws_secretsmanager_secret.agent_psk.arn,
      ]
    }]
  })
}

# Task role assumed by the containers themselves, used by the AWS ACM
# connector (STS role assumption + ACM certificate operations).
resource "aws_iam_role" "ecs_task" {
  name               = "certmanager-ecs-task-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "ecs_task_acm" {
  name = "certmanager-acm-connector-${var.environment}"
  role = aws_iam_role.ecs_task.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:AssumeRole", "acm:*"]
      Resource = "*"
    }]
  })
}

# --- CloudWatch Log Groups ---
resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/certmanager-api-${var.environment}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/certmanager-worker-${var.environment}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "scheduler" {
  name              = "/ecs/certmanager-scheduler-${var.environment}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "migrate" {
  name              = "/ecs/certmanager-migrate-${var.environment}"
  retention_in_days = 30
}

# --- Environment variables ---
# The application reads pydantic-settings nested env vars with the "__"
# delimiter: CERTMGMT_DATABASE__URL, CERTMGMT_SECURITY__SECRET_KEY, etc.
# Flat names (CERTMGMT_DATABASE_URL) are silently ignored by the backend.
locals {
  database_url      = "postgresql+asyncpg://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:5432/${var.db_name}"
  database_url_sync = "postgresql+psycopg2://${var.db_username}:${var.db_password}@${aws_db_instance.main.address}:5432/${var.db_name}"
  redis_url         = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0"

  api_env = [
    { name = "CERTMGMT_ENVIRONMENT", value = var.environment },
    { name = "CERTMGMT_LOG_FORMAT", value = "json" },
    { name = "CERTMGMT_API_HOST", value = "0.0.0.0" },
    { name = "CERTMGMT_API_PORT", value = "8000" },
    { name = "CERTMGMT_CORS__ORIGINS", value = jsonencode(["https://${var.domain_name}"]) },
    { name = "CERTMGMT_DATABASE__URL", value = local.database_url },
    { name = "CERTMGMT_DATABASE__URL_SYNC", value = local.database_url_sync },
    { name = "CERTMGMT_REDIS__URL", value = local.redis_url },
  ]

  api_secrets = [
    { name = "CERTMGMT_SECURITY__SECRET_KEY", valueFrom = aws_secretsmanager_secret.secret_key.arn },
    { name = "CERTMGMT_SECURITY__ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.encryption_key.arn },
    { name = "CERTMGMT_AGENT__PSK", valueFrom = aws_secretsmanager_secret.agent_psk.arn },
  ]

  common_env = [
    { name = "CERTMGMT_ENVIRONMENT", value = var.environment },
    { name = "CERTMGMT_LOG_FORMAT", value = "json" },
    { name = "CERTMGMT_DATABASE__URL", value = local.database_url },
    { name = "CERTMGMT_DATABASE__URL_SYNC", value = local.database_url_sync },
    { name = "CERTMGMT_REDIS__URL", value = local.redis_url },
  ]

  common_secrets = [
    { name = "CERTMGMT_SECURITY__SECRET_KEY", valueFrom = aws_secretsmanager_secret.secret_key.arn },
  ]
}

# --- API Task Definition ---
resource "aws_ecs_task_definition" "api" {
  family                   = "certmanager-api-${var.environment}"
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name         = "api"
    image        = "${aws_ecr_repository.api.repository_url}:latest"
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    environment  = local.api_env
    secrets      = local.api_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.api.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "api"
      }
    }
    # python:3.12-slim has no curl, so use urllib for the container healthcheck
    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health', timeout=5).status==200 else 1)\""]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "certmanager-worker-${var.environment}"
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name        = "worker"
    image       = "${aws_ecr_repository.worker.repository_url}:latest"
    command     = ["celery", "-A", "certmanager.workers.celery_app", "worker", "--loglevel=info", "--concurrency=4"]
    environment = local.common_env
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.worker.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "worker"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "scheduler" {
  family                   = "certmanager-scheduler-${var.environment}"
  cpu                      = 256
  memory                   = 512
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name        = "scheduler"
    image       = "${aws_ecr_repository.worker.repository_url}:latest"
    command     = ["celery", "-A", "certmanager.workers.celery_app", "beat", "--loglevel=info"]
    environment = local.common_env
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.scheduler.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "scheduler"
      }
    }
  }])
}

# One-shot migration/seed task. Run it manually after every deploy:
#   tofu output run_migrations
resource "aws_ecs_task_definition" "migrate" {
  family                   = "certmanager-migrate-${var.environment}"
  cpu                      = 512
  memory                   = 1024
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name        = "migrate"
    image       = "${aws_ecr_repository.api.repository_url}:latest"
    command     = ["sh", "-c", "python -m certmanager.cli migrate && python -m certmanager.cli seed"]
    environment = local.common_env
    secrets     = local.common_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.migrate.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "migrate"
      }
    }
  }])
}

# --- ECS Services ---
resource "aws_ecs_service" "api" {
  name            = "certmanager-api-${var.environment}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_replicas
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_ecs_service" "worker" {
  name            = "certmanager-worker-${var.environment}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_replicas
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }
}

resource "aws_ecs_service" "scheduler" {
  name            = "certmanager-scheduler-${var.environment}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.scheduler.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }
}

# =========================================================================
# Application Load Balancer
# =========================================================================
resource "aws_lb" "main" {
  name               = "certmanager-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "api" {
  name        = "certmanager-api-${var.environment}"
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path                = "/api/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  # With a TLS certificate: redirect all HTTP to HTTPS.
  dynamic "default_action" {
    for_each = var.certificate_arn != "" ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  # Without a TLS certificate: serve the API directly over HTTP.
  dynamic "default_action" {
    for_each = var.certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.api.arn
    }
  }
}

# The HTTPS listener is only created when a certificate ARN is provided —
# an HTTPS listener with no certificate fails to apply.
resource "aws_lb_listener" "https" {
  count             = var.certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
