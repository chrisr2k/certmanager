# CertManager on AWS — OpenTofu

Deploys the full stack via OpenTofu (open-source Terraform).

## Architecture

```
ALB (HTTPS) → ECS Fargate API (x2)
               ECS Fargate Worker (x2)
               ECS Fargate Scheduler (x1)
                    ↓              ↓
            RDS PostgreSQL    ElastiCache Redis
            (Multi-AZ prod)   (encrypted)
```

## Prerequisites

- **OpenTofu** >= 1.6 (`tofu --version`)
- **AWS CLI** configured (`aws configure`)
- **Docker** for building images
- **S3 bucket + DynamoDB table** for remote state (or edit `provider.tf` to use local backend)

```bash
# One-time: create state backend
aws s3 mb s3://certmanager-tfstate --region us-east-1
aws dynamodb create-table \
  --table-name certmanager-tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

## Deploy

```bash
cd deploy/aws

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Deploy
tofu init
tofu plan
tofu apply

# Get push commands for Docker images
tofu output push_commands
```

Run the output push commands to build and upload your Docker images.

## Post-deploy

```bash
# Run database migrations
TASK_ARN=$(aws ecs list-tasks \
  --cluster certmanager-production \
  --service certmanager-api-production \
  --query 'taskArns[0]' --output text)

aws ecs execute-command \
  --cluster certmanager-production \
  --task $TASK_ARN \
  --container api \
  --command "python -m alembic -c alembic/alembic.ini upgrade head && python -m certmanager.cli seed"
```

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `environment` | `production` | staging or production |
| `aws_region` | `us-east-1` | AWS region |
| `db_instance_class` | `db.t4g.medium` | RDS instance size |
| `db_password` | (required) | Database password |
| `secret_key` | (required) | JWT signing key (64 chars) |
| `agent_psk` | (generated) | Agent pre-shared key |
| `domain_name` | `certmanager.example.com` | Public domain |
| `certificate_arn` | `""` | ACM cert ARN for HTTPS |

## Cost

| Resource | Spec | ~/mo |
|----------|------|------|
| ECS Fargate x5 | 512 CPU / 1GB | $78 |
| RDS t4g.medium | 20GB | $50 |
| ElastiCache t4g.micro | - | $12 |
| ALB | - | $20 |
| **Total** | | **~$160** |

(Production with Multi-AZ RDS: ~$250/mo)
