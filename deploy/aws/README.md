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

### HTTPS

Set `certificate_arn` to an ACM certificate ARN for `domain_name` to enable
the HTTPS listener and HTTP-to-HTTPS redirect. When left empty the ALB only
listens on port 80 and forwards directly to the API (useful for staging
behind a CDN or a VPN).

## Post-deploy — database migrations

A dedicated one-shot Fargate task definition (`certmanager-migrate-...`) runs
`python -m certmanager.cli migrate && python -m certmanager.cli seed` against
the same environment. Run it after every image deploy that ships schema
changes:

```bash
tofu output run_migrations
# or equivalently:
aws ecs run-task \
  --cluster certmanager-production \
  --task-definition certmanager-migrate-production \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-zzz],assignPublicIp=ENABLED}"
```

Check the task's logs in the `/ecs/certmanager-migrate-<environment>` log
group. The task exits 0 on success and keeps the log group history.

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `environment` | `production` | staging or production |
| `aws_region` | `us-east-1` | AWS region |
| `db_instance_class` | `db.t4g.medium` | RDS instance size |
| `db_password` | (required) | Database password |
| `secret_key` | (required) | JWT signing key (64 chars) |
| `agent_psk` | (generated) | Agent pre-shared key |
| `encryption_key` | (generated) | Base64 32-byte AES key for credential encryption; auto-generated in Secrets Manager when empty |
| `domain_name` | `certmanager.example.com` | Public domain (CORS origins) |
| `certificate_arn` | `""` | ACM cert ARN for HTTPS; listener is skipped when empty |

The ECS tasks assume an IAM task role with `sts:AssumeRole` and `acm:*`
permissions so the AWS ACM connector can issue certificates.

## Cost

| Resource | Spec | ~/mo |
|----------|------|------|
| ECS Fargate x5 | 512 CPU / 1GB | $78 |
| RDS t4g.medium | 20GB | $50 |
| ElastiCache t4g.micro | - | $12 |
| ALB | - | $20 |
| **Total** | | **~$160** |

(Production with Multi-AZ RDS: ~$250/mo)
