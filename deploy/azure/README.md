# CertManager on Azure — OpenTofu

Deploys via OpenTofu to Azure Container Apps (serverless).

## Architecture

```
Container Apps Ingress (HTTPS)
        ↓
Container App: API (x2-8)     ← auto-scales on HTTP
Container App: Worker (x2-8)   ← Celery workers
Container App: Scheduler (x1)  ← Celery beat
        ↓                    ↓
PostgreSQL Flexible Server   Azure Cache for Redis
(Zone-redundant in prod)     (encrypted)
```

## Prerequisites

- **OpenTofu** >= 1.6
- **Azure CLI** (`az login`)
- **Docker** for building images
- **Storage account** for remote state (or edit `provider.tf` for local)

```bash
# One-time: create state backend
az group create --name certmanager-tfstate --location eastus2
az storage account create \
  --name certmanagertfstate \
  --resource-group certmanager-tfstate \
  --sku Standard_LRS
az storage container create --name tfstate \
  --account-name certmanagertfstate
```

## Deploy

```bash
cd deploy/azure

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit with your values

# Deploy
tofu init
tofu plan
tofu apply

# Push images (from output)
tofu output push_commands
```

## Post-deploy

```bash
# Run migrations
tofu output run_migrations

# Get API URL
tofu output api_url
```

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `environment` | `production` | staging or production |
| `location` | `eastus2` | Azure region |
| `postgres_sku` | `B_Standard_B1ms` | PostgreSQL SKU |
| `db_password` | (required) | Database password |
| `secret_key` | (required) | JWT signing key |
| `redis_sku` | `Basic` | Redis tier |
| `api_replicas` | `2` | Min API containers |
| `container_cpu` | `0.5` | vCPU per container |

## Cost

| Resource | Spec | ~/mo |
|----------|------|------|
| Container Apps x5 | 0.5 vCPU / 1GB | $78 |
| PostgreSQL Flex | B1ms, 32GB | $25 |
| Redis Cache | Basic C1 | $20 |
| Container Registry | Basic | $5 |
| Log Analytics | PerGB | ~$5 |
| **Total** | | **~$133** |
