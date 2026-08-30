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
(Zone-redundant opt-in)      (TLS required, key auth)
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

Then create a DNS record for `public_domain` (default
`certmanager.example.com`) pointing at `tofu output api_fqdn`.

## Post-deploy

```bash
# Run migrations and seed the database (also run after upgrades)
tofu output run_migrations

# Get API URL
tofu output api_url
```

## Production hardening checklist

- Set `postgres_high_availability = true` and use a General Purpose SKU
  (`GP_Standard_D2s_v3` or larger) in a region that supports zone redundancy.
  The burstable B-series SKUs do not support zone-redundant HA.
- In production the broad "allow all Azure services" database firewall rule
  is not created; access is restricted to the Container Apps environment's
  outbound IP. Add your own workstation IP to `allowed_db_ips` to run
  administrative queries.
- `secret_key`, `agent_psk` and `encryption_key` must be real values — the
  application refuses to start in production with defaults/empty values.

## Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `environment` | `production` | staging or production |
| `location` | `eastus2` | Azure region |
| `public_domain` | `certmanager.example.com` | Public domain (CORS origins) |
| `allowed_db_ips` | `[]` | Extra IPs allowed to reach PostgreSQL |
| `postgres_sku` | `B_Standard_B1ms` | PostgreSQL SKU (GP tier needed for HA) |
| `postgres_high_availability` | `false` | Zone-redundant HA + geo-redundant backup |
| `db_password` | (required) | Database password |
| `secret_key` | (required) | JWT signing key |
| `agent_psk` | `""` | Agent pre-shared key (required in production) |
| `encryption_key` | `""` | Base64 32-byte AES key (required in production) |
| `redis_sku` | `Basic` | Redis tier |
| `api_replicas` | `2` | Min API containers |
| `container_cpu` | `0.5` | vCPU per container |

## Cost

| Resource | Spec | ~/mo |
|----------|------|------|
| Container Apps x5 | 0.5 vCPU / 1GB | $78 |
| PostgreSQL Flex | GP_D2s_v3, 32GB | $110 |
| Redis Cache | Basic C1 | $20 |
| Container Registry | Basic | $5 |
| Log Analytics | PerGB | ~$5 |
| **Total** | | **~$218** |
