# CertManager — Enterprise Certificate Management Platform

Multi-datacenter, multi-cloud certificate lifecycle management supporting AWS ACM, Azure Key Vault, and Active Directory Certificate Services.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   CENTRAL PLATFORM                            │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ React    │  │ FastAPI REST │  │ Celery Workers        │   │
│  │ Dashboard│  │ /api/v1/*    │  │ Scanner/Alerter/Reporter│   │
│  └──────────┘  └──────────────┘  └──────────────────────┘   │
│            PostgreSQL + TimescaleDB    Redis                 │
│         ┌──────────────────────────────────┐                 │
│         │ CA Connector Layer (ABC)          │                 │
│         │ AWS ACM | Azure Key Vault | AD CS │                 │
│         └──────────────────────────────────┘                 │
└──────────────────────────────────────────────────────────────┘
     │              │              │
 (boto3)    (azure-sdk)    (Agent mTLS)
     ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────────────┐
│ AWS ACM  │  │ Azure KV │  │ Datacenter Agent  │
│ multi-   │  │ multi-   │  │ AD CS + TLS scan  │
│ account  │  │ vault    │  │ Air-gap capable   │
└──────────┘  └──────────┘  └──────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+ (for frontend)
- Docker & docker-compose (for PostgreSQL + Redis)

### Development Setup

```bash
# Clone and enter project
cd certmanager

# Copy environment config
cp .env.example .env
# Edit .env with your settings

# Start infrastructure (PostgreSQL + Redis)
docker compose up -d postgres redis

# Install Python dependencies
pip install -e ".[dev]"

# Run database migrations
certmanager migrate

# Seed RBAC roles and admin user
certmanager seed

# Start the API server (development)
certmanager serve --reload

# In another terminal, start the frontend
cd frontend && npm install && npm run dev
```

### Docker Compose (all services)

```bash
docker compose up -d
```

Services:
- **API**: http://localhost:8000 (Swagger: http://localhost:8000/api/docs)
- **Frontend**: http://localhost:5173
- **MailHog**: http://localhost:8025 (email testing)

### Default Credentials

- **Email**: admin@certmanager.local
- **Password**: changeme123
- **Change immediately in production!**

## CLI Usage

```bash
# Server management
certmanager serve             # Start API server
certmanager migrate           # Run database migrations
certmanager seed              # Seed RBAC + admin user
certmanager createsuperuser   # Interactive superuser creation

# Certificate operations (API server required for full functionality)
certmanager certs list        # List certificates
certmanager certs show <id>   # Show certificate detail

# Agent initialization (for datacenter deployment)
certmanager agent init --url https://central.example.com --psk <key>
certmanager agent run          # Run agent polling loop
```

## API Overview

All endpoints are at `/api/v1/` with a standard JSON envelope:

| Endpoint | Description |
|----------|-------------|
| `POST /auth/login` | JWT login + MFA |
| `POST /auth/refresh` | Refresh access token |
| `GET /certificates` | Search certificates (full-text, filters, pagination) |
| `GET /certificates/stats` | Aggregated statistics |
| `GET /certificates/{id}` | Certificate detail with chain |
| `POST /certificates` | Manual certificate registration |
| `PATCH /certificates/{id}` | Update certificate metadata |
| `GET/POST /authorities` | CA management |
| `POST /authorities/{id}/scan` | Trigger CA discovery |
| `GET/POST /alerts/rules` | Alert rule CRUD |
| `GET /alerts/events` | Alert event history |
| `GET/POST /reports` | Compliance report generation |
| `GET/POST /scans` | Scan job management |
| `GET/POST /datacenters` | Datacenter topology |
| `GET /agents` | Agent management |
| `POST /agents/register` | Agent registration (PSK) |
| `POST /agents/{id}/heartbeat` | Agent heartbeat |
| `GET/POST /users` | User management (admin) |
| `GET /audit-logs` | Audit trail queries |
| `GET/POST /api-keys` | API key management |

## Project Structure

```
certmanager/
├── certmanager/          # Python package
│   ├── cli.py            # Typer CLI
│   ├── core/             # Config, models, security, crypto, database
│   ├── api/              # FastAPI app, routers, schemas, middleware
│   ├── services/         # Business logic layer
│   ├── connectors/       # CA connector implementations
│   ├── agent/            # Datacenter agent
│   ├── workers/          # Celery background workers
│   ├── notifications/    # Email, Slack, Teams backends
│   └── templates/        # Jinja2 report templates
├── frontend/             # React + TypeScript + Ant Design
│   └── src/
│       ├── pages/        # Dashboard, Certificates, Authorities, Alerts, etc.
│       ├── components/   # Layout, common, charts
│       ├── store/        # Auth context, Zustand stores
│       └── api/          # Axios client
├── alembic/              # Database migrations
├── docker/               # Dockerfiles
├── tests/                # Test suite
└── docker-compose.yml    # Full stack deployment
```

## Implementation Status

- [x] Phase 1: Foundation (project scaffold, 16 ORM models, FastAPI app, 10 API routers, auth, frontend shell, Docker)
- [x] Phase 2: Certificate Inventory (AWS ACM + Azure KV + AD CS connectors, DiscoveryService, CertificateService, Celery workers)
- [x] Phase 3: Multi-CA + Multi-DC (topology graph, CA health dashboard, expiry Gantt, multi-DC views)
- [x] Phase 4: Datacenter Agent (main loop, AD CS + TLS scanners, local SQLite buffer, air-gap export/import)
- [x] Phase 5: Alerting + CT Monitoring (5 condition types, 4 notification backends, CT log monitor, alert rule builder UI)
- [x] Phase 6: Compliance + CLI (3 Jinja2 report templates, PDF/CSV/JSON generation, audit log viewer, full CLI)
- [x] Phase 7: Hardening (test suite, Kubernetes manifests with HPA, ingress, kustomization)

**101 source files** across Python (backend), TypeScript/React (frontend), PowerShell (agent), and YAML (Kubernetes).

## License

MIT
