# CertManager on Kubernetes

Kustomize-based manifests for running CertManager on Kubernetes:
API + Celery worker + Celery beat + nginx frontend, with an nginx-ingress
front door and HPA autoscaling.

## Layout

```
deploy/k8s/
├── base/                  # base resources (applies to any environment)
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── configmap.yaml     # non-sensitive config (env vars)
│   ├── secret.yaml        # EDIT PLACEHOLDERS — sensitive config
│   ├── api-deployment.yaml
│   ├── worker-deployment.yaml
│   ├── beat-deployment.yaml
│   ├── frontend-deployment.yaml
│   ├── api-service.yaml
│   ├── frontend-service.yaml
│   ├── ingress.yaml
│   └── hpa.yaml
└── overlays/
    └── production/        # replicas + env overrides
```

## Environment variable contract

The application reads pydantic-settings nested env vars with the `__`
delimiter under the `CERTMGMT_` prefix. Always use the nested form:

| Purpose | Variable |
|---------|----------|
| Environment | `CERTMGMT_ENVIRONMENT` |
| Async DB URL | `CERTMGMT_DATABASE__URL` |
| Sync DB URL (Alembic) | `CERTMGMT_DATABASE__URL_SYNC` |
| Redis | `CERTMGMT_REDIS__URL` |
| JWT secret | `CERTMGMT_SECURITY__SECRET_KEY` |
| Encryption key | `CERTMGMT_SECURITY__ENCRYPTION_KEY` |
| CORS (JSON list!) | `CERTMGMT_CORS__ORIGINS` |
| Agent PSK | `CERTMGMT_AGENT__PSK` |
| SMTP | `CERTMGMT_SMTP__HOST`, `__PORT`, `__USER`, `__PASSWORD`, `__FROM_ADDRESS`, `__USE_TLS` |

Flat names like `CERTMGMT_DATABASE_URL` are silently ignored.

## Prerequisites

- `kubectl` >= 1.27 targeting a cluster
- nginx ingress controller installed
  (`kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.0/deploy/static/provider/cloud/deploy.yaml`)
- metrics-server for the HPAs (usually bundled with managed clusters)
- Container images pushed to a registry your cluster can pull from:
  - `certmanager-api:latest` (docker/Dockerfile.api)
  - `certmanager-worker:latest` (docker/Dockerfile.worker)
  - `certmanager-frontend:latest` (docker/Dockerfile.frontend — nginx stage
    serving the built static assets on port 80)
  Override the image names in the deployment files if you use a private
  registry (add an `imagePullSecrets` entry if needed).

## Deploy

1. **Edit the Secret** (`base/secret.yaml`): replace every `CHANGE-ME` value.
   Consider sealing it (kubeseal) or switching to ExternalSecret before
   committing real values to git.
2. **Edit the domain**: replace `certmanager.example.com` in
   `base/configmap.yaml` (CORS origins), `base/ingress.yaml` and
   `overlays/production/env-patch.yaml` with your real hostname.
3. **TLS**: create the TLS secret referenced by the ingress:
   ```bash
   kubectl -n certmanager create secret tls certmanager-tls \
     --cert=tls.crt --key=tls.key
   ```
   (or let cert-manager issue it for `certmanager.example.com`).
4. **Apply** (staging/quick start: base only; production: overlay):
   ```bash
   # base
   kubectl apply -k deploy/k8s/base
   # production (replicas + production env overrides)
   kubectl apply -k deploy/k8s/overlays/production
   ```
5. **Migrate + seed the database** after the first deploy and after every
   upgrade:
   ```bash
   kubectl -n certmanager run migrate --rm -it --restart=Never \
     --image=certmanager-api:latest \
     --env-from=configmap/certmanager-config \
     --env-from=secret/certmanager-secrets \
     --command -- python -m certmanager.cli migrate
   kubectl -n certmanager run seed --rm -it --restart=Never \
     --image=certmanager-api:latest \
     --env-from=configmap/certmanager-config \
     --env-from=secret/certmanager-secrets \
     --command -- python -m certmanager.cli seed
   ```
6. **Verify**:
   ```bash
   kubectl -n certmanager get pods,svc,ingress,hpa
   curl -k https://certmanager.example.com/api/health
   ```

## Notes

- The API liveness probe uses a Python `urllib` one-liner because the
  `python:3.12-slim` base image has no curl.
- The HPA floor/ceiling: API 2-10, worker 1-8 (CPU utilization 70%).
- Route `frontend` and `api` through the same host (`/api` prefix is routed
  to the API service) so the CORS origin list stays a single host.
