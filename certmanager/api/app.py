"""FastAPI application factory for CertManager.

Creates and configures the FastAPI app with:
- Middleware pipeline (correlation ID, audit logging, RBAC, rate limiting)
- Router mounting
- Lifespan events
- Exception handlers
- OpenAPI documentation
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from certmanager.api.middleware.audit import AuditLogMiddleware
from certmanager.api.middleware.correlation_id import CorrelationIDMiddleware
from certmanager.api.middleware.rate_limit import RateLimitMiddleware
from certmanager.api.middleware.rbac import RBACMiddleware
from certmanager.core.config import get_settings
from certmanager.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    CertManagerError,
    ConflictError,
    MFARequiredError,
    NotFoundError,
    TokenReuseError,
    ValidationError,
)
from certmanager.core.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    # Startup
    configure_logging()

    import structlog

    log = structlog.get_logger()
    log.info("certmanager starting", environment=get_settings().environment)

    yield

    # Shutdown
    from certmanager.core.database import get_engine

    try:
        engine = get_engine()
        await engine.dispose()
        log.info("database connections closed")
    except Exception:
        pass

    log.info("certmanager stopped")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Fully configured FastAPI app instance.
    """
    settings = get_settings()

    app = FastAPI(
        title="CertManager",
        description="Enterprise Certificate Management Platform — "
        "multi-datacenter, multi-cloud (AWS ACM, Azure Key Vault, AD CS)",
        version="0.1.0",
        docs_url="/api/docs" if settings.environment != "production" else None,
        redoc_url="/api/redoc" if settings.environment != "production" else None,
        openapi_url="/api/openapi.json" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    # --- Middleware stack ---
    # Starlette's add_middleware inserts at index 0, so the LAST added
    # middleware is the OUTERMOST. Desired nesting (outermost first):
    #   CORS -> CorrelationID -> RBAC -> Audit -> RateLimit
    # This ensures 401/403 responses carry CORS + correlation headers and
    # audit entries always have a correlation ID set.

    # Innermost: rate limiting
    app.add_middleware(RateLimitMiddleware)

    # Audit logging — log every authenticated API call
    app.add_middleware(AuditLogMiddleware)

    # RBAC — authorization checks (skips auth endpoints)
    app.add_middleware(RBACMiddleware)

    # Correlation ID — inject X-Correlation-ID into every request
    app.add_middleware(CorrelationIDMiddleware)

    # Outermost: CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Exception handlers ---
    @app.exception_handler(CertManagerError)
    async def certmanager_error_handler(request: Request, exc: CertManagerError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    @app.exception_handler(MFARequiredError)
    async def mfa_required_handler(request: Request, exc: MFARequiredError):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": type(exc).__name__,
                "message": str(exc),
                "mfa_required": True,
            },
        )

    @app.exception_handler(TokenReuseError)
    async def token_reuse_handler(request: Request, exc: TokenReuseError):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    @app.exception_handler(AuthorizationError)
    async def authorization_error_handler(request: Request, exc: AuthorizationError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    @app.exception_handler(NotFoundError)
    async def not_found_handler(request: Request, exc: NotFoundError):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    @app.exception_handler(ConflictError)
    async def conflict_handler(request: Request, exc: ConflictError):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    @app.exception_handler(ValidationError)
    async def validation_handler(request: Request, exc: ValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": type(exc).__name__, "message": str(exc)},
        )

    # --- Health check (no auth required) ---
    @app.get("/api/health")
    async def health_check():
        from certmanager.core.database import check_database_connection

        db_ok = await check_database_connection()
        body = {
            "status": "healthy" if db_ok else "degraded",
            "version": "0.1.0",
            "database": "connected" if db_ok else "disconnected",
        }
        # Return 503 when the database is unreachable so orchestrators
        # (ECS, K8s probes) can react instead of routing to a dead API.
        return JSONResponse(
            status_code=status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE,
            content=body,
        )

    # --- Mount routers ---
    from certmanager.api.routers import (
        agents,
        alerts,
        api_keys,
        audit_logs,
        auth,
        authorities,
        certificates,
        dashboard,
        datacenters,
        reports,
        scans,
        users,
    )

    app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
    app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
    app.include_router(certificates.router, prefix="/api/v1/certificates", tags=["Certificates"])
    app.include_router(authorities.router, prefix="/api/v1/authorities", tags=["CA Authorities"])
    app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scan Jobs"])
    app.include_router(agents.router, prefix="/api/v1/agents", tags=["Agents"])
    app.include_router(datacenters.router, prefix="/api/v1/datacenters", tags=["Datacenters"])
    app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
    app.include_router(audit_logs.router, prefix="/api/v1/audit-logs", tags=["Audit Logs"])
    app.include_router(api_keys.router, prefix="/api/v1/api-keys", tags=["API Keys"])

    return app


# Module-level app instance for uvicorn
app = create_app()
