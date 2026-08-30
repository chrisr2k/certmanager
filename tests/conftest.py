"""Pytest fixtures for CertManager tests.

The test database is in-memory SQLite via a StaticPool (so every session
shares one database). The API app's get_db dependency is overridden to use
the test session factory.
"""

from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from certmanager.api.app import create_app
from certmanager.core.config import reload_settings
from certmanager.core.models import Base, Datacenter

ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "test-admin-password-123"


@pytest.fixture(autouse=True)
def test_settings(monkeypatch):
    """Use test-specific settings with the CORRECT nested env names."""
    monkeypatch.setenv("CERTMGMT_ENVIRONMENT", "development")
    monkeypatch.setenv("CERTMGMT_SECURITY__SECRET_KEY", "test-secret-key-1234567890")
    monkeypatch.setenv("CERTMGMT_SECURITY__ENCRYPTION_KEY", "")
    monkeypatch.setenv("CERTMGMT_SECURITY__ACCESS_TOKEN_EXPIRE_MINUTES", "15")
    monkeypatch.setenv("CERTMGMT_SECURITY__REFRESH_TOKEN_EXPIRE_HOURS", "24")
    monkeypatch.setenv("CERTMGMT_REDIS__URL", "redis://localhost:6399/0")  # no Redis in tests
    monkeypatch.setenv("CERTMGMT_AGENT__PSK", "test-agent-psk")
    monkeypatch.setenv("CERTMGMT_LOG_LEVEL", "ERROR")
    monkeypatch.setenv("CERTMGMT_DATABASE__URL", "sqlite+aiosqlite://")
    reload_settings()


@pytest_asyncio.fixture
async def db_session(tmp_path) -> AsyncGenerator[AsyncSession, None]:
    """Create a file-backed SQLite database for testing.

    A real file (not :memory:) lets background tasks — audit-log writes,
    API-key lookups — open their own sessions against the same database.
    """
    import certmanager.core.database as database_module

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Point the GLOBAL session factory at the test database so middleware
    # that opens its own sessions (audit log writes, X-API-Key lookups)
    # uses the test DB instead of the configured Postgres URL.
    original_factory = database_module._async_session_factory
    original_engine = database_module._engine
    database_module._async_session_factory = async_session
    database_module._engine = engine

    try:
        async with async_session() as session:
            yield session
    finally:
        database_module._async_session_factory = original_factory
        database_module._engine = original_engine
        await engine.dispose()


@pytest_asyncio.fixture
async def seeded_db(db_session: AsyncSession) -> AsyncSession:
    """Seed RBAC roles, a superuser, and a datacenter for API tests."""
    from certmanager.core.seed import seed_all

    await seed_all(db_session, admin_email=ADMIN_EMAIL, admin_password=ADMIN_PASSWORD)
    db_session.add(Datacenter(name="Test DC", code="tstdc", location="Test", timezone="UTC"))
    await db_session.commit()
    return db_session


@pytest_asyncio.fixture
async def client(seeded_db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client for API tests, wired to the seeded test database."""
    from certmanager.api.dependencies import get_db

    app = create_app()

    async def _override_get_db():
        # Mirror the production get_db: commit on success, rollback on error
        try:
            yield seeded_db
            await seeded_db.commit()
        except Exception:
            await seeded_db.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient) -> str:
    """Log in as the seeded admin and return an access token."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def admin_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}
