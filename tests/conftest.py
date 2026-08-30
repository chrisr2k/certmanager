"""Pytest fixtures for CertManager tests."""

import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from certmanager.api.app import create_app
from certmanager.core.config import reload_settings
from certmanager.core.models import Base


@pytest.fixture(autouse=True)
def test_settings():
    """Use test-specific settings."""
    import os

    os.environ["CERTMGMT_ENVIRONMENT"] = "development"
    os.environ["CERTMGMT_SECRET_KEY"] = "test-secret-key-123"
    os.environ["CERTMGMT_ENCRYPTION_KEY"] = ""
    os.environ["CERTMGMT_LOG_LEVEL"] = "ERROR"
    reload_settings()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing the API."""
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
