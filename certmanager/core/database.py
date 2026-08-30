"""Async database engine and session management using SQLAlchemy 2.0."""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy import NullPool, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from certmanager.core.config import DatabaseSettings, get_settings


def create_engine(database_settings: DatabaseSettings | None = None):
    """Create an async SQLAlchemy engine."""
    if database_settings is None:
        database_settings = get_settings().database

    return create_async_engine(
        database_settings.url,
        pool_size=database_settings.pool_size,
        max_overflow=database_settings.pool_overflow,
        pool_timeout=database_settings.pool_timeout,
        echo=False,
        pool_pre_ping=True,
    )


# Module-level engine — created on first use
_engine = None
_async_session_factory = None


def get_engine():
    """Get or create the async engine singleton."""
    global _engine, _async_session_factory
    if _engine is None:
        _engine = create_engine()
        _async_session_factory = async_sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )
    return _engine


def get_session_factory() -> async_sessionmaker:
    """Get or create the async session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        get_engine()  # Initializes both
    return _async_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async database session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_database_connection() -> bool:
    """Verify the database is reachable. Returns True if healthy."""
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
