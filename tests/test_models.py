"""Tests for SQLAlchemy ORM models — create/query operations."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import select

from certmanager.core.models import Base, User, Role, Permission, Datacenter


@pytest_asyncio.fixture
async def db_session():
    """In-memory SQLite database for model tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
    await engine.dispose()


class TestUserModel:
    async def test_create_user(self, db_session: AsyncSession):
        user = User(
            email="test@example.com",
            password_hash="hashed_value",
            full_name="Test User",
        )
        db_session.add(user)
        await db_session.flush()

        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_superuser is False

    async def test_query_user_by_email(self, db_session: AsyncSession):
        user = User(email="query@test.com", password_hash="hash")
        db_session.add(user)
        await db_session.flush()

        result = await db_session.execute(
            select(User).where(User.email == "query@test.com")
        )
        found = result.scalar_one_or_none()
        assert found is not None
        assert found.email == "query@test.com"

    async def test_user_roles_relationship(self, db_session: AsyncSession):
        user = User(email="roleuser@test.com", password_hash="hash")
        role = Role(name="test-role", description="Test role")
        db_session.add_all([user, role])
        await db_session.flush()

        from certmanager.core.models import UserRole
        db_session.add(UserRole(user_id=user.id, role_id=role.id))
        await db_session.flush()

        # Query with relationship loaded
        result = await db_session.execute(
            select(User).where(User.id == user.id)
        )
        found = result.scalar_one()
        assert found is not None


class TestRoleModel:
    async def test_create_role(self, db_session: AsyncSession):
        role = Role(name="admin", description="Administrator")
        db_session.add(role)
        await db_session.flush()
        assert role.name == "admin"

    async def test_duplicate_role_name_raises(self, db_session: AsyncSession):
        db_session.add(Role(name="unique-role"))
        await db_session.flush()

        db_session.add(Role(name="unique-role"))
        with pytest.raises(Exception):  # UNIQUE constraint
            await db_session.flush()


class TestDatacenterModel:
    async def test_create_datacenter(self, db_session: AsyncSession):
        dc = Datacenter(name="DC1", code="dc1", location="New York", timezone="America/New_York")
        db_session.add(dc)
        await db_session.flush()

        assert dc.name == "DC1"
        assert dc.code == "dc1"
        assert dc.is_active is True

    async def test_metadata_jsonb(self, db_session: AsyncSession):
        dc = Datacenter(
            name="DC2",
            code="dc2",
            metadata_={"region": "us-east", "tier": "prod"},
        )
        db_session.add(dc)
        await db_session.flush()

        result = await db_session.execute(select(Datacenter).where(Datacenter.code == "dc2"))
        found = result.scalar_one()
        assert found.metadata_["region"] == "us-east"
        assert found.metadata_["tier"] == "prod"
