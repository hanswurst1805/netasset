"""pytest-Fixtures für NetAsset Tests.

Für Integration-Tests (test_identity, test_api) wird eine laufende PostgreSQL-Instanz
benötigt. Starten mit: docker-compose up -d db

Ohne PostgreSQL werden diese Tests automatisch übersprungen.
"""

import os

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://netasset:changeme@localhost:5432/netasset_test",
)

_pg_available = None


async def _check_pg() -> bool:
    global _pg_available
    if _pg_available is not None:
        return _pg_available
    try:
        engine = create_async_engine(TEST_DB_URL, echo=False)
        async with engine.connect():
            pass
        await engine.dispose()
        _pg_available = True
    except Exception:
        _pg_available = False
    return _pg_available


requires_db = pytest.mark.skipif(
    os.environ.get("SKIP_DB_TESTS", "0") == "1",
    reason="DB-Tests übersprungen (SKIP_DB_TESTS=1)",
)


@pytest_asyncio.fixture(scope="session")
async def engine():
    from src.models.all_models import Base

    if not await _check_pg():
        pytest.skip("PostgreSQL nicht erreichbar – DB-Tests übersprungen")

    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.execute(
            __import__("sqlalchemy").text("CREATE EXTENSION IF NOT EXISTS vector")
        )
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def session(engine):
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


@pytest_asyncio.fixture
async def client(session):
    from src.core.database import get_session
    from src.main import app

    app.dependency_overrides[get_session] = lambda: session

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
