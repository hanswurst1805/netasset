"""pytest-Fixtures für NetAsset Tests.

Für Integration-Tests (test_identity, test_api) wird eine laufende PostgreSQL-Instanz
benötigt. Starten mit: docker-compose up -d db

Ohne PostgreSQL werden diese Tests automatisch übersprungen.
"""

import asyncio
import os

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://netasset:changeme@localhost:5432/netasset_test",
)

requires_db = pytest.mark.skipif(
    os.environ.get("SKIP_DB_TESTS", "0") == "1",
    reason="DB-Tests übersprungen (SKIP_DB_TESTS=1)",
)


async def _reset_schema(create: bool) -> None:
    """Schema komplett neu aufsetzen.

    DROP SCHEMA ... CASCADE statt Base.metadata.drop_all: das Modell hat
    FK-Zyklen (CircularDependencyError) und Reste aus abgebrochenen Läufen
    sollen auch weg.
    """
    from src.models.all_models import Base

    engine = create_async_engine(TEST_DB_URL, echo=False, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            if create:
                await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


@pytest.fixture(scope="session")
def _db_schema():
    """Einmal pro Testlauf: Schema anlegen, am Ende wieder entfernen.

    Synchron mit eigenem Event-Loop – so hängt nichts an einem Loop, der
    später von pytest-asyncio (function-scoped Loops) nicht mehr existiert.
    """
    try:
        asyncio.run(_reset_schema(create=True))
    except OSError as e:
        pytest.skip(f"PostgreSQL nicht erreichbar – DB-Tests übersprungen ({e})")
    yield
    asyncio.run(_reset_schema(create=False))


@pytest_asyncio.fixture
async def engine(_db_schema):
    # Pro Test eine eigene Engine ohne Pool: asyncpg-Verbindungen sind an den
    # Event-Loop gebunden, in dem sie geöffnet wurden.
    engine = create_async_engine(TEST_DB_URL, echo=False, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session(engine):
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


@pytest_asyncio.fixture
async def client(session):
    import uuid as _uuid

    from src.core.auth import AuthContext, get_current_user
    from src.core.database import get_session
    from src.main import app

    app.dependency_overrides[get_session] = lambda: session
    # Alle Endpunkte verlangen Auth – im Test als Admin ohne Tag-Filter.
    app.dependency_overrides[get_current_user] = lambda: AuthContext(
        user_id=_uuid.uuid4(),
        username="test-admin",
        role="admin",
        allowed_tags=[],
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
