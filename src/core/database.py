"""DB-Engine und Session-Factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import settings

_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            # asyncpg im UTC-Modus: akzeptiert naive + aware Datetimes konsistent
            connect_args={"server_settings": {"timezone": "UTC"}},
        )
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(_get_engine(), expire_on_commit=False)
    return _session_factory


# Öffentliches Interface — werden von Modulen direkt importiert
@property  # type: ignore[misc]
def engine():
    return _get_engine()


def get_async_session_factory() -> async_sessionmaker:
    return _get_session_factory()


# Compat: direkt importierbares Objekt für Scripts
class _LazySessionFactory:
    """Proxy, der erst beim ersten Aufruf die echte Factory erstellt."""

    def __call__(self) -> AsyncSession:  # type: ignore[override]
        return _get_session_factory()()

    def __getattr__(self, name: str):
        return getattr(_get_session_factory(), name)


async_session_factory = _LazySessionFactory()  # type: ignore[assignment]


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
