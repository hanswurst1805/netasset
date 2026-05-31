"""
NetAsset API – FastAPI Hauptanwendung
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from src.api import applications, assets, auth, conflicts, cve, discovery, gateways, networks, obashi, owners, processes, sbom, snapshots
from src.core.auth import hash_password
from src.core.config import settings
from src.core.database import async_session_factory
from src.models.auth import User  # noqa: F401 – sicherstellen dass Modell registriert

logger = logging.getLogger(__name__)


async def _ensure_admin():
    """Legt beim ersten Start einen Admin-User an, falls keiner existiert."""
    async with async_session_factory() as session:
        existing = (await session.execute(
            select(User).where(User.role == "admin")
        )).scalar_one_or_none()
        if not existing:
            admin = User(
                username="admin",
                password_hash=hash_password(settings.initial_admin_password),
                role="admin",
                allowed_tags=[],
            )
            session.add(admin)
            await session.commit()
            logger.info("Admin-User angelegt (Passwort aus INITIAL_ADMIN_PASSWORD)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _ensure_admin()
    yield


app = FastAPI(
    title="NetAsset API",
    description="CMDB & Security Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router,      prefix="/auth",            tags=["Auth"])
app.include_router(assets.router,    prefix="/api/v1/assets",   tags=["Assets"])
app.include_router(sbom.router,      prefix="/api/v1/sbom",     tags=["SBOM"])
app.include_router(cve.router,       prefix="/api/v1/cve",      tags=["CVE & Security"])
app.include_router(processes.router, prefix="/api/v1/processes", tags=["Business Processes"])
app.include_router(obashi.router,       prefix="/api/v1",                tags=["OBASHI"])
app.include_router(owners.router,       prefix="/api/v1/owners",         tags=["Owners"])
app.include_router(conflicts.router,    prefix="/api/v1/conflicts",      tags=["Conflicts"])
app.include_router(gateways.router,     prefix="/api/v1/gateways",       tags=["Network Gateways"])
app.include_router(networks.router,     prefix="/api/v1/networks",       tags=["IP Networks"])
app.include_router(snapshots.router,    prefix="/api/v1/snapshots",      tags=["Snapshots"])
app.include_router(applications.router, prefix="/api/v1/applications",   tags=["Applications"])
app.include_router(discovery.router, prefix="/api/v1/discovery", tags=["Discovery"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
