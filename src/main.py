"""
NetAsset API – FastAPI Hauptanwendung
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from src.api import alerts, app_settings, applications, assets, auth, basis, cards, conflicts, cve, discovery, export, gateways, networks, owners, processes, reports, reporting, sbom, services_view, sessions, snapshots
from src.core.auth import hash_password
from src.core.config import settings
from src.core.database import async_session_factory
from src.models.auth import User  # noqa: F401 – sicherstellen dass Modell registriert

logger = logging.getLogger(__name__)


async def _ensure_admin():
    """Legt beim ersten Start einen Admin-User an, falls keiner existiert."""
    async with async_session_factory() as session:
        existing = (await session.execute(
            select(User).where(User.role == "admin").limit(1)
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
    title="DRUCKER API",
    description="Infrastructure Intelligence Platform",
    version="1.0.0",
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
app.include_router(basis.router,        prefix="/api/v1",                tags=["BASIS"])
app.include_router(owners.router,       prefix="/api/v1/owners",         tags=["Owners"])
app.include_router(conflicts.router,    prefix="/api/v1/conflicts",      tags=["Conflicts"])
app.include_router(gateways.router,     prefix="/api/v1/gateways",       tags=["Network Gateways"])
app.include_router(networks.router,     prefix="/api/v1/networks",       tags=["IP Networks"])
app.include_router(snapshots.router,    prefix="/api/v1/snapshots",      tags=["Snapshots"])
app.include_router(reports.router,      prefix="/api/v1/reports",        tags=["Reports"])
app.include_router(reporting.router,    prefix="/api/v1/reporting",      tags=["Reporting"])
app.include_router(export.router,       prefix="/api/v1/export",         tags=["Betriebsleitfaden Export"])
app.include_router(cards.router,        prefix="/api/v1/cards",          tags=["Cards / RAG Export"])
app.include_router(applications.router, prefix="/api/v1/applications",   tags=["Applications"])
app.include_router(discovery.router, prefix="/api/v1/discovery", tags=["Discovery"])
app.include_router(app_settings.router, prefix="/api/v1/settings", tags=["Settings"])
app.include_router(sessions.router,     prefix="/api/v1/sessions",       tags=["Audit Sessions"])
app.include_router(services_view.router, prefix="/api/v1/services",       tags=["Services / Container"])
app.include_router(alerts.router,        prefix="/api/v1/alerts",         tags=["Alarme"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
