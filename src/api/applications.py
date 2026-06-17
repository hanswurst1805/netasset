"""Application CRUD – BASIS A-Layer (fachliche Anwendungen)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.components import component_condition
from src.core.database import get_session
from src.models.all_models import (
    Application, ApplicationComponent, Asset, BusinessProcess, CVEImpact, SBOMEntry,
)

router = APIRouter()

APP_TYPES = ["web", "api", "batch", "integration", "desktop", "mobile", "service", "other"]
MATCH_KINDS = ["name", "prefix", "purl", "cpe"]

# Infrastruktur-/System-Software, die beim Auto-Discover als Komponente
# vorgeschlagen wird (zusätzlich zu allem mit bekannten CVEs).
RELEVANT_PKG_NAMES = {
    "nginx", "apache2", "httpd", "lighttpd",
    "postgresql", "mysql", "mariadb", "redis", "mongodb",
    "openssh-server", "openssl", "libssl",
    "docker", "containerd", "podman",
    "python3", "python", "java", "openjdk", "nodejs", "node", "ruby",
    "php", "php-fpm", "haproxy", "traefik", "envoy", "tomcat",
}


class ApplicationCreate(BaseModel):
    name: str
    description: Optional[str] = None
    app_type: Optional[str] = "web"
    version: Optional[str] = None
    url: Optional[str] = None
    process_id: uuid.UUID
    owner_id: Optional[uuid.UUID] = None
    criticality: Optional[int] = None
    asset_ids: Optional[list[str]] = None


class ApplicationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    app_type: Optional[str] = None
    version: Optional[str] = None
    url: Optional[str] = None
    owner_id: Optional[uuid.UUID] = None
    criticality: Optional[int] = None
    asset_ids: Optional[list[str]] = None
    is_active: Optional[bool] = None


class ApplicationOut(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    app_type: Optional[str]
    version: Optional[str]
    url: Optional[str]
    process_id: uuid.UUID
    owner_id: Optional[uuid.UUID]
    criticality: Optional[int]
    asset_ids: Optional[list]
    is_active: bool
    model_config = {"from_attributes": True}


@router.get("", response_model=list[ApplicationOut])
async def list_applications(
    process_id: Optional[uuid.UUID] = None,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    stmt = select(Application).where(Application.is_active == True)
    if process_id:
        stmt = stmt.where(Application.process_id == process_id)
    result = await session.execute(stmt.order_by(Application.name))
    return result.scalars().all()


@router.post("", response_model=ApplicationOut, status_code=201)
async def create_application(
    body: ApplicationCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    process = await session.get(BusinessProcess, body.process_id)
    if not process:
        raise HTTPException(404, f"Prozess {body.process_id} nicht gefunden")

    app = Application(**body.model_dump(exclude_none=True))
    session.add(app)
    await session.flush()
    await session.refresh(app)
    return app


@router.put("/{app_id}", response_model=ApplicationOut)
async def update_application(
    app_id: uuid.UUID,
    body: ApplicationUpdate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    app = await session.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Anwendung nicht gefunden")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(app, k, v)
    await session.flush()
    await session.refresh(app)
    return app


@router.delete("/{app_id}", status_code=204)
async def delete_application(
    app_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    app = await session.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Anwendung nicht gefunden")
    app.is_active = False
    await session.flush()


# ===========================================================================
# Application Components (A↔S Zwischenschicht)
# ===========================================================================

class ComponentCreate(BaseModel):
    name: str
    match_kind: str = "name"
    match_value: str
    asset_id: Optional[uuid.UUID] = None


class ComponentInstance(BaseModel):
    asset_id: str
    hostname: Optional[str]
    pkg_name: str
    pkg_version: str
    cpe: Optional[str] = None


class ComponentSystem(BaseModel):
    asset_id: str
    hostname: Optional[str]


class ComponentOut(BaseModel):
    id: uuid.UUID
    application_id: uuid.UUID
    name: str
    match_kind: str
    match_value: str
    asset_id: Optional[uuid.UUID]
    origin: str
    confirmed: bool
    created_at: datetime
    # aufgelöst gegen die aktuelle SBOM:
    instances: list[ComponentInstance] = []
    systems: list[ComponentSystem] = []
    cve_count: int = 0
    max_risk_score: Optional[float] = None
    max_risk_level: Optional[str] = None
    model_config = {"from_attributes": True}


async def _resolve_component(comp: ApplicationComponent, session: AsyncSession) -> ComponentOut:
    """Löst eine Komponenten-Regel gegen die SBOM auf: Instanzen, Systeme, CVEs."""
    out = ComponentOut.model_validate(comp)

    stmt = (
        select(SBOMEntry, Asset.hostname)
        .join(Asset, Asset.id == SBOMEntry.asset_id)
        .where(
            component_condition(comp.match_kind, comp.match_value),
            Asset.is_active == True,
            Asset.is_archived == False,
        )
    )
    if comp.asset_id:
        stmt = stmt.where(SBOMEntry.asset_id == comp.asset_id)

    rows = (await session.execute(stmt)).all()

    systems: dict[str, Optional[str]] = {}
    pkg_names: set[str] = set()
    for entry, hostname in rows:
        out.instances.append(ComponentInstance(
            asset_id=str(entry.asset_id), hostname=hostname,
            pkg_name=entry.pkg_name, pkg_version=entry.pkg_version, cpe=entry.cpe,
        ))
        systems[str(entry.asset_id)] = hostname
        pkg_names.add(entry.pkg_name.lower())

    out.systems = [ComponentSystem(asset_id=a, hostname=h) for a, h in systems.items()]

    # CVEs über CVEImpact (asset_id + affected_pkg) ermitteln
    if systems and pkg_names:
        import uuid as _uuid
        cve_stmt = select(CVEImpact).where(
            CVEImpact.asset_id.in_([_uuid.UUID(a) for a in systems]),
            func.lower(CVEImpact.affected_pkg).in_(pkg_names),
        )
        impacts = (await session.execute(cve_stmt)).scalars().all()
        out.cve_count = len({i.cve_id for i in impacts})
        if impacts:
            worst = max(impacts, key=lambda i: i.risk_score or 0)
            out.max_risk_score = worst.risk_score
            out.max_risk_level = worst.risk_level

    return out


@router.get("/{app_id}/components", response_model=list[ComponentOut])
async def list_components(
    app_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    app = await session.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Anwendung nicht gefunden")
    comps = (await session.execute(
        select(ApplicationComponent)
        .where(ApplicationComponent.application_id == app_id)
        .order_by(ApplicationComponent.name)
    )).scalars().all()
    return [await _resolve_component(c, session) for c in comps]


@router.post("/{app_id}/components", response_model=ComponentOut, status_code=201)
async def add_component(
    app_id: uuid.UUID,
    body: ComponentCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    app = await session.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Anwendung nicht gefunden")
    if body.match_kind not in MATCH_KINDS:
        raise HTTPException(400, f"match_kind muss eines von {MATCH_KINDS} sein")

    comp = ApplicationComponent(
        application_id=app_id,
        name=body.name,
        match_kind=body.match_kind,
        match_value=body.match_value,
        asset_id=body.asset_id,
        origin="manual",
        confirmed=True,
    )
    session.add(comp)
    await session.flush()
    return await _resolve_component(comp, session)


@router.post("/{app_id}/components/{component_id}/confirm", response_model=ComponentOut)
async def confirm_component(
    app_id: uuid.UUID,
    component_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    comp = await session.get(ApplicationComponent, component_id)
    if not comp or comp.application_id != app_id:
        raise HTTPException(404, "Komponente nicht gefunden")
    comp.confirmed = True
    await session.flush()
    return await _resolve_component(comp, session)


@router.delete("/{app_id}/components/{component_id}", status_code=204)
async def delete_component(
    app_id: uuid.UUID,
    component_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    comp = await session.get(ApplicationComponent, component_id)
    if not comp or comp.application_id != app_id:
        raise HTTPException(404, "Komponente nicht gefunden")
    await session.delete(comp)


@router.post("/{app_id}/components/autodiscover", response_model=list[ComponentOut])
async def autodiscover_components(
    app_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """
    Schlägt Komponenten aus der SBOM der App-Systeme (asset_ids) vor.
    Vorgeschlagen werden Pakete mit bekannten CVEs sowie Infrastruktur-Software.
    Fügt nur Neues hinzu (origin=auto, confirmed=false); manuelle/bestätigte
    Einträge bleiben unangetastet.
    """
    app = await session.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Anwendung nicht gefunden")

    seed_ids = [uuid.UUID(str(a)) for a in (app.asset_ids or [])]
    if not seed_ids:
        raise HTTPException(
            400, "Keine Seed-Systeme: asset_ids der Anwendung setzen, dann erneut versuchen."
        )

    # SBOM der Seed-Systeme laden
    sbom = (await session.execute(
        select(SBOMEntry).where(SBOMEntry.asset_id.in_(seed_ids))
    )).scalars().all()

    # Pakete mit bekannten CVEs auf den Seed-Systemen
    vuln_pkgs = set((await session.execute(
        select(func.lower(CVEImpact.affected_pkg)).where(CVEImpact.asset_id.in_(seed_ids))
    )).scalars().all())

    # Kandidaten-Paketnamen bestimmen
    candidates: set[str] = set()
    for e in sbom:
        n = e.pkg_name.lower()
        base = n.split("-")[0]
        if (n in vuln_pkgs or n in RELEVANT_PKG_NAMES or base in RELEVANT_PKG_NAMES
                or (e.pkg_type or "") in ("application", "library")):
            candidates.add(e.pkg_name)

    # Bereits vorhandene name-Regeln (asset-übergreifend) nicht duplizieren
    existing = set((await session.execute(
        select(func.lower(ApplicationComponent.match_value)).where(
            ApplicationComponent.application_id == app_id,
            ApplicationComponent.match_kind == "name",
            ApplicationComponent.asset_id.is_(None),
        )
    )).scalars().all())

    created: list[ApplicationComponent] = []
    for pkg in sorted(candidates):
        if pkg.lower() in existing:
            continue
        comp = ApplicationComponent(
            application_id=app_id,
            name=pkg,
            match_kind="name",
            match_value=pkg.lower(),
            asset_id=None,
            origin="auto",
            confirmed=False,
        )
        session.add(comp)
        created.append(comp)

    await session.flush()
    return [await _resolve_component(c, session) for c in created]
