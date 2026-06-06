"""Asset CRUD – FastAPI Router."""
from __future__ import annotations

import uuid
from typing import Optional

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import Asset

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    additional_ips: Optional[list[str]] = None
    fqdn: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    chassis_id: Optional[str] = None
    asset_type: str = "server"
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_arch: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    exposure_level: str = "INTERN"
    network_zones: Optional[list[str]] = None
    open_ports: Optional[list] = None
    rack_id: Optional[str] = None
    rack_unit: Optional[int] = None
    location: Optional[str] = None
    tags: Optional[list[str]] = None
    min_confidence: Optional[float] = None
    # 0.0 = alles akzeptieren | 0.95 = nur Stable Keys | 1.0 = nur UUID


class AssetUpdate(AssetCreate):
    pass


class AssetOut(BaseModel):
    id: uuid.UUID
    hostname: Optional[str]
    ip_address: Optional[str]
    fqdn: Optional[str]
    mac_address: Optional[str]
    serial_number: Optional[str]
    asset_type: str
    os_name: Optional[str]
    os_version: Optional[str]
    additional_ips: Optional[list[str]] = None
    exposure_level: str
    network_zones: Optional[list[str]]
    open_ports: Optional[list]
    location: Optional[str]
    tags: Optional[list[str]]
    is_active: bool
    min_confidence: Optional[float] = None
    last_seen_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=list[AssetOut])
async def list_assets(
    asset_type: Optional[str] = None,
    exposure_level: Optional[str] = None,
    is_active: bool = True,
    limit: int = Query(100, le=500),
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    from sqlalchemy import func as sqlfunc
    stmt = select(Asset).where(Asset.is_active == is_active)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if exposure_level:
        stmt = stmt.where(Asset.exposure_level == exposure_level)
    # Tag-basierte Zugriffskontrolle
    if allowed := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(allowed))
    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(
    body: AssetCreate,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    asset = Asset(**body.model_dump(exclude_none=True))
    session.add(asset)
    await session.flush()
    await session.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    # Tag-Check
    if allowed := ctx.filter_tags():
        if not asset.tags or not set(asset.tags) & set(allowed):
            raise HTTPException(403, "Kein Zugriff auf dieses Asset")
    return asset


@router.put("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    if allowed := ctx.filter_tags():
        if not asset.tags or not set(asset.tags) & set(allowed):
            raise HTTPException(403, "Kein Zugriff auf dieses Asset")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)
    await session.flush()

    # Router mit 2+ Zonen → Gateways automatisch anlegen
    await _ensure_gateways(asset, session)

    await session.refresh(asset)
    return asset


async def _ensure_gateways(asset: Asset, session) -> None:
    """Legt fehlende Gateways für Router-Assets automatisch an."""
    from itertools import combinations
    from src.models.all_models import NetworkGateway

    if asset.asset_type not in ("router", "firewall"):
        return
    zones = list(set(asset.network_zones or []))
    if len(zones) < 2:
        return

    existing = await session.execute(
        select(NetworkGateway).where(NetworkGateway.asset_id == asset.id)
    )
    existing_pairs = {
        (gw.from_segment, gw.to_segment)
        for gw in existing.scalars().all()
    }

    label = asset.hostname or asset.ip_address or str(asset.id)
    for z1, z2 in combinations(sorted(zones), 2):
        if (z1, z2) in existing_pairs or (z2, z1) in existing_pairs:
            continue
        session.add(NetworkGateway(
            asset_id=asset.id,
            name=f"{label}",
            from_segment=z1,
            to_segment=z2,
            is_primary=False,
            description="Automatisch angelegt",
        ))
        existing_pairs.add((z1, z2))
    await session.flush()


@router.delete("/{asset_id}", status_code=204)
async def deactivate_asset(
    asset_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    if allowed := ctx.filter_tags():
        if not asset.tags or not set(asset.tags) & set(allowed):
            raise HTTPException(403, "Kein Zugriff auf dieses Asset")
    asset.is_active = False
    await session.flush()


# ---------------------------------------------------------------------------
# Bulk-Delete
# ---------------------------------------------------------------------------

class BulkDeleteFilter(BaseModel):
    """Filter-Kriterien für Bulk-Löschung (alle Bedingungen werden per AND verknüpft)."""
    last_seen_before_days: Optional[int] = None   # nie aktualisiert seit N Tagen
    never_seen: bool = False                       # last_seen_at IS NULL
    tags: Optional[list[str]] = None              # hat mindestens einen dieser Tags
    dry_run: bool = True                          # Standard: nur zählen, nicht löschen


class BulkDeleteResult(BaseModel):
    matched: int
    deleted: int
    dry_run: bool


@router.post("/bulk-delete", response_model=BulkDeleteResult)
async def bulk_delete_assets(
    body: BulkDeleteFilter,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Löscht (deaktiviert) Assets anhand von Filterkriterien."""
    # Nur Admins dürfen bulk-löschen
    if ctx.role != "admin":
        raise HTTPException(403, "Nur Admins dürfen Assets in Bulk löschen")

    # Mindestens ein Kriterium muss gesetzt sein
    if not body.last_seen_before_days and not body.never_seen and not body.tags:
        raise HTTPException(400, "Mindestens ein Filterkriterium erforderlich")

    stmt = select(Asset).where(Asset.is_active == True)  # noqa: E712

    # Tag-basierter Zugriff des eingeloggten Users
    if allowed := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(allowed))

    # Filterkriterien
    conditions = []
    if body.last_seen_before_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=body.last_seen_before_days)
        from sqlalchemy import or_, and_
        conditions.append(
            or_(
                Asset.last_seen_at < cutoff,
                Asset.last_seen_at.is_(None),
            ) if body.never_seen else Asset.last_seen_at < cutoff
        )
    if body.never_seen and not body.last_seen_before_days:
        conditions.append(Asset.last_seen_at.is_(None))

    if body.tags:
        stmt = stmt.where(Asset.tags.overlap(body.tags))

    for cond in conditions:
        stmt = stmt.where(cond)

    result = await session.execute(stmt)
    assets = result.scalars().all()
    matched = len(assets)

    if body.dry_run:
        return BulkDeleteResult(matched=matched, deleted=0, dry_run=True)

    for asset in assets:
        asset.is_active = False
    await session.flush()

    return BulkDeleteResult(matched=matched, deleted=matched, dry_run=False)
