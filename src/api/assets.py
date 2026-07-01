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
from src.models.all_models import Asset, CVEEntry, CVEImpact, Service
from src.rag.cve_impact import _is_vm, _is_vm_irrelevant_pkg, get_hide_vm_microcode_setting

router = APIRouter()

# Schwelle für "last_seen_at zu alt" (Aufmerksamkeits-Filter)
STALE_HOURS = 24


def _is_stale(last_seen: Optional[datetime]) -> bool:
    if not last_seen:
        return True
    return (datetime.utcnow() - last_seen).total_seconds() > STALE_HOURS * 3600


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
    is_archived: Optional[bool] = None
    # Archiviert: ausgeblendet aus Reports/Auswertungen, keine Discovery-Updates mehr
    force_vm: Optional[bool] = None
    # Erzwingt VM-Erkennung (z.B. für Microcode-CVE-Ausblendung)


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
    is_archived: bool = False
    force_vm: bool = False
    min_confidence: Optional[float] = None
    last_seen_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    needs_attention: bool = False
    attention_reasons: list[str] = []

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

async def _annotate_attention(assets: list[Asset], session: AsyncSession) -> None:
    """
    Markiert Assets, die Aufmerksamkeit benötigen, mit `needs_attention` + `attention_reasons`.
    Kriterien: HIGH-Risk-CVEs, aktiv ausgenutzte CVEs (KEV), ausstehender Reboot,
    ausstehende Security-Updates, oder seit > STALE_HOURS nicht gesehen.
    Microcode-/Firmware-CVEs auf VMs werden dabei ignoriert (nicht exploitierbar).
    """
    if not assets:
        return

    asset_ids = [a.id for a in assets]

    high_risk: dict[uuid.UUID, set[str]] = {}
    rows = await session.execute(
        select(CVEImpact.asset_id, CVEImpact.affected_pkg)
        .where(CVEImpact.asset_id.in_(asset_ids), CVEImpact.risk_level == "HIGH")
    )
    for row in rows:
        high_risk.setdefault(row.asset_id, set()).add(row.affected_pkg or "")

    kev: dict[uuid.UUID, set[str]] = {}
    rows = await session.execute(
        select(CVEImpact.asset_id, CVEImpact.affected_pkg)
        .select_from(CVEImpact)
        .join(CVEEntry, CVEImpact.cve_id == CVEEntry.cve_id)
        .where(CVEImpact.asset_id.in_(asset_ids), CVEEntry.is_kev == True)
    )
    for row in rows:
        kev.setdefault(row.asset_id, set()).add(row.affected_pkg or "")

    hide_vm_microcode = await get_hide_vm_microcode_setting(session)

    for asset in assets:
        reasons: list[str] = []
        is_vm_asset = _is_vm(asset)

        def _relevant(pkgs: set[str]) -> bool:
            return any(
                not (hide_vm_microcode and is_vm_asset and _is_vm_irrelevant_pkg(pkg))
                for pkg in pkgs
            )

        if _relevant(high_risk.get(asset.id, set())):
            reasons.append("kritische CVEs (HIGH)")
        if _relevant(kev.get(asset.id, set())):
            reasons.append("aktiv ausgenutzte CVE (KEV)")

        tags = asset.tags or []
        if "reboot-required" in tags:
            reasons.append("Neustart erforderlich")

        sec_updates = next(
            (t.split(":")[1] for t in tags if t.startswith("security-updates:")), None
        )
        if sec_updates and sec_updates.isdigit() and int(sec_updates) > 0:
            reasons.append(f"{sec_updates} Security-Updates ausstehend")

        # ESET-Schutzstatus: alles außer "ok" ist ein Alarm
        eset = next((t for t in tags if t.startswith("eset-status-")), None)
        if eset and eset != "eset-status-ok" and eset != "eset-status-unknown":
            reasons.append(f"ESET-Schutzstatus: {eset[len('eset-status-'):].replace('-', ' ')}")

        if _is_stale(asset.last_seen_at):
            reasons.append("nicht kürzlich gesehen")

        asset.needs_attention = bool(reasons)
        asset.attention_reasons = reasons


@router.get("", response_model=list[AssetOut])
async def list_assets(
    asset_type: Optional[str] = None,
    exposure_level: Optional[str] = None,
    is_active: bool = True,
    is_archived: Optional[bool] = None,
    needs_attention: Optional[bool] = None,
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
    if is_archived is not None:
        stmt = stmt.where(Asset.is_archived == is_archived)
    # Tag-basierte Zugriffskontrolle
    if allowed := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(allowed))
    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    assets = result.scalars().all()

    await _annotate_attention(assets, session)

    if needs_attention:
        assets = [a for a in assets if a.needs_attention]

    return assets


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


# ---------------------------------------------------------------------------
# Bulk-Delete  (muss VOR /{asset_id} stehen, sonst 405 Method Not Allowed)
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
    from sqlalchemy import or_
    conditions = []
    if body.last_seen_before_days is not None:
        cutoff = datetime.utcnow() - timedelta(days=body.last_seen_before_days)
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
    assets_to_delete = result.scalars().all()
    matched = len(assets_to_delete)

    if body.dry_run:
        return BulkDeleteResult(matched=matched, deleted=0, dry_run=True)

    for asset in assets_to_delete:
        asset.is_active = False
    await session.flush()

    return BulkDeleteResult(matched=matched, deleted=matched, dry_run=False)


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


class ServiceOut(BaseModel):
    id: uuid.UUID
    port: int
    proto: str
    bind_address: Optional[str]
    bind_scope: str
    process_name: Optional[str]
    process_path: Optional[str]
    sbom_pkg: Optional[str]
    container_name: Optional[str]
    container_image: Optional[str]
    source: Optional[str]
    model_config = {"from_attributes": True}


@router.get("/{asset_id}/services", response_model=list[ServiceOut])
async def asset_services(
    asset_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Lauschende Dienste des Assets (Port → Prozess → SBOM-Paket, inkl. localhost/Docker)."""
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    if allowed := ctx.filter_tags():
        if not asset.tags or not set(asset.tags) & set(allowed):
            raise HTTPException(403, "Kein Zugriff auf dieses Asset")
    rows = (await session.execute(
        select(Service).where(Service.asset_id == asset_id)
        .order_by(Service.bind_scope, Service.port)
    )).scalars().all()
    return rows


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

    from src.core.identity import PRIORITY_FIELDS
    update_data = body.model_dump(exclude_none=True)
    changed_priority_fields = [
        f for f in update_data if f in PRIORITY_FIELDS and getattr(asset, f, None) != update_data[f]
    ]
    for field, value in update_data.items():
        setattr(asset, field, value)

    if changed_priority_fields:
        from sqlalchemy.orm.attributes import flag_modified
        sources = [s for s in (asset.sources or []) if s.get("origin") != "manual"]
        sources.append({
            "origin": "manual",
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "priority": 100,
            "fields": changed_priority_fields,
        })
        asset.sources = sources
        flag_modified(asset, "sources")

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
