"""Conflict Queue – manuelle Auflösung von Geräte-Konflikten."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.core.identity import IdentityResolver
from src.models.all_models import Asset, ConflictQueueEntry

router = APIRouter()

# Felder aus DiscoveredDevice die direkt in Asset übernommen werden können
ASSET_FIELDS = {
    "mac_address", "serial_number", "chassis_id", "hostname", "ip_address",
    "fqdn", "asset_type", "os_name", "os_version", "manufacturer", "model",
    "exposure_level", "open_ports", "tags",
}


class ConflictOut(BaseModel):
    id: uuid.UUID
    incoming_data: dict
    source: Optional[str]
    confidence: float
    matched_on: list[str]
    candidate_asset_id: Optional[uuid.UUID]
    candidate_asset: Optional[dict]
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


class ConflictStats(BaseModel):
    pending: int
    merged: int
    created: int
    discarded: int


@router.get("/stats", response_model=ConflictStats)
async def conflict_stats(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Zähler für Sidebar-Badge."""
    stats = {"pending": 0, "merged": 0, "created": 0, "discarded": 0}
    for status in stats:
        result = await session.execute(
            select(func.count()).where(ConflictQueueEntry.status == status)
        )
        stats[status] = result.scalar() or 0
    return ConflictStats(**stats)


@router.get("", response_model=list[ConflictOut])
async def list_conflicts(
    status: str = "pending",
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    stmt = (
        select(ConflictQueueEntry)
        .where(ConflictQueueEntry.status == status)
        .order_by(ConflictQueueEntry.created_at.desc())
        .limit(100)
    )
    result = await session.execute(stmt)
    entries = result.scalars().all()

    out = []
    for e in entries:
        candidate = None
        if e.candidate_asset_id:
            asset = await session.get(Asset, e.candidate_asset_id)
            if asset:
                candidate = {
                    "id": str(asset.id),
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "mac_address": asset.mac_address,
                    "os_name": asset.os_name,
                    "asset_type": asset.asset_type,
                    "exposure_level": asset.exposure_level,
                    "tags": asset.tags,
                    "sources": asset.sources,
                }
        out.append(ConflictOut(
            id=e.id,
            incoming_data=e.incoming_data,
            source=e.source,
            confidence=e.confidence or 0.0,
            matched_on=e.matched_on or [],
            candidate_asset_id=e.candidate_asset_id,
            candidate_asset=candidate,
            status=e.status,
            created_at=e.created_at,
        ))
    return out


@router.post("/{conflict_id}/merge", response_model=dict)
async def resolve_merge(
    conflict_id: uuid.UUID,
    asset_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Eingehende Daten mit einem bestehenden Asset zusammenführen."""
    entry = await session.get(ConflictQueueEntry, conflict_id)
    if not entry or entry.status != "pending":
        raise HTTPException(404, "Conflict nicht gefunden oder bereits aufgelöst")

    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    resolver = IdentityResolver(session)
    await resolver.merge_data(asset.id, entry.incoming_data)

    entry.status = "merged"
    entry.resolved_by = ctx.username
    entry.resolved_at = datetime.utcnow()
    await session.flush()
    return {"status": "merged", "asset_id": str(asset.id)}


@router.post("/{conflict_id}/create", response_model=dict)
async def resolve_create(
    conflict_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Eingehende Daten als neues Asset anlegen."""
    entry = await session.get(ConflictQueueEntry, conflict_id)
    if not entry or entry.status != "pending":
        raise HTTPException(404, "Conflict nicht gefunden oder bereits aufgelöst")

    # Nur bekannte Asset-Felder übernehmen, None-Werte überspringen
    asset_data = {
        k: v for k, v in entry.incoming_data.items()
        if k in ASSET_FIELDS and v is not None
    }
    asset = Asset(**asset_data)
    asset.sources = [{
        "origin": entry.source or "manual",
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "priority": 0,
        "fields": list(asset_data.keys()),
    }]
    session.add(asset)
    await session.flush()

    entry.status = "created"
    entry.resolved_by = ctx.username
    entry.resolved_at = datetime.utcnow()
    entry.candidate_asset_id = asset.id
    await session.flush()
    return {"status": "created", "asset_id": str(asset.id)}


@router.post("/{conflict_id}/discard", response_model=dict)
async def resolve_discard(
    conflict_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Eingehende Daten verwerfen."""
    entry = await session.get(ConflictQueueEntry, conflict_id)
    if not entry or entry.status != "pending":
        raise HTTPException(404, "Conflict nicht gefunden oder bereits aufgelöst")

    entry.status = "discarded"
    entry.resolved_by = ctx.username
    entry.resolved_at = datetime.utcnow()
    await session.flush()
    return {"status": "discarded"}


@router.delete("/{conflict_id}", status_code=204)
async def delete_conflict(
    conflict_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Conflict-Eintrag dauerhaft aus der DB löschen."""
    entry = await session.get(ConflictQueueEntry, conflict_id)
    if not entry:
        raise HTTPException(404, "Conflict nicht gefunden")
    await session.delete(entry)
    await session.flush()
