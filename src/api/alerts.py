"""
Alarme / Detections – Ingest + Cross-Host-Übersicht.

Nimmt Sicherheits-Alarme externer Quellen entgegen (z.B. ESET /v2/detections),
verknüpft sie mit Assets (per Geräte-UUID/Hostname) und liefert sie für den
Menüpunkt „Alarme".
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import Alert, Asset

router = APIRouter()


def _naive(dt: Optional[datetime]) -> Optional[datetime]:
    if dt and dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class AlertIn(BaseModel):
    external_id: str = Field(..., max_length=128)
    source: str = "eset"
    device_uuid: Optional[str] = None
    device_name: Optional[str] = None
    severity: Optional[str] = None
    severity_score: Optional[int] = None
    threat: Optional[str] = None
    type_name: Optional[str] = None
    category: Optional[str] = None
    resolved: bool = False
    occurred_at: Optional[datetime] = None
    user_name: Optional[str] = None


class AlertOut(BaseModel):
    id: uuid.UUID
    source: str
    asset_id: Optional[uuid.UUID]
    device_uuid: Optional[str]
    device_name: Optional[str]
    severity: Optional[str]
    severity_score: Optional[int]
    threat: Optional[str]
    type_name: Optional[str]
    category: Optional[str]
    resolved: bool
    occurred_at: Optional[datetime]
    user_name: Optional[str]
    model_config = {"from_attributes": True}


async def _resolve_asset(device_uuid: Optional[str], device_name: Optional[str], session: AsyncSession):
    if device_uuid:
        aid = (await session.execute(
            select(Asset.id).where(func.lower(Asset.chassis_id) == device_uuid.lower()).limit(1)
        )).scalar_one_or_none()
        if aid:
            return aid
    if device_name:
        aid = (await session.execute(
            select(Asset.id).where(func.lower(Asset.hostname) == device_name.lower()).limit(1)
        )).scalar_one_or_none()
        if aid:
            return aid
    return None


@router.post("/ingest", status_code=201)
async def ingest_alerts(
    alerts: list[AlertIn],
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Bulk-Ingest von Alarmen; Upsert über external_id."""
    if len(alerts) > 1000:
        raise HTTPException(400, "Maximal 1000 Alarme pro Request")
    created = updated = 0
    for a in alerts:
        existing = (await session.execute(
            select(Alert).where(Alert.external_id == a.external_id)
        )).scalar_one_or_none()
        asset_id = await _resolve_asset(a.device_uuid, a.device_name, session)
        if existing:
            existing.resolved = a.resolved
            existing.severity = a.severity
            existing.severity_score = a.severity_score
            if asset_id:
                existing.asset_id = asset_id
            updated += 1
        else:
            session.add(Alert(
                external_id=a.external_id, source=a.source, asset_id=asset_id,
                device_uuid=a.device_uuid, device_name=a.device_name,
                severity=a.severity, severity_score=a.severity_score, threat=a.threat,
                type_name=a.type_name, category=a.category, resolved=a.resolved,
                occurred_at=_naive(a.occurred_at), user_name=a.user_name,
            ))
            created += 1
    await session.flush()
    return {"created": created, "updated": updated}


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    resolved: Optional[bool] = None,
    severity: Optional[str] = None,
    asset_id: Optional[uuid.UUID] = None,
    limit: int = 200,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    stmt = select(Alert).order_by(Alert.resolved, Alert.occurred_at.desc().nullslast())
    if resolved is not None:
        stmt = stmt.where(Alert.resolved == resolved)
    if severity:
        stmt = stmt.where(func.upper(Alert.severity) == severity.upper())
    if asset_id:
        stmt = stmt.where(Alert.asset_id == asset_id)
    stmt = stmt.limit(min(limit, 1000))

    rows = (await session.execute(stmt)).scalars().all()

    allowed = ctx.filter_tags()
    if not allowed:
        return rows
    # Tag-Filter: nur Alarme zu erlaubten Assets (unverknüpfte bleiben sichtbar)
    asset_ids = {r.asset_id for r in rows if r.asset_id}
    tag_map = {}
    if asset_ids:
        for aid, tags in (await session.execute(
            select(Asset.id, Asset.tags).where(Asset.id.in_(asset_ids))
        )).all():
            tag_map[aid] = set(tags or [])
    return [r for r in rows if not r.asset_id or (tag_map.get(r.asset_id, set()) & set(allowed))]


@router.get("/summary")
async def alerts_summary(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Kennzahlen für Badge/Übersicht (offene Alarme, nach Schwere)."""
    open_total = (await session.execute(
        select(func.count()).where(Alert.resolved == False)
    )).scalar() or 0
    by_sev = dict((await session.execute(
        select(func.upper(Alert.severity), func.count())
        .where(Alert.resolved == False).group_by(func.upper(Alert.severity))
    )).all())
    return {"open": open_total, "by_severity": by_sev}
