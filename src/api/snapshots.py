"""Asset Snapshot API."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.core.snapshots import run_daily_snapshots, snapshot_asset
from src.models.all_models import Asset, AssetSnapshot

router = APIRouter()


class SnapshotOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    snapshot_date: datetime
    data: dict
    diff: Optional[dict]
    created_at: datetime
    has_changes: bool = False
    model_config = {"from_attributes": True}


class RunResult(BaseModel):
    created: int
    updated: int
    errors: int
    total: int


@router.post("/run", response_model=RunResult)
async def run_snapshots(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Erstellt/aktualisiert Snapshots für alle aktiven Assets."""
    result = await run_daily_snapshots(session)
    return RunResult(**result)


@router.post("/assets/{asset_id}", response_model=SnapshotOut, status_code=201)
async def create_asset_snapshot(
    asset_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Erstellt einen Snapshot für ein einzelnes Asset."""
    asset = await session.get(Asset, asset_id,
                              options=[selectinload(Asset.sbom_entries)])
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    snap = await snapshot_asset(asset, asset.sbom_entries, session)
    return SnapshotOut(
        id=snap.id,
        asset_id=snap.asset_id,
        snapshot_date=snap.snapshot_date,
        data=snap.data,
        diff=snap.diff,
        created_at=snap.created_at,
        has_changes=bool(snap.diff),
    )


@router.get("/assets/{asset_id}", response_model=list[SnapshotOut])
async def list_asset_snapshots(
    asset_id: uuid.UUID,
    limit: int = 30,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Alle Snapshots eines Assets, neueste zuerst."""
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    stmt = (
        select(AssetSnapshot)
        .where(AssetSnapshot.asset_id == asset_id)
        .order_by(desc(AssetSnapshot.snapshot_date))
        .limit(limit)
    )
    result = await session.execute(stmt)
    snaps = result.scalars().all()

    return [
        SnapshotOut(
            id=s.id,
            asset_id=s.asset_id,
            snapshot_date=s.snapshot_date,
            data=s.data,
            diff=s.diff,
            created_at=s.created_at,
            has_changes=bool(s.diff),
        )
        for s in snaps
    ]


@router.get("/assets/{asset_id}/{snapshot_id}", response_model=SnapshotOut)
async def get_snapshot(
    asset_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    snap = await session.get(AssetSnapshot, snapshot_id)
    if not snap or snap.asset_id != asset_id:
        raise HTTPException(404, "Snapshot nicht gefunden")
    return SnapshotOut(
        id=snap.id,
        asset_id=snap.asset_id,
        snapshot_date=snap.snapshot_date,
        data=snap.data,
        diff=snap.diff,
        created_at=snap.created_at,
        has_changes=bool(snap.diff),
    )
