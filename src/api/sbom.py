"""SBOM Endpoints."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.models.all_models import Asset, SBOMEntry

router = APIRouter()


class SBOMEntryIn(BaseModel):
    pkg_name: str
    pkg_version: str
    pkg_type: Optional[str] = None
    cpe: Optional[str] = None
    purl: Optional[str] = None
    source: Optional[str] = None


class SBOMEntryOut(BaseModel):
    id: int
    asset_id: uuid.UUID
    pkg_name: str
    pkg_version: str
    pkg_type: Optional[str]
    cpe: Optional[str]
    purl: Optional[str]
    source: Optional[str]

    model_config = {"from_attributes": True}


@router.get("/assets/{asset_id}/sbom", response_model=list[SBOMEntryOut])
async def get_sbom(asset_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    stmt = select(SBOMEntry).where(SBOMEntry.asset_id == asset_id)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("/assets/{asset_id}/sbom", response_model=list[SBOMEntryOut], status_code=201)
async def add_sbom_entries(
    asset_id: uuid.UUID,
    entries: list[SBOMEntryIn],
    session: AsyncSession = Depends(get_session),
):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    created = []
    for e in entries:
        # Upsert: existierende Einträge aktualisieren
        stmt = select(SBOMEntry).where(
            SBOMEntry.asset_id == asset_id,
            SBOMEntry.pkg_name == e.pkg_name,
            SBOMEntry.pkg_version == e.pkg_version,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            for field, value in e.model_dump(exclude_none=True).items():
                setattr(existing, field, value)
            created.append(existing)
        else:
            entry = SBOMEntry(asset_id=asset_id, **e.model_dump())
            session.add(entry)
            created.append(entry)

    await session.flush()
    for e in created:
        await session.refresh(e)
    return created


@router.get("/search", response_model=list[SBOMEntryOut])
async def search_sbom(
    pkg: str,
    version_min: Optional[str] = None,
    version_max: Optional[str] = None,
    limit: int = Query(50, le=200),
    session: AsyncSession = Depends(get_session),
):
    """Suche nach Paketen über alle Assets (für CVE-Impact-Vorbereitung)."""
    stmt = select(SBOMEntry).where(SBOMEntry.pkg_name.ilike(f"%{pkg}%"))
    result = await session.execute(stmt.limit(limit))
    entries = result.scalars().all()

    # Versions-Filter in Python (semver-aware wäre aufwendiger)
    if version_min or version_max:
        filtered = []
        for e in entries:
            if version_min and e.pkg_version < version_min:
                continue
            if version_max and e.pkg_version > version_max:
                continue
            filtered.append(e)
        return filtered

    return entries
