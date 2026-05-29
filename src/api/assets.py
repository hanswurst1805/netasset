"""Asset CRUD – FastAPI Router."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.models.all_models import Asset

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
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
    open_ports: Optional[list] = None
    rack_id: Optional[str] = None
    rack_unit: Optional[int] = None
    location: Optional[str] = None
    tags: Optional[list[str]] = None


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
    exposure_level: str
    open_ports: Optional[list]
    location: Optional[str]
    tags: Optional[list[str]]
    is_active: bool

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
):
    stmt = select(Asset).where(Asset.is_active == is_active)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if exposure_level:
        stmt = stmt.where(Asset.exposure_level == exposure_level)
    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(body: AssetCreate, session: AsyncSession = Depends(get_session)):
    asset = Asset(**body.model_dump(exclude_none=True))
    session.add(asset)
    await session.flush()
    await session.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    return asset


@router.put("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    session: AsyncSession = Depends(get_session),
):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)

    await session.flush()
    await session.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=204)
async def deactivate_asset(asset_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")
    asset.is_active = False
    await session.flush()
