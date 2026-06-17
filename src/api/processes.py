"""Business-Prozesse (BASIS B-Layer) – FastAPI Router."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.database import get_session
from src.models.all_models import Asset, BusinessProcess, CVEImpact, ProcessAsset

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ProcessCreate(BaseModel):
    name: str
    description: Optional[str] = None
    criticality: int = 3
    sla_rto_hours: Optional[int] = None
    sla_rpo_hours: Optional[int] = None
    owner_id: Optional[uuid.UUID] = None

    model_config = {"populate_by_name": True}


class ProcessOut(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    criticality: int
    sla_rto_hours: Optional[int]
    sla_rpo_hours: Optional[int]
    owner_id: Optional[uuid.UUID]

    model_config = {"from_attributes": True}


class ProcessAssetIn(BaseModel):
    asset_id: uuid.UUID
    role: Optional[str] = "primary"


class CVERiskSummary(BaseModel):
    process_id: uuid.UUID
    process_name: str
    criticality: int
    total_affected_assets: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    top_cves: list[dict]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=list[ProcessOut])
async def list_processes(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(BusinessProcess))
    return result.scalars().all()


@router.post("", response_model=ProcessOut, status_code=201)
async def create_process(body: ProcessCreate, session: AsyncSession = Depends(get_session)):
    if not 1 <= body.criticality <= 5:
        raise HTTPException(400, "criticality muss zwischen 1 und 5 liegen")
    process = BusinessProcess(**body.model_dump(exclude_none=True))
    session.add(process)
    await session.flush()
    await session.refresh(process)
    return process


@router.get("/{process_id}", response_model=ProcessOut)
async def get_process(process_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")
    return process


@router.put("/{process_id}", response_model=ProcessOut)
async def update_process(
    process_id: uuid.UUID,
    body: ProcessCreate,
    session: AsyncSession = Depends(get_session),
):
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(process, k, v)
    await session.flush()
    await session.refresh(process)
    return process


@router.post("/{process_id}/assets", status_code=201)
async def add_asset_to_process(
    process_id: uuid.UUID,
    body: ProcessAssetIn,
    session: AsyncSession = Depends(get_session),
):
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")
    asset = await session.get(Asset, body.asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {body.asset_id} nicht gefunden")

    stmt = select(ProcessAsset).where(
        ProcessAsset.process_id == process_id,
        ProcessAsset.asset_id == body.asset_id,
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if existing:
        existing.role = body.role
    else:
        session.add(ProcessAsset(process_id=process_id, asset_id=body.asset_id, role=body.role))

    await session.flush()
    return {"process_id": str(process_id), "asset_id": str(body.asset_id), "role": body.role}


@router.get("/{process_id}/assets")
async def get_process_assets(process_id: uuid.UUID, session: AsyncSession = Depends(get_session)):
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")

    stmt = (
        select(ProcessAsset)
        .where(ProcessAsset.process_id == process_id)
        .options(selectinload(ProcessAsset.asset))
    )
    result = await session.execute(stmt)
    items = result.scalars().all()
    return [
        {
            "asset_id": str(pa.asset_id),
            "role": pa.role,
            "hostname": pa.asset.hostname,
            "ip_address": pa.asset.ip_address,
            "asset_type": pa.asset.asset_type,
            "exposure_level": pa.asset.exposure_level,
        }
        for pa in items
    ]


@router.get("/{process_id}/cve-risk", response_model=CVERiskSummary)
async def get_process_cve_risk(
    process_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    """Aggregiertes CVE-Risiko für alle Assets eines Prozesses."""
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")

    # Asset-IDs des Prozesses
    stmt = select(ProcessAsset.asset_id).where(ProcessAsset.process_id == process_id)
    result = await session.execute(stmt)
    asset_ids = [row[0] for row in result]

    if not asset_ids:
        return CVERiskSummary(
            process_id=process_id,
            process_name=process.name,
            criticality=process.criticality,
            total_affected_assets=0,
            high_risk_count=0,
            medium_risk_count=0,
            low_risk_count=0,
            top_cves=[],
        )

    # CVE-Impacts für alle Assets
    stmt = select(CVEImpact).where(CVEImpact.asset_id.in_(asset_ids))
    result = await session.execute(stmt)
    impacts = result.scalars().all()

    affected_assets = {i.asset_id for i in impacts}
    high = sum(1 for i in impacts if i.risk_level == "HIGH")
    medium = sum(1 for i in impacts if i.risk_level == "MEDIUM")
    low = sum(1 for i in impacts if i.risk_level == "LOW")

    # Top CVEs nach Score
    top = sorted(impacts, key=lambda x: x.risk_score or 0, reverse=True)[:5]
    top_cves = [
        {"cve_id": i.cve_id, "risk_score": i.risk_score, "risk_level": i.risk_level}
        for i in top
    ]

    return CVERiskSummary(
        process_id=process_id,
        process_name=process.name,
        criticality=process.criticality,
        total_affected_assets=len(affected_assets),
        high_risk_count=high,
        medium_risk_count=medium,
        low_risk_count=low,
        top_cves=top_cves,
    )
