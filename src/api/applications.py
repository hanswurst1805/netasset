"""Application CRUD – OBASHI A-Layer (fachliche Anwendungen)."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import Application, BusinessProcess

router = APIRouter()

APP_TYPES = ["web", "api", "batch", "integration", "desktop", "mobile", "service", "other"]


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
