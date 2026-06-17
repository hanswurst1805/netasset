"""Owner CRUD – BASIS O-Layer."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import Owner

router = APIRouter()


class OwnerCreate(BaseModel):
    name: str
    email: Optional[str] = None
    team: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None  # Owner, Operator, Stakeholder ...


class OwnerOut(BaseModel):
    id: uuid.UUID
    name: str
    email: Optional[str]
    team: Optional[str]
    department: Optional[str]
    role: Optional[str]
    model_config = {"from_attributes": True}


@router.get("", response_model=list[OwnerOut])
async def list_owners(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    result = await session.execute(select(Owner).order_by(Owner.name))
    return result.scalars().all()


@router.post("", response_model=OwnerOut, status_code=201)
async def create_owner(
    body: OwnerCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    owner = Owner(**body.model_dump(exclude_none=True))
    session.add(owner)
    await session.flush()
    await session.refresh(owner)
    return owner


@router.put("/{owner_id}", response_model=OwnerOut)
async def update_owner(
    owner_id: uuid.UUID,
    body: OwnerCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    owner = await session.get(Owner, owner_id)
    if not owner:
        raise HTTPException(404, "Owner nicht gefunden")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(owner, k, v)
    await session.flush()
    await session.refresh(owner)
    return owner


@router.delete("/{owner_id}", status_code=204)
async def delete_owner(
    owner_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    owner = await session.get(Owner, owner_id)
    if not owner:
        raise HTTPException(404, "Owner nicht gefunden")
    await session.delete(owner)
