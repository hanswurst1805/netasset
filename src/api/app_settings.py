"""Globale, über die UI änderbare Anwendungseinstellungen."""

from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user, require_admin
from src.core.database import get_session
from src.models.all_models import AppSettings

router = APIRouter()


class AppSettingsOut(BaseModel):
    hide_vm_microcode_cves: bool
    model_config = {"from_attributes": True}


class AppSettingsUpdate(BaseModel):
    hide_vm_microcode_cves: bool


async def _get_or_create(session: AsyncSession) -> AppSettings:
    settings_row = await session.get(AppSettings, 1)
    if settings_row is None:
        settings_row = AppSettings(id=1)
        session.add(settings_row)
        await session.flush()
    return settings_row


@router.get("", response_model=AppSettingsOut)
async def get_settings(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    return await _get_or_create(session)


@router.put("", response_model=AppSettingsOut)
async def update_settings(
    body: AppSettingsUpdate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(require_admin),
):
    settings_row = await _get_or_create(session)
    settings_row.hide_vm_microcode_cves = body.hide_vm_microcode_cves
    await session.flush()
    await session.refresh(settings_row)
    return settings_row
