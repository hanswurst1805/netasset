"""
Dienste/Container – Cross-Host-Übersicht.

Listet die in der services-Tabelle erfassten Listener über alle Assets hinweg
(analog zur Audit-Sessions-Übersicht). Standardmäßig nur container-gebundene
Dienste (Docker/Podman); optional alle Dienste.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import Asset, Service

router = APIRouter()


class ServiceRow(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    hostname: Optional[str]
    ip_address: Optional[str]
    port: int
    proto: str
    bind_address: Optional[str]
    bind_scope: str
    process_name: Optional[str]
    sbom_pkg: Optional[str]
    container_name: Optional[str]
    container_image: Optional[str]
    source: Optional[str]


@router.get("", response_model=list[ServiceRow])
async def list_services(
    container_only: bool = True,
    host: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    stmt = (
        select(Service, Asset)
        .join(Asset, Asset.id == Service.asset_id)
        .where(Asset.is_active == True, Asset.is_archived == False)
    )
    if container_only:
        stmt = stmt.where(
            or_(Service.container_image.is_not(None), Service.container_name.is_not(None))
        )
    if host:
        like = f"%{host.lower()}%"
        from sqlalchemy import func
        stmt = stmt.where(or_(
            func.lower(Asset.hostname).like(like),
            func.lower(Asset.ip_address).like(like),
        ))
    stmt = stmt.order_by(Asset.hostname, Service.port)

    rows = (await session.execute(stmt)).all()
    allowed = ctx.filter_tags()

    out: list[ServiceRow] = []
    for svc, asset in rows:
        if allowed and (not asset.tags or not set(asset.tags) & set(allowed)):
            continue
        out.append(ServiceRow(
            id=svc.id, asset_id=asset.id, hostname=asset.hostname, ip_address=asset.ip_address,
            port=svc.port, proto=svc.proto, bind_address=svc.bind_address, bind_scope=svc.bind_scope,
            process_name=svc.process_name, sbom_pkg=svc.sbom_pkg,
            container_name=svc.container_name, container_image=svc.container_image, source=svc.source,
        ))
    return out
