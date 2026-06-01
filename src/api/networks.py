"""IP-Netzwerk-Verwaltung – benannte Subnetze mit automatischer Asset-Zuordnung."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.core.network_classifier import ip_in_network, reclassify_all
from src.models.all_models import Asset, IpNetwork

import ipaddress

router = APIRouter()


class NetworkCreate(BaseModel):
    name: str
    cidr: str
    description: Optional[str] = None
    exposure_level: str = "INTERN"
    color: Optional[str] = None
    gateway_asset_id: Optional[uuid.UUID] = None  # Router der dieses Netz nach oben verbindet

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            net = ipaddress.ip_network(v, strict=False)
            return str(net)  # normalisieren: 192.168.178.1/24 → 192.168.178.0/24
        except ValueError:
            raise ValueError(f"Ungültige CIDR-Notation: {v}")


class NetworkOut(BaseModel):
    id: uuid.UUID
    name: str
    cidr: str
    description: Optional[str]
    exposure_level: str
    color: Optional[str]
    gateway_asset_id: Optional[uuid.UUID] = None
    gateway_hostname: Optional[str] = None  # für Anzeige
    asset_count: int = 0
    model_config = {"from_attributes": True}


class ReclassifyResult(BaseModel):
    updated: int
    total: int


@router.get("", response_model=list[NetworkOut])
async def list_networks(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    result = await session.execute(select(IpNetwork).order_by(IpNetwork.name))
    networks = result.scalars().all()

    out = []
    for net in networks:
        count_result = await session.execute(
            select(func.count()).where(
                Asset.is_active == True,
                or_(
                    Asset.network_id == net.id,
                    Asset.network_zones.contains([net.name]),
                )
            )
        )
        gw_hostname = None
        if net.gateway_asset_id:
            gw = await session.get(Asset, net.gateway_asset_id)
            gw_hostname = gw.hostname or gw.ip_address if gw else None
        out.append(NetworkOut(
            id=net.id, name=net.name, cidr=net.cidr,
            description=net.description, exposure_level=net.exposure_level,
            color=net.color, gateway_asset_id=net.gateway_asset_id,
            gateway_hostname=gw_hostname,
            asset_count=count_result.scalar() or 0,
        ))
    return out


@router.post("", response_model=NetworkOut, status_code=201)
async def create_network(
    body: NetworkCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    # Duplikat-Check
    existing = (await session.execute(
        select(IpNetwork).where(IpNetwork.cidr == body.cidr)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(400, f"Netz {body.cidr} existiert bereits: '{existing.name}'")

    net = IpNetwork(**body.model_dump(exclude_none=True))
    session.add(net)
    await session.flush()

    # Gateway-Router: dessen network_zones um dieses Netz ergänzen
    if body.gateway_asset_id:
        gw_asset = await session.get(Asset, body.gateway_asset_id)
        if gw_asset:
            zones = set(gw_asset.network_zones or [])
            zones.add(net.name)
            gw_asset.network_zones = list(zones)
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(gw_asset, "network_zones")

    # Bestehende Assets sofort zuordnen
    assets_result = await session.execute(
        select(Asset).where(Asset.is_active == True, Asset.ip_address.is_not(None))
    )
    assets = assets_result.scalars().all()
    assigned = 0
    for asset in assets:
        if asset.ip_address and ip_in_network(asset.ip_address, net.cidr):
            asset.network_id = net.id
            zones = set(asset.network_zones or [])
            zones.add(net.name)
            zones.add(net.cidr)
            asset.network_zones = list(zones)
            assigned += 1
    await session.flush()

    await session.refresh(net)
    return NetworkOut(
        id=net.id, name=net.name, cidr=net.cidr,
        description=net.description, exposure_level=net.exposure_level,
        color=net.color, asset_count=assigned,
    )


@router.put("/{network_id}", response_model=NetworkOut)
async def update_network(
    network_id: uuid.UUID,
    body: NetworkCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    net = await session.get(IpNetwork, network_id)
    if not net:
        raise HTTPException(404, "Netzwerk nicht gefunden")

    for k, v in body.model_dump(exclude_none=True).items():
        setattr(net, k, v)
    await session.flush()

    # Assets neu klassifizieren
    await reclassify_all(session)
    await session.refresh(net)

    count = (await session.execute(
        select(func.count()).where(Asset.network_id == net.id, Asset.is_active == True)
    )).scalar() or 0

    return NetworkOut(id=net.id, name=net.name, cidr=net.cidr,
                      description=net.description, exposure_level=net.exposure_level,
                      color=net.color, asset_count=count)


@router.delete("/{network_id}", status_code=204)
async def delete_network(
    network_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    net = await session.get(IpNetwork, network_id)
    if not net:
        raise HTTPException(404, "Netzwerk nicht gefunden")
    await session.delete(net)


@router.post("/reclassify", response_model=ReclassifyResult)
async def reclassify(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Alle Assets anhand der definierten Netze neu klassifizieren."""
    total_result = await session.execute(
        select(func.count()).where(Asset.is_active == True, Asset.ip_address.is_not(None))
    )
    total = total_result.scalar() or 0
    updated = await reclassify_all(session)
    return ReclassifyResult(updated=updated, total=total)


@router.get("/{network_id}/assets")
async def network_assets(
    network_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Alle Assets eines Netzwerks."""
    net = await session.get(IpNetwork, network_id)
    if not net:
        raise HTTPException(404, "Netzwerk nicht gefunden")

    result = await session.execute(
        select(Asset).where(
            Asset.is_active == True,
            or_(
                Asset.network_id == network_id,
                Asset.network_zones.contains([net.name]),
            )
        ).order_by(Asset.ip_address)
    )
    assets = result.scalars().all()
    return [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "asset_type": a.asset_type,
            "exposure_level": a.exposure_level,
            "os_name": a.os_name,
            "tags": a.tags,
        }
        for a in assets
    ]
