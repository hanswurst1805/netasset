"""Network Gateway API – Router als Netzwerk-Übergangspunkte markieren."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import Asset, NetworkGateway

router = APIRouter()

COMMON_SEGMENTS = ["INTERN", "DMZ", "EXTERN", "MGMT", "GUEST"]


class GatewayCreate(BaseModel):
    asset_id: uuid.UUID
    name: str
    from_segment: str
    to_segment: str
    is_primary: bool = False
    description: Optional[str] = None


class GatewayOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    name: str
    from_segment: str
    to_segment: str
    is_primary: bool
    description: Optional[str]
    # Asset-Infos für Anzeige
    asset_hostname: Optional[str] = None
    asset_ip: Optional[str] = None
    asset_type: Optional[str] = None
    model_config = {"from_attributes": True}


class TopologyNode(BaseModel):
    id: str           # Segment-Name
    type: str         # "segment" | "gateway"
    label: str
    exposure: Optional[str] = None
    asset_id: Optional[str] = None


class TopologyEdge(BaseModel):
    from_id: str
    to_id: str
    gateway_name: str
    is_primary: bool
    asset_hostname: Optional[str] = None
    asset_ip: Optional[str] = None


class TopologyDiagram(BaseModel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


@router.get("", response_model=list[GatewayOut])
async def list_gateways(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    result = await session.execute(select(NetworkGateway).order_by(NetworkGateway.is_primary.desc()))
    gateways = result.scalars().all()

    out = []
    for gw in gateways:
        asset = await session.get(Asset, gw.asset_id)
        out.append(GatewayOut(
            id=gw.id,
            asset_id=gw.asset_id,
            name=gw.name,
            from_segment=gw.from_segment,
            to_segment=gw.to_segment,
            is_primary=gw.is_primary,
            description=gw.description,
            asset_hostname=asset.hostname if asset else None,
            asset_ip=asset.ip_address if asset else None,
            asset_type=asset.asset_type if asset else None,
        ))
    return out


@router.post("", response_model=GatewayOut, status_code=201)
async def create_gateway(
    body: GatewayCreate,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    asset = await session.get(Asset, body.asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {body.asset_id} nicht gefunden")

    # Wenn primary: bisherigen primary im gleichen Segment abwählen
    if body.is_primary:
        stmt = select(NetworkGateway).where(
            NetworkGateway.from_segment == body.from_segment,
            NetworkGateway.to_segment == body.to_segment,
            NetworkGateway.is_primary == True,
        )
        for old_primary in (await session.execute(stmt)).scalars():
            old_primary.is_primary = False

    gw = NetworkGateway(**body.model_dump())
    session.add(gw)
    await session.flush()
    await session.refresh(gw)

    return GatewayOut(
        id=gw.id,
        asset_id=gw.asset_id,
        name=gw.name,
        from_segment=gw.from_segment,
        to_segment=gw.to_segment,
        is_primary=gw.is_primary,
        description=gw.description,
        asset_hostname=asset.hostname,
        asset_ip=asset.ip_address,
        asset_type=asset.asset_type,
    )


@router.delete("/{gateway_id}", status_code=204)
async def delete_gateway(
    gateway_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    gw = await session.get(NetworkGateway, gateway_id)
    if not gw:
        raise HTTPException(404, "Gateway nicht gefunden")
    await session.delete(gw)


@router.get("/topology", response_model=TopologyDiagram)
async def get_topology(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """
    Netzwerk-Topologie als Graph:
    Knoten = Segmente (INTERN, DMZ, EXTERN, VLANs, CIDRs...)
    Kanten = Gateways (Router/Firewalls als Verbindungen)

    Segmente kommen aus:
      1. Explizit konfigurierten Gateways (from_segment / to_segment)
      2. network_zones der Assets (Router/Firewalls die in mehreren Netzen sind)
    """
    gw_result = await session.execute(select(NetworkGateway))
    gateways = gw_result.scalars().all()

    # Assets mit network_zones laden
    asset_result = await session.execute(
        select(Asset).where(
            Asset.is_active == True,
            Asset.network_zones.is_not(None),
        )
    )
    multi_zone_assets = asset_result.scalars().all()

    segments: set[str] = set()

    # Segmente aus Gateways
    for gw in gateways:
        segments.add(gw.from_segment)
        segments.add(gw.to_segment)

    # Segmente aus network_zones der Assets
    for asset in multi_zone_assets:
        for zone in (asset.network_zones or []):
            segments.add(zone)

    # Fallback
    if not segments:
        segments = {"INTERN", "DMZ", "EXTERN"}

    exposure_map = {"INTERN": "INTERN", "DMZ": "DMZ", "EXTERN": "EXTERN"}

    nodes: list[TopologyNode] = []
    for seg in sorted(segments):
        nodes.append(TopologyNode(
            id=f"seg-{seg}",
            type="segment",
            label=seg,
            exposure=exposure_map.get(seg),
        ))

    # Kanten aus expliziten Gateways
    edges: list[TopologyEdge] = []
    for gw in gateways:
        asset = await session.get(Asset, gw.asset_id)
        edges.append(TopologyEdge(
            from_id=f"seg-{gw.from_segment}",
            to_id=f"seg-{gw.to_segment}",
            gateway_name=gw.name,
            is_primary=gw.is_primary,
            asset_hostname=asset.hostname if asset else None,
            asset_ip=asset.ip_address if asset else None,
        ))

    # Zusätzliche Kanten aus network_zones:
    # Wenn ein Router in [INTERN, DMZ, EXTERN] ist → Kanten zwischen allen Zonen
    gw_asset_ids = {gw.asset_id for gw in gateways}
    for asset in multi_zone_assets:
        if asset.id in gw_asset_ids:
            continue  # bereits durch explizite Gateways abgedeckt
        zones = asset.network_zones or []
        if len(zones) >= 2:
            # Kanten zwischen allen Zone-Paaren
            for i, z1 in enumerate(zones):
                for z2 in zones[i+1:]:
                    if f"seg-{z1}" in {n.id for n in nodes} and f"seg-{z2}" in {n.id for n in nodes}:
                        edges.append(TopologyEdge(
                            from_id=f"seg-{z1}",
                            to_id=f"seg-{z2}",
                            gateway_name=asset.hostname or str(asset.ip_address),
                            is_primary=False,
                            asset_hostname=asset.hostname,
                            asset_ip=asset.ip_address,
                        ))

    return TopologyDiagram(nodes=nodes, edges=edges)
