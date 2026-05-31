"""Network Gateway API – Router als Netzwerk-Übergangspunkte markieren."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
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
    id: str
    type: str         # "segment" | "router"
    label: str
    exposure: Optional[str] = None
    cidr: Optional[str] = None
    asset_count: int = 0
    connected: bool = False
    asset_id: Optional[str] = None    # für router-Nodes
    asset_type: Optional[str] = None  # router | firewall
    asset_ip: Optional[str] = None


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


@router.post("/auto-detect", response_model=dict)
async def auto_detect_gateways(
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """
    Erkennt automatisch Gateways aus Assets:
    - Router/Firewall mit 2+ network_zones → je eine Gateway-Kante pro Zone-Paar
    - Existierende Gateways werden nicht dupliziert
    """
    from src.models.all_models import IpNetwork
    from itertools import combinations

    GATEWAY_TYPES = {"router", "firewall", "switch"}

    # Kandidaten: Router/Firewalls mit mehreren Netzwerk-Zonen
    result = await session.execute(
        select(Asset).where(
            Asset.is_active == True,
            Asset.asset_type.in_(GATEWAY_TYPES),
            Asset.network_zones.is_not(None),
        )
    )
    candidates = result.scalars().all()

    # Existierende Gateway-Paare laden (zur Duplikat-Prüfung)
    existing = await session.execute(select(NetworkGateway))
    existing_pairs = {
        (gw.from_segment, gw.to_segment)
        for gw in existing.scalars().all()
    }

    created = 0
    skipped = 0

    for asset in candidates:
        zones = [z for z in (asset.network_zones or []) if z]
        if len(zones) < 2:
            continue

        label = asset.hostname or asset.ip_address or str(asset.id)

        # Alle Zone-Paare als Gateway anlegen
        for z1, z2 in combinations(sorted(set(zones)), 2):
            pair = (z1, z2)
            pair_rev = (z2, z1)
            if pair in existing_pairs or pair_rev in existing_pairs:
                skipped += 1
                continue

            gw = NetworkGateway(
                asset_id=asset.id,
                name=f"{label}: {z1} ↔ {z2}",
                from_segment=z1,
                to_segment=z2,
                is_primary=False,
                description=f"Automatisch erkannt ({asset.asset_type})",
            )
            session.add(gw)
            existing_pairs.add(pair)
            created += 1

    await session.flush()
    return {"created": created, "skipped": skipped}


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
    Netzwerk-Topologie als Graph.
    Segmente = definierte IP-Netzwerke + Gateway-Segmente.
    Kanten = ausschließlich explizit konfigurierte Gateways.
    """
    from src.models.all_models import IpNetwork

    gw_result = await session.execute(select(NetworkGateway))
    gateways = gw_result.scalars().all()

    # Segmente: primär aus definierten IP-Netzwerken
    net_result = await session.execute(select(IpNetwork).order_by(IpNetwork.name))
    ip_networks = net_result.scalars().all()

    segments: dict[str, dict] = {}  # name → {exposure, cidr}

    # 1. IP-Netzwerke als Segmente
    for net in ip_networks:
        segments[net.name] = {
            "exposure": net.exposure_level,
            "cidr": net.cidr,
        }

    # 2. Gateway-Segmente (from/to) — falls nicht schon als IP-Netz vorhanden
    for gw in gateways:
        for seg in (gw.from_segment, gw.to_segment):
            if seg not in segments:
                exp = seg if seg in ("INTERN", "DMZ", "EXTERN") else None
                segments[seg] = {"exposure": exp, "cidr": None}

    # Fallback: Standard-Segmente wenn gar nichts definiert
    if not segments:
        for s in ("INTERN", "DMZ", "EXTERN"):
            segments[s] = {"exposure": s, "cidr": None}

    # Asset-Counts pro Segment laden
    asset_counts: dict[str, int] = {}
    for net in ip_networks:
        count_result = await session.execute(
            select(func.count()).where(
                Asset.network_id == net.id,
                Asset.is_active == True,
            )
        )
        asset_counts[net.name] = count_result.scalar() or 0

    # Verbundene Segmente ermitteln
    connected_segs = set()
    for gw in gateways:
        connected_segs.add(gw.from_segment)
        connected_segs.add(gw.to_segment)

    nodes: list[TopologyNode] = [
        TopologyNode(
            id=f"seg-{name}",
            type="segment",
            label=name,
            exposure=info.get("exposure"),
            cidr=info.get("cidr"),
            asset_count=asset_counts.get(name, 0),
            connected=name in connected_segs,
        )
        for name, info in sorted(segments.items())
    ]

    # Kanten: 1. explizit konfigurierte Gateways
    edges: list[TopologyEdge] = []
    explicit_pairs: set[tuple] = set()

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
        explicit_pairs.add((gw.from_segment, gw.to_segment))
        explicit_pairs.add((gw.to_segment, gw.from_segment))

    # 2. Router/Firewall-Assets mit 2+ Zonen → als eigene Nodes + Kanten
    from itertools import combinations as _comb
    GATEWAY_TYPES = {"router", "firewall"}

    router_result = await session.execute(
        select(Asset).where(
            Asset.is_active == True,
            Asset.asset_type.in_(GATEWAY_TYPES),
            Asset.network_zones.is_not(None),
        )
    )
    router_assets = router_result.scalars().all()
    segment_ids = {n.id for n in nodes}
    router_nodes: list[TopologyNode] = []

    for asset in router_assets:
        zones = [z for z in (asset.network_zones or []) if f"seg-{z}" in segment_ids]
        if len(zones) < 2:
            continue

        label = asset.hostname or asset.ip_address or str(asset.id)
        router_id = f"router-{asset.id}"

        router_nodes.append(TopologyNode(
            id=router_id,
            type=asset.asset_type,  # "router" | "firewall"
            label=label,
            asset_id=str(asset.id),
            asset_type=asset.asset_type,
            asset_ip=asset.ip_address,
        ))

        # Kanten: Segment ↔ Router-Node
        for zone in sorted(set(zones)):
            # Prüfen ob nicht schon durch expliziten Gateway abgedeckt
            explicit_for_zone = any(
                (e.from_id == f"seg-{zone}" or e.to_id == f"seg-{zone}")
                and (e.from_id == router_id or e.to_id == router_id or
                     e.asset_hostname == asset.hostname or e.asset_ip == asset.ip_address)
                for e in edges
            )
            if not explicit_for_zone:
                edges.append(TopologyEdge(
                    from_id=f"seg-{zone}",
                    to_id=router_id,
                    gateway_name=label,
                    is_primary=False,
                    asset_hostname=asset.hostname,
                    asset_ip=asset.ip_address,
                ))
            connected_segs.add(zone)

    # Segment-Nodes mit aktualisiertem connected-Flag neu bauen
    nodes = [
        TopologyNode(
            id=f"seg-{name}",
            type="segment",
            label=name,
            exposure=info.get("exposure"),
            cidr=info.get("cidr"),
            asset_count=asset_counts.get(name, 0),
            connected=name in connected_segs,
        )
        for name, info in sorted(segments.items())
    ] + router_nodes  # Router-Nodes anhängen

    return TopologyDiagram(nodes=nodes, edges=edges)
