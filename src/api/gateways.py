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
    type: str         # "segment" | "router" | "firewall"
    label: str
    exposure: Optional[str] = None
    cidr: Optional[str] = None
    asset_count: int = 0
    connected: bool = False
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None
    asset_ip: Optional[str] = None
    level: int = 0    # Hierarchie-Ebene: 0=extern, höher=interner


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
    Hierarchische Netzwerk-Topologie.
    Level 0 = extern, höhere Level = interner.
    Router sitzen zwischen den Segmenten die sie verbinden.
    """
    from collections import defaultdict, deque
    from itertools import combinations as _comb
    from src.models.all_models import IpNetwork

    # ── Daten laden ──────────────────────────────────────────────────────────
    gw_result   = await session.execute(select(NetworkGateway))
    gateways    = gw_result.scalars().all()
    net_result  = await session.execute(select(IpNetwork).order_by(IpNetwork.name))
    ip_networks = net_result.scalars().all()

    GATEWAY_TYPES = {"router", "firewall"}
    router_result = await session.execute(
        select(Asset).where(
            Asset.is_active == True,
            Asset.asset_type.in_(GATEWAY_TYPES),
            Asset.network_zones.is_not(None),
        )
    )
    router_assets = router_result.scalars().all()

    # ── Segmente sammeln ──────────────────────────────────────────────────────
    EXPOSURE_BASE = {"EXTERN": 0, "DMZ": 2, "INTERN": 4}
    segments: dict[str, dict] = {}
    for net in ip_networks:
        segments[net.name] = {"exposure": net.exposure_level, "cidr": net.cidr}
    for gw in gateways:
        for seg in (gw.from_segment, gw.to_segment):
            if seg not in segments:
                segments[seg] = {"exposure": seg if seg in EXPOSURE_BASE else None, "cidr": None}
    if not segments:
        for s in ("EXTERN", "INTERN"):
            segments[s] = {"exposure": s, "cidr": None}

    # Asset-Counts
    asset_counts: dict[str, int] = {}
    for net in ip_networks:
        c = (await session.execute(
            select(func.count()).where(Asset.network_id == net.id, Asset.is_active == True)
        )).scalar() or 0
        asset_counts[net.name] = c

    # ── Graph aufbauen (nur Segmentnamen, Routers kommen später) ─────────────
    # Kanten zwischen Segmenten: aus Gateways + Router-Zonen
    seg_edges: list[tuple[str, str, str, bool, str | None, str | None]] = []
    # (seg_a, seg_b, label, is_primary, hostname, ip)

    for gw in gateways:
        a_asset = await session.get(Asset, gw.asset_id)
        seg_edges.append((
            gw.from_segment, gw.to_segment,
            gw.name, gw.is_primary,
            a_asset.hostname if a_asset else None,
            a_asset.ip_address if a_asset else None,
        ))

    for asset in router_assets:
        zones = [z for z in (asset.network_zones or []) if z in segments]
        if len(zones) < 2:
            continue
        label = asset.hostname or asset.ip_address or str(asset.id)
        for z1, z2 in _comb(sorted(set(zones)), 2):
            seg_edges.append((z1, z2, label, False, asset.hostname, asset.ip_address))

    # ── Level per BFS berechnen ──────────────────────────────────────────────
    # Start: EXTERN-Segmente → Level 0, dann BFS über Segment-Edges
    seg_level: dict[str, int] = {}

    # Initiale Level aus Exposure
    for name, info in segments.items():
        exp = info.get("exposure") or ""
        seg_level[name] = EXPOSURE_BASE.get(exp, 6)

    # BFS: Level propagieren (verbundenes Segment = max(bekannt, Nachbar+2))
    adjacency: dict[str, set[str]] = defaultdict(set)
    for a, b, *_ in seg_edges:
        adjacency[a].add(b)
        adjacency[b].add(a)

    # Normalisieren: kleinster Level = 0
    if seg_level:
        min_l = min(seg_level.values())
        seg_level = {k: v - min_l for k, v in seg_level.items()}

    # ── Router-Nodes erstellen mit Level zwischen ihren Segmenten ────────────
    router_by_asset: dict[str, TopologyNode] = {}
    all_nodes: list[TopologyNode] = []
    all_edges: list[TopologyEdge] = []

    # Segmente als Nodes
    connected_segs: set[str] = set()
    for a, b, *_ in seg_edges:
        connected_segs.add(a)
        connected_segs.add(b)

    for name, info in segments.items():
        all_nodes.append(TopologyNode(
            id=f"seg-{name}",
            type="segment",
            label=name,
            exposure=info.get("exposure"),
            cidr=info.get("cidr"),
            asset_count=asset_counts.get(name, 0),
            connected=name in connected_segs,
            level=seg_level.get(name, 4),
        ))

    # Router als Nodes: Level = Durchschnitt der verbundenen Segment-Level
    seen_routers: set[str] = set()

    for asset in router_assets:
        zones = [z for z in (asset.network_zones or []) if z in segments]
        if len(zones) < 2:
            continue

        router_id = f"router-{asset.id}"
        if router_id in seen_routers:
            continue
        seen_routers.add(router_id)

        zone_levels = [seg_level.get(z, 4) for z in zones]
        # Router sitzt zwischen min und max Level seiner Zonen
        router_level = (min(zone_levels) + max(zone_levels)) // 2 + 1

        label = asset.hostname or asset.ip_address or str(asset.id)
        all_nodes.append(TopologyNode(
            id=router_id,
            type=asset.asset_type,
            label=label,
            asset_id=str(asset.id),
            asset_type=asset.asset_type,
            asset_ip=asset.ip_address,
            connected=True,
            level=router_level,
        ))
        router_by_asset[str(asset.id)] = all_nodes[-1]

        # Kanten: Router ↔ jede seiner Zonen
        for zone in sorted(set(zones)):
            zone_lv = seg_level.get(zone, 4)
            # Richtung: von externalem Segment zu internem
            if zone_lv <= router_level:
                all_edges.append(TopologyEdge(
                    from_id=f"seg-{zone}", to_id=router_id,
                    gateway_name=label, is_primary=False,
                    asset_hostname=asset.hostname, asset_ip=asset.ip_address,
                ))
            else:
                all_edges.append(TopologyEdge(
                    from_id=router_id, to_id=f"seg-{zone}",
                    gateway_name=label, is_primary=False,
                    asset_hostname=asset.hostname, asset_ip=asset.ip_address,
                ))

    # Explizite Gateways als Edges ergänzen (primär-Flag)
    for gw in gateways:
        a_asset = await session.get(Asset, gw.asset_id)
        router_id = f"router-{gw.asset_id}"
        from_id = f"seg-{gw.from_segment}" if f"seg-{gw.from_segment}" in {n.id for n in all_nodes} else router_id
        to_id   = f"seg-{gw.to_segment}"   if f"seg-{gw.to_segment}"   in {n.id for n in all_nodes} else router_id
        # Primäre Gateways als separate Kante mit is_primary=True markieren
        if gw.is_primary:
            all_edges.append(TopologyEdge(
                from_id=from_id, to_id=to_id,
                gateway_name=gw.name, is_primary=True,
                asset_hostname=a_asset.hostname if a_asset else None,
                asset_ip=a_asset.ip_address if a_asset else None,
            ))

    return TopologyDiagram(nodes=all_nodes, edges=all_edges)
