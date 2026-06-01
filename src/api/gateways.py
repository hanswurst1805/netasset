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
    Baumstruktur-Topologie: INTERNET → Router → Netz → Router → Netz ...
    Jedes Netz kennt seinen Gateway-Router (gateway_asset_id).
    Router stehen zwischen den Netzen die sie verbinden.
    """
    from src.models.all_models import IpNetwork

    # ── Daten laden ──────────────────────────────────────────────────────────
    net_result = await session.execute(select(IpNetwork).order_by(IpNetwork.name))
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
    router_by_id = {str(a.id): a for a in router_assets}

    # Asset-Counts pro Netz
    asset_counts: dict[str, int] = {}
    for net in ip_networks:
        from sqlalchemy import or_
        c = (await session.execute(
            select(func.count()).where(
                Asset.is_active == True,
                or_(Asset.network_id == net.id, Asset.network_zones.contains([net.name]))
            )
        )).scalar() or 0
        asset_counts[net.name] = c

    # ── Baumstruktur aufbauen ─────────────────────────────────────────────────
    # Idee: jedes Netz kennt seinen gateway_asset_id (den Router nach oben)
    # Wir traversieren: INTERNET → Router → Netz → Router → Netz → ...
    # Level: INTERNET=0, Router=1, Netz=2, Router=3, Netz=4, ...

    all_nodes: list[TopologyNode] = []
    all_edges: list[TopologyEdge] = []
    seen_routers: set[str] = set()

    # INTERNET-Pseudo-Node immer oben
    all_nodes.append(TopologyNode(
        id="seg-INTERNET", type="segment", label="INTERNET",
        exposure="EXTERN", level=0, connected=True, asset_count=0,
    ))

    # ── Externe Netze (EXTERN) an INTERNET hängen ─────────────────────────────
    # Router der externe Netze verbindet → sitzt auf Level 1
    # Externe Netze selbst → Level 0 (direkt am INTERNET)

    for net in ip_networks:
        net_id = f"seg-{net.name}"
        if net.exposure_level == "EXTERN":
            # Externe Netze auf Level 0 (neben INTERNET)
            all_nodes.append(TopologyNode(
                id=net_id, type="segment", label=net.name,
                exposure="EXTERN", cidr=net.cidr,
                asset_count=asset_counts.get(net.name, 0),
                connected=True, level=0,
            ))
            all_edges.append(TopologyEdge(
                from_id="seg-INTERNET", to_id=net_id,
                gateway_name="Internet", is_primary=True,
            ))

    # ── Router traversieren: Router → verbundene Netze → Router → ... ─────────
    # Wir bauen den Baum per BFS-ähnlichem Traversal

    # Netz → sein Gateway-Router (aus gateway_asset_id oder network_zones)
    net_to_gateway: dict[str, str] = {}
    for net in ip_networks:
        if net.gateway_asset_id:
            net_to_gateway[net.name] = str(net.gateway_asset_id)

    # Router → welche Netze er bedient (downstream)
    router_to_nets: dict[str, list[str]] = {}
    for asset in router_assets:
        zones = asset.network_zones or []
        downstream = []
        for net in ip_networks:
            # Ein Netz ist downstream wenn dieser Router sein gateway ist
            if str(net.gateway_asset_id) == str(asset.id):
                downstream.append(net.name)
            # Oder: Router ist in diesem Netz UND nicht das externe Netz
            elif net.name in zones and net.exposure_level != "EXTERN":
                # Nur wenn kein expliziter gateway gesetzt
                if net.name not in net_to_gateway:
                    downstream.append(net.name)
        if downstream:
            router_to_nets[str(asset.id)] = list(set(downstream))

    # BFS: Starte bei Routern die EXTERN-Zonen haben (direkt am Internet)
    from collections import deque
    queue: deque = deque()
    placed_nets: set[str] = set()
    placed_routers: set[str] = set()

    # Extern-Netze sind schon platziert
    for net in ip_networks:
        if net.exposure_level == "EXTERN":
            placed_nets.add(net.name)

    # Finde Router die ein EXTERN-Netz in ihren Zonen haben → Level 1
    for asset in router_assets:
        zones = asset.network_zones or []
        has_extern = any(
            net.name in zones and net.exposure_level == "EXTERN"
            for net in ip_networks
        ) or any(z == "EXTERN" for z in zones)
        if has_extern and str(asset.id) not in placed_routers:
            queue.append((asset, 1))  # (asset, level)
            placed_routers.add(str(asset.id))

    # Auch Router ohne explizite EXTERN-Zone aber mit gateway_asset_id=None für EXTERN-Netze
    for asset in router_assets:
        aid = str(asset.id)
        if aid not in placed_routers:
            # Hat Router eine IP in einem EXTERN-Netz?
            for net in ip_networks:
                if net.exposure_level == "EXTERN" and net.gateway_asset_id == asset.id:
                    queue.append((asset, 1))
                    placed_routers.add(aid)
                    break

    visited_levels: dict[str, int] = {}

    while queue:
        asset, level = queue.popleft()
        aid = str(asset.id)
        router_id = f"router-{aid}"
        label = asset.hostname or asset.ip_address or str(aid)

        # Router-Node anlegen
        if router_id not in {n.id for n in all_nodes}:
            all_nodes.append(TopologyNode(
                id=router_id, type=asset.asset_type,
                label=label, asset_id=aid,
                asset_type=asset.asset_type, asset_ip=asset.ip_address,
                connected=True, level=level,
            ))

        # Kante vom übergeordneten Netz zu diesem Router
        # Übergeordnetes Netz = das EXTERN/externe Netz in den Zonen
        for zone in (asset.network_zones or []):
            zone_node_id = f"seg-{zone}"
            if zone_node_id in {n.id for n in all_nodes}:
                node_level = next((n.level for n in all_nodes if n.id == zone_node_id), 0)
                if node_level < level:
                    edge_exists = any(
                        e.from_id == zone_node_id and e.to_id == router_id
                        for e in all_edges
                    )
                    if not edge_exists:
                        all_edges.append(TopologyEdge(
                            from_id=zone_node_id, to_id=router_id,
                            gateway_name=label, is_primary=False,
                            asset_hostname=asset.hostname, asset_ip=asset.ip_address,
                        ))

        # Downstream-Netze dieses Routers anlegen
        downstream = router_to_nets.get(aid, [])
        for net_name in downstream:
            if net_name in placed_nets:
                continue
            placed_nets.add(net_name)
            net_id = f"seg-{net_name}"
            net_obj = next((n for n in ip_networks if n.name == net_name), None)
            net_lv = level + 1

            if net_id not in {n.id for n in all_nodes}:
                all_nodes.append(TopologyNode(
                    id=net_id, type="segment", label=net_name,
                    exposure=net_obj.exposure_level if net_obj else None,
                    cidr=net_obj.cidr if net_obj else None,
                    asset_count=asset_counts.get(net_name, 0),
                    connected=True, level=net_lv,
                ))
            all_edges.append(TopologyEdge(
                from_id=router_id, to_id=net_id,
                gateway_name=label, is_primary=False,
                asset_hostname=asset.hostname, asset_ip=asset.ip_address,
            ))

            # Gibt es einen Router der dieses Netz weiterverbindet?
            for next_asset in router_assets:
                next_aid = str(next_asset.id)
                if next_aid in placed_routers:
                    continue
                if net_name in (next_asset.network_zones or []):
                    # Dieser Router ist in diesem Netz
                    placed_routers.add(next_aid)
                    queue.append((next_asset, net_lv + 1))

    # ── Nicht verbundene Netze am Ende hinzufügen ─────────────────────────────
    for net in ip_networks:
        net_id = f"seg-{net.name}"
        if net_id not in {n.id for n in all_nodes}:
            all_nodes.append(TopologyNode(
                id=net_id, type="segment", label=net.name,
                exposure=net.exposure_level, cidr=net.cidr,
                asset_count=asset_counts.get(net.name, 0),
                connected=False, level=8,
            ))

    return TopologyDiagram(nodes=all_nodes, edges=all_edges)
