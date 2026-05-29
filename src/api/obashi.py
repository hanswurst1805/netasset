"""OBASHI-Struktur API – liefert den vollständigen Schichten-Baum eines Prozesses."""

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
from src.models.all_models import Asset, BusinessProcess, ProcessAsset, SBOMEntry
from src.models.auth import User

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class OBASHINode(BaseModel):
    id: str
    label: str
    sublabel: Optional[str] = None
    layer: str          # O B A S H I
    meta: dict = {}     # beliebige Zusatzinfos


class OBASHIEdge(BaseModel):
    from_id: str
    to_id: str


class OBASHIDiagram(BaseModel):
    process_id: str
    process_name: str
    nodes: list[OBASHINode]
    edges: list[OBASHIEdge]


# ---------------------------------------------------------------------------
# Endpunkt
# ---------------------------------------------------------------------------

@router.get("/processes/{process_id}/obashi", response_model=OBASHIDiagram)
async def get_obashi(
    process_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Liefert den OBASHI-Baum für einen Business-Prozess."""

    # Prozess laden
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")

    nodes: list[OBASHINode] = []
    edges: list[OBASHIEdge] = []

    # -----------------------------------------------------------------------
    # O – Owner
    # -----------------------------------------------------------------------
    owner_node_id = None
    if process.owner_id:
        owner = await session.get(User, process.owner_id)
        if owner:
            owner_node_id = f"O-{owner.id}"
            nodes.append(OBASHINode(
                id=owner_node_id,
                label=owner.username,
                sublabel=getattr(owner, "email", None),
                layer="O",
                meta={"role": "admin"},
            ))

    # -----------------------------------------------------------------------
    # B – Business Process
    # -----------------------------------------------------------------------
    b_node_id = f"B-{process.id}"
    nodes.append(OBASHINode(
        id=b_node_id,
        label=process.name,
        sublabel=f"Kritikalität {process.criticality}/5",
        layer="B",
        meta={
            "criticality": process.criticality,
            "sla_rto": process.sla_rto_hours,
            "sla_rpo": process.sla_rpo_hours,
            "description": process.description,
        },
    ))

    if owner_node_id:
        edges.append(OBASHIEdge(from_id=owner_node_id, to_id=b_node_id))

    # -----------------------------------------------------------------------
    # Assets des Prozesses laden (H + S + A + I)
    # -----------------------------------------------------------------------
    stmt = (
        select(ProcessAsset)
        .where(ProcessAsset.process_id == process_id)
    )
    pa_result = await session.execute(stmt)
    process_assets = pa_result.scalars().all()

    asset_ids = [pa.asset_id for pa in process_assets]

    if asset_ids:
        asset_stmt = (
            select(Asset)
            .where(Asset.id.in_(asset_ids))
            .options(selectinload(Asset.sbom_entries))
        )
        assets = (await session.execute(asset_stmt)).scalars().all()
    else:
        assets = []

    for asset in assets:
        # -------------------------------------------------------------------
        # H – Hardware
        # -------------------------------------------------------------------
        h_node_id = f"H-{asset.id}"
        nodes.append(OBASHINode(
            id=h_node_id,
            label=asset.hostname or str(asset.ip_address),
            sublabel=f"{asset.manufacturer or ''} {asset.model or ''}".strip() or asset.asset_type,
            layer="H",
            meta={
                "asset_type": asset.asset_type,
                "ip_address": asset.ip_address,
                "mac_address": asset.mac_address,
                "serial_number": asset.serial_number,
                "location": asset.location,
                "rack_id": asset.rack_id,
            },
        ))
        edges.append(OBASHIEdge(from_id=b_node_id, to_id=h_node_id))

        # -------------------------------------------------------------------
        # S – System (OS-Layer)
        # -------------------------------------------------------------------
        if asset.os_name:
            s_node_id = f"S-{asset.id}"
            nodes.append(OBASHINode(
                id=s_node_id,
                label=f"{asset.os_name} {asset.os_version or ''}".strip(),
                sublabel=asset.os_arch,
                layer="S",
                meta={
                    "os_name": asset.os_name,
                    "os_version": asset.os_version,
                    "os_arch": asset.os_arch,
                    "firmware": asset.firmware_version,
                    "pkg_count": len(asset.sbom_entries),
                },
            ))
            edges.append(OBASHIEdge(from_id=h_node_id, to_id=s_node_id))

            # ---------------------------------------------------------------
            # A – Application (aus SBOM: nur Typ "application" oder top-Pakete)
            # ---------------------------------------------------------------
            apps = [
                e for e in asset.sbom_entries
                if e.pkg_type in ("application", "firmware") or
                e.pkg_name.lower() in (
                    "nginx", "apache2", "httpd", "postgresql", "mysql",
                    "redis", "docker", "python3", "java", "nodejs", "node",
                    "openssl", "openssh-server", "sshd",
                )
            ]
            # Fallback: erste 5 Pakete wenn keine Apps erkannt
            if not apps:
                apps = asset.sbom_entries[:5]

            for app in apps[:8]:  # max 8 pro Asset
                a_node_id = f"A-{asset.id}-{app.pkg_name}"
                nodes.append(OBASHINode(
                    id=a_node_id,
                    label=app.pkg_name,
                    sublabel=app.pkg_version,
                    layer="A",
                    meta={
                        "version": app.pkg_version,
                        "type": app.pkg_type,
                        "cpe": app.cpe,
                        "purl": app.purl,
                        "source": app.source,
                    },
                ))
                edges.append(OBASHIEdge(from_id=s_node_id, to_id=a_node_id))

        # -------------------------------------------------------------------
        # I – Infrastructure (Exposure + Ports)
        # -------------------------------------------------------------------
        i_node_id = f"I-{asset.id}"
        port_summary = ""
        if asset.open_ports:
            ports = [str(p["port"]) for p in asset.open_ports[:5]]
            port_summary = "Ports: " + ", ".join(ports)
            if len(asset.open_ports) > 5:
                port_summary += f" +{len(asset.open_ports)-5}"

        nodes.append(OBASHINode(
            id=i_node_id,
            label=asset.exposure_level,
            sublabel=port_summary or "Keine offenen Ports",
            layer="I",
            meta={
                "exposure_level": asset.exposure_level,
                "open_ports": asset.open_ports or [],
                "vlan": None,
            },
        ))
        edges.append(OBASHIEdge(from_id=h_node_id, to_id=i_node_id))

    return OBASHIDiagram(
        process_id=str(process_id),
        process_name=process.name,
        nodes=nodes,
        edges=edges,
    )
