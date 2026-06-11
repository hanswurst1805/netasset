"""OBASHI-Struktur API – liefert den vollständigen Schichten-Baum eines Prozesses.

Korrekte OBASHI-Schichten:
  O – Owners:         Personen / Teams / Abteilungen
  B – Business:       Geschäftsprozesse / Services
  A – Application:    Fachliche Anwendungen (Webshop, CRM, ERP) – KEINE Software-Pakete
  S – System:         OS + Middleware + Schlüssel-Software (aus SBOM)
  H – Hardware:       Physische / Virtuelle Maschinen (Assets)
  I – Infrastructure: Netzwerk, Exposure, Ports, Firewall
"""

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
from src.models.all_models import (
    Application, Asset, BusinessProcess, Owner, ProcessAsset, SBOMEntry
)

router = APIRouter()

# System-relevante Pakete für S-Layer (alles andere im SBOM wird weggefiltert)
SYSTEM_PKG_NAMES = {
    "nginx", "apache2", "httpd", "lighttpd",
    "postgresql", "mysql", "mariadb", "sqlite3", "redis", "mongodb",
    "openssh-server", "sshd", "openssl", "libssl",
    "docker", "containerd", "podman",
    "python3", "python", "java", "openjdk", "nodejs", "node", "ruby",
    "php", "php-fpm",
    "kernel", "linux-image",
    "haproxy", "traefik", "envoy",
}


class OBASHINode(BaseModel):
    id: str
    label: str
    sublabel: Optional[str] = None
    layer: str
    meta: dict = {}


class OBASHIEdge(BaseModel):
    from_id: str
    to_id: str


class OBASHIDiagram(BaseModel):
    process_id: str
    process_name: str
    nodes: list[OBASHINode]
    edges: list[OBASHIEdge]


@router.get("/processes/{process_id}/obashi", response_model=OBASHIDiagram)
async def get_obashi(
    process_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    # Prozess + Owner laden
    process = await session.get(BusinessProcess, process_id)
    if not process:
        raise HTTPException(404, f"Prozess {process_id} nicht gefunden")

    nodes: list[OBASHINode] = []
    edges: list[OBASHIEdge] = []

    # -----------------------------------------------------------------------
    # O – Owner des Prozesses
    # -----------------------------------------------------------------------
    owner_node_id = None
    if process.owner_id:
        owner = await session.get(Owner, process.owner_id)
        if owner:
            owner_node_id = f"O-{owner.id}"
            nodes.append(OBASHINode(
                id=owner_node_id,
                label=owner.name,
                sublabel=owner.team or owner.department,
                layer="O",
                meta={
                    "email": owner.email,
                    "team": owner.team,
                    "department": owner.department,
                    "role": owner.role,
                },
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
            "sla_rto_hours": process.sla_rto_hours,
            "sla_rpo_hours": process.sla_rpo_hours,
            "description": process.description,
        },
    ))
    if owner_node_id:
        edges.append(OBASHIEdge(from_id=owner_node_id, to_id=b_node_id))

    # -----------------------------------------------------------------------
    # A – Applications (fachliche Anwendungen aus DB)
    # -----------------------------------------------------------------------
    app_stmt = (
        select(Application)
        .where(Application.process_id == process_id, Application.is_active == True)
    )
    applications = (await session.execute(app_stmt)).scalars().all()

    # App-Owner Node-IDs sammeln (Deduplizierung)
    app_owner_ids: dict[uuid.UUID, str] = {}

    for app in applications:
        # App-spezifischer Owner (wenn abweichend vom Prozess-Owner)
        if app.owner_id and app.owner_id != process.owner_id:
            if app.owner_id not in app_owner_ids:
                app_owner = await session.get(Owner, app.owner_id)
                if app_owner:
                    aon_id = f"O-{app_owner.id}"
                    app_owner_ids[app.owner_id] = aon_id
                    if aon_id not in [n.id for n in nodes]:
                        nodes.append(OBASHINode(
                            id=aon_id,
                            label=app_owner.name,
                            sublabel=app_owner.team,
                            layer="O",
                            meta={"email": app_owner.email, "team": app_owner.team},
                        ))

        a_node_id = f"A-{app.id}"
        type_label = {
            "web": "🌐 Web",
            "api": "⚡ API",
            "batch": "⚙ Batch",
            "integration": "🔗 Integration",
            "service": "🔧 Service",
            "desktop": "🖥 Desktop",
            "mobile": "📱 Mobile",
        }.get(app.app_type or "", app.app_type or "App")

        nodes.append(OBASHINode(
            id=a_node_id,
            label=app.name,
            sublabel=f"{type_label}" + (f" · v{app.version}" if app.version else ""),
            layer="A",
            meta={
                "app_type": app.app_type,
                "version": app.version,
                "url": app.url,
                "criticality": app.criticality,
                "asset_ids": app.asset_ids or [],
                "description": app.description,
            },
        ))

        # Kante: B → A
        edges.append(OBASHIEdge(from_id=b_node_id, to_id=a_node_id))

        # Kante: App-Owner → A (wenn vorhanden)
        if app.owner_id and app.owner_id in app_owner_ids:
            edges.append(OBASHIEdge(from_id=app_owner_ids[app.owner_id], to_id=a_node_id))

    # -----------------------------------------------------------------------
    # Assets für H + S + I:
    # Quelle 1: asset_ids der Anwendungen (primär — über OBASHI-Editor verknüpft)
    # Quelle 2: process_assets (alt — direkte Prozess-Asset-Zuordnung)
    # -----------------------------------------------------------------------
    all_asset_ids: set[str] = set()

    # Quelle 1: aus den Anwendungen
    for app in applications:
        for aid in (app.asset_ids or []):
            all_asset_ids.add(str(aid))

    # Quelle 2: direkte Prozess-Assets (Fallback)
    pa_result = await session.execute(
        select(ProcessAsset).where(ProcessAsset.process_id == process_id)
    )
    for pa in pa_result.scalars().all():
        all_asset_ids.add(str(pa.asset_id))

    if all_asset_ids:
        import uuid as _uuid
        asset_stmt = (
            select(Asset)
            .where(
                Asset.id.in_([_uuid.UUID(aid) for aid in all_asset_ids]),
                Asset.is_active == True,
                Asset.is_archived == False,
            )
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
            sublabel=(f"{asset.manufacturer} {asset.model}".strip()
                      if asset.manufacturer else asset.asset_type),
            layer="H",
            meta={
                "asset_type": asset.asset_type,
                "ip_address": asset.ip_address,
                "mac_address": asset.mac_address,
                "serial_number": asset.serial_number,
                "location": asset.location,
                "firmware_version": asset.firmware_version,
            },
        ))

        # Kante: A → H (wenn App auf diesem Asset läuft)
        linked_to_app = False
        for app in applications:
            if app.asset_ids and str(asset.id) in [str(aid) for aid in app.asset_ids]:
                a_node_id = f"A-{app.id}"
                edges.append(OBASHIEdge(from_id=a_node_id, to_id=h_node_id))
                linked_to_app = True

        # Fallback: B → H wenn keine App verknüpft
        if not linked_to_app:
            edges.append(OBASHIEdge(from_id=b_node_id, to_id=h_node_id))

        # -------------------------------------------------------------------
        # S – System (OS + relevante System-Software aus SBOM)
        # -------------------------------------------------------------------
        if asset.os_name:
            s_node_id = f"S-{asset.id}"

            # System-relevante Pakete filtern
            sys_pkgs = [
                e for e in asset.sbom_entries
                if e.pkg_name.lower().split("-")[0] in SYSTEM_PKG_NAMES
                or e.pkg_name.lower() in SYSTEM_PKG_NAMES
            ]
            pkg_summary = ", ".join(
                f"{e.pkg_name} {e.pkg_version}" for e in sys_pkgs[:4]
            )
            if len(sys_pkgs) > 4:
                pkg_summary += f" +{len(sys_pkgs)-4}"

            nodes.append(OBASHINode(
                id=s_node_id,
                label=f"{asset.os_name} {asset.os_version or ''}".strip(),
                sublabel=pkg_summary or "Kein SBOM",
                layer="S",
                meta={
                    "os_name": asset.os_name,
                    "os_version": asset.os_version,
                    "os_arch": asset.os_arch,
                    "firmware": asset.firmware_version,
                    "sbom_total": len(asset.sbom_entries),
                    "system_packages": [
                        {"name": e.pkg_name, "version": e.pkg_version, "cpe": e.cpe}
                        for e in sys_pkgs
                    ],
                },
            ))
            edges.append(OBASHIEdge(from_id=h_node_id, to_id=s_node_id))

        # -------------------------------------------------------------------
        # I – Infrastructure
        # -------------------------------------------------------------------
        i_node_id = f"I-{asset.id}"
        ports = asset.open_ports or []
        extern_ports = [p for p in ports if "internet" in p.get("reachable_from", [])]
        port_str = ", ".join(str(p["port"]) for p in ports[:4])
        if len(ports) > 4:
            port_str += f" +{len(ports)-4}"

        nodes.append(OBASHINode(
            id=i_node_id,
            label=asset.exposure_level,
            sublabel=f"Ports: {port_str}" if port_str else "Keine Ports",
            layer="I",
            meta={
                "exposure_level": asset.exposure_level,
                "open_ports": ports,
                "extern_ports": extern_ports,
                "total_ports": len(ports),
            },
        ))
        edges.append(OBASHIEdge(from_id=h_node_id, to_id=i_node_id))

    return OBASHIDiagram(
        process_id=str(process_id),
        process_name=process.name,
        nodes=nodes,
        edges=edges,
    )
