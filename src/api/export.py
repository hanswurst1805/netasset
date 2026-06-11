"""
Betriebsleitfaden Export API

Stellt Systemdaten in einem strukturierten Format bereit das
direkt in Betriebsleitfäden, CMDB-Tools oder andere Systeme
importiert werden kann.

Endpunkte:
  GET /api/v1/export/systems          – Systemliste (JSON)
  GET /api/v1/export/systems.csv      – Systemliste (CSV)
  GET /api/v1/export/system/{id}      – Einzelsystem mit allen Details
  GET /api/v1/export/openapi          – Schema-Beschreibung

Authentifizierung: X-API-Key Header (aus DRUCKER → Einstellungen → API Keys)
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.models.all_models import (
    Asset, BusinessProcess, CVEImpact, IpNetwork,
    NetworkGateway, Owner, ProcessAsset, SBOMEntry,
)
from src.rag.cve_impact import _is_vm, _is_vm_irrelevant_pkg

router = APIRouter()


# ---------------------------------------------------------------------------
# Schema – Betriebsleitfaden-Systemdatensatz
# ---------------------------------------------------------------------------

class BLSystemKontakt(BaseModel):
    name: str
    email: Optional[str]
    team: Optional[str]
    abteilung: Optional[str]
    rolle: Optional[str]


class BLNetzwerk(BaseModel):
    exposure_level: str           # INTERN | DMZ | EXTERN
    primäres_netz: Optional[str]  # Netzwerkname
    cidr: Optional[str]
    zonen: list[str]
    offene_ports: list[dict]


class BLSicherheit(BaseModel):
    cve_high: int
    cve_medium: int
    cve_low: int
    kev_count: int                # Aktiv ausgenutzte CVEs
    lynis_score: Optional[int]
    reboot_erforderlich: bool
    ausstehende_updates: Optional[int]
    ausstehende_security_updates: Optional[int]


class BLProzess(BaseModel):
    name: str
    kritikalitaet: int
    sla_rto_stunden: Optional[int]
    sla_rpo_stunden: Optional[int]
    rolle_im_prozess: Optional[str]


class BLSystem(BaseModel):
    """Vollständiger Systemdatensatz für den Betriebsleitfaden."""
    # Identifikation
    id: str
    hostname: Optional[str]
    ip_adresse: Optional[str]
    weitere_ips: list[str]
    fqdn: Optional[str]
    mac_adresse: Optional[str]
    seriennummer: Optional[str]

    # Klassifikation
    system_typ: str               # server | client | router | switch | firewall
    hersteller: Optional[str]
    modell: Optional[str]

    # Betriebssystem
    os_name: Optional[str]
    os_version: Optional[str]
    firmware: Optional[str]

    # Standort
    standort: Optional[str]
    rack: Optional[str]

    # Netzwerk
    netzwerk: BLNetzwerk

    # Verantwortlichkeiten
    kontakte: list[BLKontakt]

    # Geschäftsprozesse
    prozesse: list[BLProzess]

    # Sicherheit
    sicherheit: BLSicherheit

    # Inventar
    software_count: int
    tags: list[str]

    # Metadaten
    zuletzt_gesehen: Optional[datetime]
    quelle: list[str]             # Woher stammen die Daten
    erstellt_am: Optional[datetime]
    aktualisiert_am: Optional[datetime]


# Alias für das Schema
BLKontakt = BLSystemKontakt


class BLSystemliste(BaseModel):
    """Antwort der Systemliste."""
    meta: dict
    systeme: list[BLSystem]


# ---------------------------------------------------------------------------
# Schema-Endpunkt
# ---------------------------------------------------------------------------

@router.get("/openapi")
async def get_schema():
    """Beschreibt das Format der Systemdaten für den Import."""
    return {
        "version": "1.0",
        "beschreibung": "DRUCKER Betriebsleitfaden Export API",
        "felder": {
            "id": "UUID des Systems (stabil, nie verändert)",
            "hostname": "Hostname",
            "ip_adresse": "Primäre IP-Adresse",
            "weitere_ips": "Weitere IP-Adressen (z.B. Management-IP, WAN-IP)",
            "system_typ": "server | client | router | switch | firewall | printer",
            "os_name": "Betriebssystem (z.B. Ubuntu, Windows Server)",
            "os_version": "Version des Betriebssystems",
            "netzwerk.exposure_level": "INTERN | DMZ | EXTERN",
            "netzwerk.primäres_netz": "Name des primären Netzwerks",
            "sicherheit.cve_high": "Anzahl kritischer CVEs",
            "sicherheit.kev_count": "Anzahl aktiv ausgenutzter CVEs (CISA KEV)",
            "sicherheit.reboot_erforderlich": "true wenn Neustart aussteht",
            "prozesse": "Zugeordnete Geschäftsprozesse mit Kritikalität",
            "kontakte": "Verantwortliche Personen/Teams",
        },
        "authentifizierung": "X-API-Key Header",
        "beispiel_aufruf": "GET /api/v1/export/systems?netz=LAN@HOME",
        "filter": {
            "netz": "Netzwerkname (z.B. LAN@HOME)",
            "exposure": "INTERN | DMZ | EXTERN",
            "typ": "server | router | client ...",
            "tag": "beliebiger Tag",
        }
    }


# ---------------------------------------------------------------------------
# Hilfsfunktion: Asset → BLSystem
# ---------------------------------------------------------------------------

async def _asset_to_bl(asset: Asset, session: AsyncSession) -> BLSystem:
    """Wandelt ein Asset in einen Betriebsleitfaden-Datensatz um."""

    # Primäres Netzwerk
    netz = await session.get(IpNetwork, asset.network_id) if asset.network_id else None

    # CVE-Statistik (Microcode-/Firmware-CVEs auf VMs sind hier nicht
    # exploitierbar und werden für den Betriebsleitfaden ausgeblendet)
    is_vm_asset = _is_vm(asset)

    cve_result = await session.execute(
        select(CVEImpact.risk_level, CVEImpact.affected_pkg)
        .where(CVEImpact.asset_id == asset.id)
    )
    cve_counts: dict[str, int] = {}
    for row in cve_result:
        if is_vm_asset and _is_vm_irrelevant_pkg(row.affected_pkg or ""):
            continue
        cve_counts[row.risk_level] = cve_counts.get(row.risk_level, 0) + 1

    # KEV-Count (gleiche Ausblendung für Microcode/Firmware auf VMs)
    from src.models.all_models import CVEEntry
    kev_result = await session.execute(
        select(CVEImpact.affected_pkg)
        .select_from(CVEImpact)
        .join(CVEEntry, CVEImpact.cve_id == CVEEntry.cve_id)
        .where(CVEImpact.asset_id == asset.id, CVEEntry.is_kev == True)
    )
    kev_count = sum(
        1 for row in kev_result
        if not (is_vm_asset and _is_vm_irrelevant_pkg(row.affected_pkg or ""))
    )

    # Lynis-Score
    from src.models.all_models import AssetReport
    lynis_result = await session.execute(
        select(AssetReport)
        .where(AssetReport.asset_id == asset.id, AssetReport.report_type == "lynis")
        .order_by(desc(AssetReport.created_at))
        .limit(1)
    )
    lynis = lynis_result.scalar_one_or_none()
    lynis_score = lynis.parsed_data.get("hardening_index") if lynis else None

    # Update-Status aus Tags
    reboot = "reboot-required" in (asset.tags or [])
    updates = next((int(t.split(":")[1]) for t in (asset.tags or []) if t.startswith("updates:")), None)
    sec_updates = next((int(t.split(":")[1]) for t in (asset.tags or []) if t.startswith("security-updates:")), None)

    # Geschäftsprozesse
    pa_result = await session.execute(
        select(ProcessAsset).where(ProcessAsset.asset_id == asset.id)
    )
    prozesse = []
    for pa in pa_result.scalars().all():
        proc = await session.get(BusinessProcess, pa.process_id)
        if proc:
            prozesse.append(BLProzess(
                name=proc.name,
                kritikalitaet=proc.criticality,
                sla_rto_stunden=proc.sla_rto_hours,
                sla_rpo_stunden=proc.sla_rpo_hours,
                rolle_im_prozess=pa.role,
            ))

    # Kontakte (aus Prozess-Ownern)
    kontakte: list[BLSystemKontakt] = []
    seen_owners: set[str] = set()
    for pa in pa_result.scalars() if False else []:  # Reset iterator
        pass
    pa_result2 = await session.execute(
        select(ProcessAsset).where(ProcessAsset.asset_id == asset.id)
    )
    for pa in pa_result2.scalars().all():
        proc = await session.get(BusinessProcess, pa.process_id)
        if proc and proc.owner_id and str(proc.owner_id) not in seen_owners:
            owner = await session.get(Owner, proc.owner_id)
            if owner:
                seen_owners.add(str(proc.owner_id))
                kontakte.append(BLSystemKontakt(
                    name=owner.name,
                    email=owner.email,
                    team=owner.team,
                    abteilung=owner.department,
                    rolle=owner.role,
                ))

    # SBOM-Anzahl
    sbom_count = (await session.execute(
        select(func.count()).where(SBOMEntry.asset_id == asset.id)
    )).scalar() or 0

    # Quellen
    sources = [s.get("origin", "?") for s in (asset.sources or [])]

    return BLSystem(
        id=str(asset.id),
        hostname=asset.hostname,
        ip_adresse=asset.ip_address,
        weitere_ips=getattr(asset, "additional_ips", None) or [],
        fqdn=asset.fqdn,
        mac_adresse=asset.mac_address,
        seriennummer=asset.serial_number,
        system_typ=asset.asset_type,
        hersteller=asset.manufacturer,
        modell=asset.model,
        os_name=asset.os_name,
        os_version=asset.os_version,
        firmware=asset.firmware_version,
        standort=asset.location,
        rack=asset.rack_id,
        netzwerk=BLNetzwerk(
            exposure_level=asset.exposure_level,
            primäres_netz=netz.name if netz else None,
            cidr=netz.cidr if netz else None,
            zonen=asset.network_zones or [],
            offene_ports=asset.open_ports or [],
        ),
        kontakte=kontakte,
        prozesse=prozesse,
        sicherheit=BLSicherheit(
            cve_high=cve_counts.get("HIGH", 0),
            cve_medium=cve_counts.get("MEDIUM", 0),
            cve_low=cve_counts.get("LOW", 0),
            kev_count=kev_count,
            lynis_score=lynis_score,
            reboot_erforderlich=reboot,
            ausstehende_updates=updates,
            ausstehende_security_updates=sec_updates,
        ),
        software_count=sbom_count,
        tags=[t for t in (asset.tags or []) if not t.startswith(("updates:", "security-updates:", "reboot"))],
        zuletzt_gesehen=asset.last_seen_at,
        quelle=sources,
        erstellt_am=asset.created_at,
        aktualisiert_am=asset.updated_at,
    )


# ---------------------------------------------------------------------------
# Systemliste
# ---------------------------------------------------------------------------

@router.get("/systems", response_model=BLSystemliste)
async def export_systems(
    netz: Optional[str] = Query(None, description="Filter nach Netzwerkname"),
    exposure: Optional[str] = Query(None, description="INTERN | DMZ | EXTERN"),
    typ: Optional[str] = Query(None, description="server | router | client ..."),
    tag: Optional[str] = Query(None, description="Beliebiger Tag"),
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """
    Systemliste für den Betriebsleitfaden.
    Enthält alle Systeme mit Netzwerk, Kontakten, Prozessen und Sicherheitsstatus.
    Archivierte Systeme werden nicht aufgeführt.
    """
    stmt = select(Asset).where(Asset.is_active == True, Asset.is_archived == False)

    if exposure:
        stmt = stmt.where(Asset.exposure_level == exposure)
    if typ:
        stmt = stmt.where(Asset.asset_type == typ)
    if tag:
        stmt = stmt.where(Asset.tags.contains([tag]))
    if netz:
        # Filter nach Netzwerkname (aus network_zones oder primärem Netz)
        netz_result = await session.execute(
            select(IpNetwork.id).where(IpNetwork.name == netz)
        )
        netz_id = netz_result.scalar_one_or_none()
        if netz_id:
            stmt = stmt.where(
                or_(Asset.network_id == netz_id, Asset.network_zones.contains([netz]))
            )

    if allowed := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(allowed))

    stmt = stmt.order_by(Asset.hostname)
    result = await session.execute(stmt)
    assets = result.scalars().all()

    systeme = []
    for asset in assets:
        systeme.append(await _asset_to_bl(asset, session))

    return BLSystemliste(
        meta={
            "erstellt_am": datetime.utcnow().isoformat(),
            "quelle": "DRUCKER Infrastructure Intelligence",
            "version": "1.0",
            "anzahl_systeme": len(systeme),
            "filter": {
                "netz": netz, "exposure": exposure, "typ": typ, "tag": tag
            },
        },
        systeme=systeme,
    )


@router.get("/systems.csv")
async def export_systems_csv(
    netz: Optional[str] = Query(None),
    exposure: Optional[str] = Query(None),
    typ: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """CSV-Export für direkte Tabellenimports."""
    stmt = select(Asset).where(Asset.is_active == True, Asset.is_archived == False)
    if exposure:
        stmt = stmt.where(Asset.exposure_level == exposure)
    if typ:
        stmt = stmt.where(Asset.asset_type == typ)
    if allowed := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(allowed))
    stmt = stmt.order_by(Asset.hostname)

    result = await session.execute(stmt)
    assets = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow([
        "ID", "Hostname", "IP", "Typ", "OS", "OS-Version",
        "Exposure", "Netzwerk", "Standort", "Hersteller", "Modell",
        "CVEs HIGH", "CVEs MED", "KEV", "Lynis", "Reboot", "Updates",
        "Zuletzt gesehen", "Tags",
    ])

    for asset in assets:
        bl = await _asset_to_bl(asset, session)
        writer.writerow([
            bl.id, bl.hostname or "", bl.ip_adresse or "",
            bl.system_typ, bl.os_name or "", bl.os_version or "",
            bl.netzwerk.exposure_level, bl.netzwerk.primäres_netz or "",
            bl.standort or "", bl.hersteller or "", bl.modell or "",
            bl.sicherheit.cve_high, bl.sicherheit.cve_medium,
            bl.sicherheit.kev_count,
            bl.sicherheit.lynis_score or "",
            "Ja" if bl.sicherheit.reboot_erforderlich else "Nein",
            bl.sicherheit.ausstehende_updates or "",
            bl.zuletzt_gesehen.strftime("%Y-%m-%d %H:%M") if bl.zuletzt_gesehen else "",
            ", ".join(bl.tags),
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),  # UTF-8 mit BOM für Excel
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="drucker-systeme.csv"'},
    )


@router.get("/system/{system_id}", response_model=BLSystem)
async def export_system(
    system_id: str,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Vollständige Systemdaten für ein einzelnes System."""
    asset = await session.get(Asset, uuid.UUID(system_id))
    if not asset or not asset.is_active or asset.is_archived:
        raise HTTPException(404, f"System {system_id} nicht gefunden")

    if allowed := ctx.filter_tags():
        if not asset.tags or not set(asset.tags) & set(allowed):
            raise HTTPException(403, "Kein Zugriff auf dieses System")

    return await _asset_to_bl(asset, session)
