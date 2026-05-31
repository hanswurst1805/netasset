"""
Asset Karteikarten-Generator für RAG/LLM-Training.

Erzeugt strukturierte Textdokumente aus Asset-Daten nach konfigurierbaren
Templates. Jede Karteikarte ist ein in sich geschlossenes Dokument das
alle relevanten Informationen zu einem Asset enthält.

Templates definieren welche Abschnitte enthalten sind und in welchem Format.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models.all_models import (
    Asset, AssetReport, BusinessProcess, CVEEntry, CVEImpact,
    IpNetwork, Owner, ProcessAsset, SBOMEntry,
)


# ---------------------------------------------------------------------------
# Template-Definitionen
# ---------------------------------------------------------------------------

@dataclass
class CardSection:
    key: str
    title: str
    enabled: bool = True


@dataclass
class CardTemplate:
    id: str
    name: str
    description: str
    sections: list[CardSection]
    output_format: str = "markdown"  # markdown | json | text


TEMPLATES: dict[str, CardTemplate] = {
    "full": CardTemplate(
        id="full",
        name="Vollständig",
        description="Alle verfügbaren Informationen — optimal für allgemeines RAG",
        sections=[
            CardSection("header", "Basis-Informationen"),
            CardSection("network", "Netzwerk & Exposure"),
            CardSection("ports", "Offene Ports"),
            CardSection("software", "Installierte Software (SBOM)"),
            CardSection("cve", "Sicherheitsrisiken (CVEs)"),
            CardSection("business", "Business-Kontext"),
            CardSection("lynis", "Sicherheits-Audit"),
            CardSection("meta", "Metadaten"),
        ],
    ),
    "security": CardTemplate(
        id="security",
        name="Security-fokussiert",
        description="Ports, CVEs, Exposure — für Security-RAG",
        sections=[
            CardSection("header", "Basis-Informationen"),
            CardSection("network", "Netzwerk & Exposure"),
            CardSection("ports", "Offene Ports"),
            CardSection("cve", "Sicherheitsrisiken (CVEs)"),
            CardSection("lynis", "Sicherheits-Audit"),
        ],
    ),
    "inventory": CardTemplate(
        id="inventory",
        name="Inventar",
        description="Hardware, OS, Software — für Inventar-RAG",
        sections=[
            CardSection("header", "Basis-Informationen"),
            CardSection("network", "Netzwerk"),
            CardSection("software", "Installierte Software (SBOM)"),
            CardSection("meta", "Metadaten"),
        ],
    ),
    "network": CardTemplate(
        id="network",
        name="Netzwerk",
        description="Netzwerk-Topologie und Connectivity — für Netzwerk-RAG",
        sections=[
            CardSection("header", "Basis-Informationen"),
            CardSection("network", "Netzwerk & Exposure"),
            CardSection("ports", "Offene Ports"),
            CardSection("business", "Business-Kontext"),
        ],
    ),
    "minimal": CardTemplate(
        id="minimal",
        name="Minimal",
        description="Nur Basis-Infos — für kompakte Embeddings",
        sections=[
            CardSection("header", "Basis-Informationen"),
            CardSection("network", "Netzwerk"),
        ],
    ),
}


# ---------------------------------------------------------------------------
# Daten laden
# ---------------------------------------------------------------------------

@dataclass
class AssetCardData:
    asset: Asset
    sbom: list[SBOMEntry] = field(default_factory=list)
    cve_impacts: list[tuple[CVEImpact, Optional[CVEEntry]]] = field(default_factory=list)
    processes: list[tuple[BusinessProcess, Optional[Owner]]] = field(default_factory=list)
    network: Optional[IpNetwork] = None
    lynis_score: Optional[int] = None
    lynis_warnings: int = 0
    lynis_suggestions: int = 0


async def load_asset_data(asset_id: str, session: AsyncSession) -> Optional[AssetCardData]:
    """Lädt alle relevanten Daten für eine Karteikarte."""
    import uuid
    asset = await session.get(
        Asset, uuid.UUID(asset_id),
        options=[selectinload(Asset.sbom_entries), selectinload(Asset.cve_impacts)]
    )
    if not asset:
        return None

    data = AssetCardData(asset=asset)
    data.sbom = asset.sbom_entries

    # CVE-Impacts mit CVE-Details
    for impact in asset.cve_impacts:
        cve = await session.get(CVEEntry, impact.cve_id)
        data.cve_impacts.append((impact, cve))
    data.cve_impacts.sort(key=lambda x: x[0].risk_score or 0, reverse=True)

    # Business-Prozesse
    pa_result = await session.execute(
        select(ProcessAsset).where(ProcessAsset.asset_id == asset.id)
    )
    for pa in pa_result.scalars().all():
        proc = await session.get(BusinessProcess, pa.process_id)
        if proc:
            owner = await session.get(Owner, proc.owner_id) if proc.owner_id else None
            data.processes.append((proc, owner))

    # Primäres Netzwerk
    if asset.network_id:
        data.network = await session.get(IpNetwork, asset.network_id)

    # Lynis-Report (neuester)
    from src.models.all_models import AssetReport
    report_result = await session.execute(
        select(AssetReport)
        .where(AssetReport.asset_id == asset.id, AssetReport.report_type == "lynis")
        .order_by(AssetReport.created_at.desc())
        .limit(1)
    )
    report = report_result.scalar_one_or_none()
    if report and report.parsed_data:
        data.lynis_score = report.parsed_data.get("hardening_index")
        data.lynis_warnings = len(report.parsed_data.get("warnings", []))
        data.lynis_suggestions = len(report.parsed_data.get("suggestions", []))

    return data


# ---------------------------------------------------------------------------
# Markdown-Generator
# ---------------------------------------------------------------------------

def _time_ago(dt: Optional[datetime]) -> str:
    if not dt:
        return "unbekannt"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = datetime.now(timezone.utc) - dt
    h = int(diff.total_seconds() / 3600)
    if h < 1: return "vor weniger als 1 Stunde"
    if h < 24: return f"vor {h} Stunden"
    d = h // 24
    return f"vor {d} Tag{'en' if d > 1 else ''}"


def generate_markdown(data: AssetCardData, template: CardTemplate) -> str:
    """Erzeugt eine Markdown-Karteikarte."""
    asset = data.asset
    sections = {s.key: s for s in template.sections if s.enabled}
    lines: list[str] = []

    # Titel
    name = asset.hostname or asset.ip_address or str(asset.id)
    lines.append(f"# Asset-Karteikarte: {name}")
    lines.append(f"*Erstellt: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Template: {template.name}*")
    lines.append("")

    # Header
    if "header" in sections:
        lines.append("## Basis-Informationen")
        lines.append(f"- **Hostname:** {asset.hostname or '—'}")
        lines.append(f"- **IP-Adresse:** {asset.ip_address or '—'}")
        if getattr(asset, "additional_ips", None):
            lines.append(f"- **Weitere IPs:** {', '.join(asset.additional_ips)}")
        lines.append(f"- **FQDN:** {asset.fqdn or '—'}")
        lines.append(f"- **MAC-Adresse:** {asset.mac_address or '—'}")
        lines.append(f"- **Asset-Typ:** {asset.asset_type}")
        lines.append(f"- **Hersteller/Modell:** {asset.manufacturer or '—'} {asset.model or ''}")
        lines.append(f"- **Betriebssystem:** {asset.os_name or '—'} {asset.os_version or ''} {asset.os_arch or ''}")
        if asset.firmware_version:
            lines.append(f"- **Firmware:** {asset.firmware_version}")
        if asset.location:
            lines.append(f"- **Standort:** {asset.location}")
        if asset.serial_number:
            lines.append(f"- **Seriennummer:** {asset.serial_number}")
        lines.append("")

    # Netzwerk
    if "network" in sections:
        lines.append("## Netzwerk & Exposure")
        lines.append(f"- **Exposure-Level:** {asset.exposure_level}")
        if data.network:
            lines.append(f"- **Primäres Netzwerk:** {data.network.name} ({data.network.cidr})")
        zones = asset.network_zones or []
        if zones:
            lines.append(f"- **Netzwerk-Zonen:** {', '.join(zones)}")
        lines.append("")

    # Ports
    if "ports" in sections and asset.open_ports:
        lines.append("## Offene Ports")
        lines.append("| Port | Protokoll | Erreichbar von |")
        lines.append("|------|-----------|----------------|")
        for p in (asset.open_ports or []):
            reach = ", ".join(p.get("reachable_from", ["—"]))
            svc = p.get("service") or ""
            label = f"{p['port']}/{p.get('proto','tcp')}"
            if svc:
                label += f" ({svc})"
            lines.append(f"| {label} | {p.get('proto','tcp')} | {reach} |")
        lines.append("")

    # SBOM
    if "software" in sections and data.sbom:
        lines.append(f"## Installierte Software ({len(data.sbom)} Pakete)")
        # Grupiert nach Typ
        by_type: dict[str, list[SBOMEntry]] = {}
        for e in data.sbom:
            t = e.pkg_type or "sonstige"
            by_type.setdefault(t, []).append(e)
        for typ, pkgs in sorted(by_type.items()):
            lines.append(f"\n**{typ.title()}:**")
            for p in sorted(pkgs, key=lambda x: x.pkg_name):
                cpe = f" `{p.cpe}`" if p.cpe else ""
                lines.append(f"- {p.pkg_name} {p.pkg_version}{cpe}")
        lines.append("")

    # CVE-Risiken
    if "cve" in sections and data.cve_impacts:
        high = [(i, c) for i, c in data.cve_impacts if i.risk_level == "HIGH"]
        med  = [(i, c) for i, c in data.cve_impacts if i.risk_level == "MEDIUM"]
        low  = [(i, c) for i, c in data.cve_impacts if i.risk_level == "LOW"]

        lines.append(f"## Sicherheitsrisiken (CVEs)")
        lines.append(f"**Zusammenfassung:** {len(high)} HIGH | {len(med)} MEDIUM | {len(low)} LOW")
        lines.append("")

        if high or med:
            lines.append("| CVE-ID | CVSS | Schwere | Risk-Score | Paket | Version |")
            lines.append("|--------|------|---------|------------|-------|---------|")
            for impact, cve in (high + med)[:20]:
                cvss = f"{cve.cvss_score:.1f}" if cve and cve.cvss_score else "—"
                lines.append(
                    f"| {impact.cve_id} | {cvss} | {impact.risk_level} | "
                    f"{impact.risk_score:.1f} | {impact.affected_pkg or '—'} | "
                    f"{impact.affected_ver or '—'} |"
                )
            if len(data.cve_impacts) > 20:
                lines.append(f"| ... | | | | +{len(data.cve_impacts)-20} weitere | |")
        lines.append("")

    # Business-Kontext
    if "business" in sections and data.processes:
        lines.append("## Business-Kontext")
        for proc, owner in data.processes:
            lines.append(f"\n**Prozess:** {proc.name} (Kritikalität {proc.criticality}/5)")
            if proc.description:
                lines.append(f"  {proc.description}")
            if owner:
                lines.append(f"  Owner: {owner.name}"
                             + (f" ({owner.team})" if owner.team else ""))
            if proc.sla_rto_hours:
                lines.append(f"  SLA RTO: {proc.sla_rto_hours}h")
        lines.append("")

    # Lynis
    if "lynis" in sections and data.lynis_score is not None:
        score_label = (
            "GUT" if data.lynis_score >= 80 else
            "MITTEL" if data.lynis_score >= 60 else "NIEDRIG"
        )
        lines.append("## Sicherheits-Audit (Lynis)")
        lines.append(f"- **Hardening-Index:** {data.lynis_score}/100 ({score_label})")
        lines.append(f"- **Warnings:** {data.lynis_warnings}")
        lines.append(f"- **Verbesserungsvorschläge:** {data.lynis_suggestions}")
        lines.append("")

    # Metadaten
    if "meta" in sections:
        lines.append("## Metadaten")
        lines.append(f"- **Asset-ID:** `{asset.id}`")
        lines.append(f"- **Zuletzt gesehen:** {_time_ago(asset.last_seen_at)}")
        lines.append(f"- **Erstellt:** {asset.created_at.strftime('%Y-%m-%d') if asset.created_at else '—'}")
        if asset.tags:
            lines.append(f"- **Tags:** {', '.join(asset.tags)}")
        if asset.sources:
            sources = ", ".join(s.get("origin", "?") for s in (asset.sources or []))
            lines.append(f"- **Quellen:** {sources}")
        lines.append("")

    return "\n".join(lines)


def generate_json(data: AssetCardData, template: CardTemplate) -> dict:
    """Erzeugt eine strukturierte JSON-Karteikarte."""
    asset = data.asset
    sections = {s.key for s in template.sections if s.enabled}

    card: dict[str, Any] = {
        "id": str(asset.id),
        "template": template.id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    if "header" in sections:
        card["asset"] = {
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "additional_ips": getattr(asset, "additional_ips", None) or [],
            "fqdn": asset.fqdn,
            "mac_address": asset.mac_address,
            "asset_type": asset.asset_type,
            "manufacturer": asset.manufacturer,
            "model": asset.model,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "os_arch": asset.os_arch,
            "firmware_version": asset.firmware_version,
            "location": asset.location,
            "serial_number": asset.serial_number,
        }

    if "network" in sections:
        card["network"] = {
            "exposure_level": asset.exposure_level,
            "primary_network": {"name": data.network.name, "cidr": data.network.cidr} if data.network else None,
            "network_zones": asset.network_zones or [],
        }

    if "ports" in sections:
        card["open_ports"] = asset.open_ports or []

    if "software" in sections:
        card["sbom"] = [
            {"name": e.pkg_name, "version": e.pkg_version, "type": e.pkg_type, "cpe": e.cpe}
            for e in data.sbom
        ]

    if "cve" in sections:
        card["cve_impacts"] = [
            {
                "cve_id": i.cve_id,
                "risk_level": i.risk_level,
                "risk_score": i.risk_score,
                "cvss_score": cve.cvss_score if cve else None,
                "affected_pkg": i.affected_pkg,
                "affected_ver": i.affected_ver,
            }
            for i, cve in data.cve_impacts
        ]

    if "business" in sections:
        card["business_processes"] = [
            {
                "name": p.name,
                "criticality": p.criticality,
                "owner": owner.name if owner else None,
            }
            for p, owner in data.processes
        ]

    if "lynis" in sections and data.lynis_score is not None:
        card["security_audit"] = {
            "hardening_index": data.lynis_score,
            "warnings": data.lynis_warnings,
            "suggestions": data.lynis_suggestions,
        }

    if "meta" in sections:
        card["meta"] = {
            "tags": asset.tags or [],
            "sources": [s.get("origin") for s in (asset.sources or [])],
            "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
        }

    return card


def generate_card(data: AssetCardData, template: CardTemplate, fmt: str = "markdown") -> str:
    """Erzeugt eine Karteikarte im gewünschten Format."""
    if fmt == "json":
        return json.dumps(generate_json(data, template), ensure_ascii=False, indent=2)
    elif fmt == "text":
        # Markdown ohne Formatierung
        md = generate_markdown(data, template)
        import re
        text = re.sub(r'[#*`|]', '', md)
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()
    else:
        return generate_markdown(data, template)
