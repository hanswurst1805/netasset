"""
Baut einen vollständigen, strukturierten Asset-Kontext für das RAG-System.

Jedes Asset wird als "Kontext-Dokument" aufgebaut das alle relevanten Daten enthält:
- Basis-Infos (Hostname, IP, Typ, OS)
- Exposure + offene Ports
- SBOM (alle installierten Pakete)
- Bekannte CVE-Impacts

Der Kontext wird als strukturierter Text übergeben, damit das LLM
ausschließlich auf echten Daten basiert und nichts erfindet.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models.all_models import Asset, CVEImpact, SBOMEntry


def _format_asset(asset: Asset, sbom: list[SBOMEntry], impacts: list[CVEImpact]) -> str:
    """Erstellt ein strukturiertes Kontext-Dokument für ein einzelnes Asset."""
    lines = []
    lines.append(f"=== ASSET: {asset.hostname or asset.ip_address} ===")
    lines.append(f"ID: {asset.id}")
    lines.append(f"Typ: {asset.asset_type}")
    lines.append(f"Hostname: {asset.hostname or '—'}")
    lines.append(f"IP-Adresse: {asset.ip_address or '—'}")
    lines.append(f"FQDN: {asset.fqdn or '—'}")
    lines.append(f"Betriebssystem: {asset.os_name or '—'} {asset.os_version or ''}")
    lines.append(f"Hersteller/Modell: {asset.manufacturer or '—'} {asset.model or ''}")
    lines.append(f"Firmware: {asset.firmware_version or '—'}")
    lines.append(f"Exposure-Level: {asset.exposure_level}")
    lines.append(f"Tags: {', '.join(asset.tags or []) or '—'}")
    lines.append(f"Standort: {asset.location or '—'}")

    # Offene Ports
    if asset.open_ports:
        lines.append("Offene Ports:")
        for p in asset.open_ports:
            erreichbar = ", ".join(p.get("reachable_from", []))
            lines.append(f"  - Port {p['port']}/{p.get('proto','tcp')} erreichbar von: {erreichbar}")
    else:
        lines.append("Offene Ports: keine bekannt")

    # SBOM
    if sbom:
        lines.append(f"Installierte Software ({len(sbom)} Pakete):")
        for e in sbom:
            cpe_info = f" [CPE: {e.cpe}]" if e.cpe else ""
            lines.append(f"  - {e.pkg_name} {e.pkg_version} ({e.pkg_type or 'unbekannt'}){cpe_info}")
    else:
        lines.append("Installierte Software: kein SBOM vorhanden")

    # CVE-Impacts
    if impacts:
        lines.append(f"Bekannte CVE-Risiken ({len(impacts)} Einträge):")
        for i in impacts:
            lines.append(
                f"  - {i.cve_id}: {i.risk_level} (Score {i.risk_score:.1f})"
                f" betrifft {i.affected_pkg} {i.affected_ver}"
            )
    else:
        lines.append("Bekannte CVE-Risiken: keine berechnet")

    return "\n".join(lines)


async def build_full_context(
    session: AsyncSession,
    allowed_tags: list[str] | None = None,
) -> tuple[str, list[str]]:
    """
    Lädt alle aktiven Assets mit SBOM und CVE-Impacts und baut den Kontext.

    Returns:
        (context_text, asset_names) — Kontext-String und Liste der Asset-Namen
    """
    stmt = (
        select(Asset)
        .where(Asset.is_active == True, Asset.is_archived == False)
        .options(
            selectinload(Asset.sbom_entries),
            selectinload(Asset.cve_impacts),
        )
        .order_by(Asset.hostname)
    )

    # Tag-Filter für mandantenfähige Umgebungen
    if allowed_tags:
        stmt = stmt.where(Asset.tags.overlap(allowed_tags))

    result = await session.execute(stmt)
    assets = result.scalars().all()

    if not assets:
        return "Es sind keine Assets in der Datenbank vorhanden.", []

    docs = []
    names = []
    for asset in assets:
        doc = _format_asset(asset, asset.sbom_entries, asset.cve_impacts)
        docs.append(doc)
        names.append(asset.hostname or str(asset.ip_address))

    context = "\n\n".join(docs)
    return context, names


async def build_filtered_context(
    session: AsyncSession,
    keywords: list[str],
    allowed_tags: list[str] | None = None,
    max_assets: int = 15,
) -> tuple[str, list[str]]:
    """
    Lädt nur Assets die zu den Keywords passen (Hostname, IP, OS, Pakete).
    Für große Umgebungen effizienter als build_full_context.
    """
    from sqlalchemy import or_, func

    stmt = (
        select(Asset)
        .where(Asset.is_active == True, Asset.is_archived == False)
        .options(
            selectinload(Asset.sbom_entries),
            selectinload(Asset.cve_impacts),
        )
    )

    if allowed_tags:
        stmt = stmt.where(Asset.tags.overlap(allowed_tags))

    # Keyword-Filter auf wichtige Felder
    if keywords:
        filters = []
        for kw in keywords:
            kw_lower = f"%{kw.lower()}%"
            filters.extend([
                Asset.hostname.ilike(kw_lower),
                Asset.ip_address.ilike(kw_lower),
                Asset.os_name.ilike(kw_lower),
                Asset.asset_type.ilike(kw_lower),
                Asset.location.ilike(kw_lower),
            ])
        stmt = stmt.where(or_(*filters))

    stmt = stmt.limit(max_assets)
    result = await session.execute(stmt)
    assets = result.scalars().all()

    # Falls keine direkte Übereinstimmung: alle laden (bis max_assets)
    if not assets:
        stmt2 = (
            select(Asset)
            .where(Asset.is_active == True, Asset.is_archived == False)
            .options(
                selectinload(Asset.sbom_entries),
                selectinload(Asset.cve_impacts),
            )
            .limit(max_assets)
        )
        if allowed_tags:
            stmt2 = stmt2.where(Asset.tags.overlap(allowed_tags))
        result2 = await session.execute(stmt2)
        assets = result2.scalars().all()

    if not assets:
        return "Es sind keine Assets in der Datenbank vorhanden.", []

    docs = []
    names = []
    for asset in assets:
        doc = _format_asset(asset, asset.sbom_entries, asset.cve_impacts)
        docs.append(doc)
        names.append(asset.hostname or str(asset.ip_address))

    return "\n\n".join(docs), names
