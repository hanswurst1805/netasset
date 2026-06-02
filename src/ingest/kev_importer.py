"""
CISA Known Exploited Vulnerabilities (KEV) Importer.

Lädt die KEV-Liste von CISA herunter und markiert betroffene CVEs
in der lokalen Datenbank. KEV = aktiv ausgenutzten Schwachstellen,
höchste Priorität für Patching.

Kein API-Key nötig.
Quelle: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import logging
from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import async_session_factory
from src.models.all_models import Asset, CVEEntry, CVEImpact, SBOMEntry

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def download_kev() -> list[dict]:
    """Lädt die aktuelle KEV-Liste von CISA herunter."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        log.info("CISA KEV: %d Einträge heruntergeladen", len(vulns))
        return vulns


async def import_kev(session: AsyncSession | None = None) -> dict:
    """
    Markiert CVEs in der DB als KEV (Known Exploited).
    Legt neue CVEEntry an falls noch nicht vorhanden.
    """
    vulns = await download_kev()

    async def _run(s: AsyncSession) -> dict:
        marked = 0
        created = 0

        for v in vulns:
            cve_id = v.get("cveID", "")
            if not cve_id:
                continue

            due_date = v.get("dueDate", "")
            ransomware = v.get("knownRansomwareCampaignUse", "Unknown").lower() == "known"
            description = (
                f"{v.get('vulnerabilityName', '')} — "
                f"{v.get('shortDescription', '')} "
                f"(Vendor: {v.get('vendorProject', '')}, Product: {v.get('product', '')})"
            ).strip(" —")
            required_action = v.get("requiredAction", "")

            existing = await s.get(CVEEntry, cve_id)
            if existing:
                existing.is_kev = True
                existing.kev_due_date = due_date
                existing.kev_ransomware = ransomware
                # Severity mindestens HIGH für KEV-Einträge
                if existing.severity not in ("CRITICAL", "HIGH"):
                    existing.severity = "HIGH"
                    if not existing.cvss_score or existing.cvss_score < 7.0:
                        existing.cvss_score = 7.0
                marked += 1
            else:
                # Neuen CVEEntry anlegen
                new_cve = CVEEntry(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=7.0,  # Minimum für KEV
                    severity="HIGH",
                    is_kev=True,
                    kev_due_date=due_date,
                    kev_ransomware=ransomware,
                    published_at=datetime.utcnow(),
                    raw={
                        "source": "cisa-kev",
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "required_action": required_action,
                        "date_added": v.get("dateAdded"),
                    },
                )
                s.add(new_cve)
                created += 1

        await s.flush()
        log.info("KEV-Import: %d markiert, %d neu angelegt", marked, created)
        return {"marked": marked, "created": created, "total_kev": len(vulns)}

    if session:
        return await _run(session)

    async with async_session_factory() as s:
        result = await _run(s)
        await s.commit()
        return result


async def kev_asset_scan(
    asset_id: str,
    session: AsyncSession,
) -> dict:
    """
    Prüft ein Asset auf KEV-betroffene Software.
    Matching-Strategie:
    1. Direkte CVE-ID aus SBOM-CPE → prüfen ob KEV
    2. Produkt-Name Matching gegen KEV-Datenbank (Vendor/Product)
    3. Für Windows-Programme: fuzzy Name-Matching

    Legt CVEImpact-Einträge für Treffer an.
    """
    import uuid
    asset = await session.get(Asset, uuid.UUID(asset_id))
    if not asset:
        raise ValueError(f"Asset {asset_id} nicht gefunden")

    sbom_result = await session.execute(
        select(SBOMEntry).where(SBOMEntry.asset_id == asset.id)
    )
    sbom = sbom_result.scalars().all()

    # Alle KEV-CVEs laden
    kev_result = await session.execute(
        select(CVEEntry).where(CVEEntry.is_kev == True)
    )
    kev_cves = kev_result.scalars().all()

    EXPOSURE_FACTOR = {"EXTERN": 1.5, "DMZ": 1.2, "INTERN": 1.0}
    impacts_added = 0
    matched_cves = []

    for entry in sbom:
        pkg_name_lower = entry.pkg_name.lower()

        for cve in kev_cves:
            # 1. CPE-Match: wenn SBOM-Entry eine CPE hat
            if entry.cpe and cve.raw:
                cpe_product = (cve.raw.get("product") or "").lower()
                cpe_vendor  = (cve.raw.get("vendor") or "").lower()
                if cpe_product and cpe_product in entry.cpe.lower():
                    pass  # weiter zu Impact-Anlage
                elif cpe_vendor and cpe_vendor in entry.cpe.lower():
                    pass
                else:
                    continue  # kein CPE-Match

            # 2. Produkt-Name-Match (für Windows/macOS Programme)
            elif cve.raw and cve.raw.get("product"):
                product = cve.raw["product"].lower()
                vendor  = (cve.raw.get("vendor") or "").lower()
                # Fuzzy: Produkt-Name in Paket-Name oder umgekehrt
                if (product in pkg_name_lower or
                    pkg_name_lower in product or
                    (vendor and vendor in pkg_name_lower)):
                    pass  # Match
                else:
                    # Kein Match
                    continue

            # 3. Description-Match als letzter Fallback
            elif cve.description:
                desc_lower = cve.description.lower()
                if pkg_name_lower not in desc_lower and len(pkg_name_lower) < 4:
                    continue
                elif pkg_name_lower not in desc_lower:
                    continue
            else:
                continue

            # Impact anlegen
            existing = (await session.execute(
                select(CVEImpact).where(
                    CVEImpact.cve_id == cve.cve_id,
                    CVEImpact.asset_id == asset.id,
                )
            )).scalar_one_or_none()

            cvss = cve.cvss_score or 7.0
            exp_f = EXPOSURE_FACTOR.get(asset.exposure_level, 1.0)
            # KEV: Basis-Faktor erhöhen (aktiv ausgenutzt!)
            kev_factor = 1.5 if cve.kev_ransomware else 1.2
            risk = round(cvss * exp_f * kev_factor, 2)
            level = "HIGH" if risk >= 7 else "MEDIUM"

            if existing:
                existing.risk_score = max(existing.risk_score or 0, risk)
                existing.risk_level = level
            else:
                session.add(CVEImpact(
                    cve_id=cve.cve_id,
                    asset_id=asset.id,
                    risk_score=risk,
                    risk_level=level,
                    affected_pkg=entry.pkg_name,
                    affected_ver=entry.pkg_version,
                    reasoning=f"CISA KEV: {cve.cve_id} betrifft {entry.pkg_name}"
                              + (" [RANSOMWARE]" if cve.kev_ransomware else ""),
                ))
                impacts_added += 1
                matched_cves.append(cve.cve_id)

    await session.flush()
    return {
        "asset": asset.hostname or asset_id,
        "kev_matches": impacts_added,
        "cves": matched_cves[:20],
    }
