from __future__ import annotations
"""CVE-Impact-Berechnung: SBOM-Match + Exposure + Risk Score + LLM-Analyse."""

import logging
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.config import settings
from src.core.llm import llm_complete
from src.models.all_models import Asset, BusinessProcess, CVEEntry, CVEImpact, ProcessAsset, SBOMEntry

logger = logging.getLogger(__name__)

# Exposure → Risikofaktor
EXPOSURE_FACTOR = {"EXTERN": 1.5, "DMZ": 1.2, "INTERN": 1.0}


class AffectedAsset(BaseModel):
    asset_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    exposure_level: str
    affected_package: str
    package_version: str
    risk_score: float
    risk_level: str
    open_ports: Optional[list]


class ImpactReport(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    affected_assets: list[AffectedAsset]
    llm_analysis: Optional[str] = None
    business_processes_at_risk: list[dict] = []


def _risk_level(score: float) -> str:
    if score >= settings.risk_high_threshold:
        return "HIGH"
    if score >= settings.risk_medium_threshold:
        return "MEDIUM"
    return "LOW"


def _calc_risk_score(
    cvss: float,
    exposure_level: str,
    open_ports: list | None,
    criticality: int = 3,
) -> float:
    exposure_factor = EXPOSURE_FACTOR.get(exposure_level, 1.0)
    # Port-Faktor: externe Ports erhöhen Risiko
    port_factor = 1.0
    if open_ports:
        for p in open_ports:
            if "internet" in p.get("reachable_from", []):
                port_factor = min(port_factor + 0.1, 1.5)
    score = cvss * exposure_factor * port_factor * (0.5 + 0.5 * criticality / 5)
    return round(score, 2)


async def _get_llm_analysis(
    cve: CVEEntry,
    affected: list[AffectedAsset],
    processes: list[dict],
) -> str:
    asset_summary = "\n".join(
        f"- {a.hostname or a.ip_address} ({a.exposure_level}), "
        f"pkg: {a.affected_package} {a.package_version}, "
        f"risk: {a.risk_level} ({a.risk_score})"
        for a in affected[:10]
    )
    proc_summary = ", ".join(p["name"] for p in processes) if processes else "keine"

    prompt = f"""Analysiere den Sicherheitsvorfall für {cve.cve_id}:

CVE-Beschreibung: {cve.description}
CVSS Score: {cve.cvss_score} ({cve.severity})

Betroffene Assets ({len(affected)} gesamt):
{asset_summary}

Betroffene Business-Prozesse: {proc_summary}

Gib eine prägnante Bewertung (max 200 Wörter):
1. Kritikalität des Angriffsvektors in dieser Umgebung
2. Empfohlene Sofortmaßnahmen
3. Priorisierung der betroffenen Systeme"""

    return llm_complete(prompt, max_tokens=400)


async def get_cve_impact(
    cve_id: str,
    session: AsyncSession,
    use_llm: bool = True,
) -> Optional[ImpactReport]:
    cve = await session.get(CVEEntry, cve_id)
    if not cve:
        return None

    # Alle aktiven Assets mit SBOM laden
    stmt = (
        select(Asset)
        .where(Asset.is_active == True)
        .options(selectinload(Asset.sbom_entries))
    )
    result = await session.execute(stmt)
    assets = result.scalars().all()

    # SBOM-Matching: Welche Assets haben betroffene Pakete?
    affected_assets: list[AffectedAsset] = []
    for asset in assets:
        for entry in asset.sbom_entries:
            is_affected = False

            if cve.affected_pkgs:
                for pkg_info in cve.affected_pkgs:
                    if entry.pkg_name.lower() not in pkg_info.get("pkg", "").lower():
                        continue
                    min_ver = pkg_info.get("min", "")
                    max_ver = pkg_info.get("max", "")
                    if min_ver and entry.pkg_version < min_ver:
                        continue
                    if max_ver and entry.pkg_version > max_ver:
                        continue
                    is_affected = True
                    break
            else:
                # Kein explizites Paket-Mapping → Heuristic via Name in Description
                if entry.pkg_name.lower() in cve.description.lower():
                    is_affected = True

            if is_affected:
                cvss = cve.cvss_score or 5.0
                score = _calc_risk_score(cvss, asset.exposure_level, asset.open_ports)
                affected_assets.append(
                    AffectedAsset(
                        asset_id=str(asset.id),
                        hostname=asset.hostname,
                        ip_address=asset.ip_address,
                        exposure_level=asset.exposure_level,
                        affected_package=entry.pkg_name,
                        package_version=entry.pkg_version,
                        risk_score=score,
                        risk_level=_risk_level(score),
                        open_ports=asset.open_ports,
                    )
                )
                break  # pro Asset reicht ein Match

    # Business-Prozesse ermitteln
    processes_at_risk: list[dict] = []
    if affected_assets:
        affected_ids = [a.asset_id for a in affected_assets]
        stmt = (
            select(BusinessProcess)
            .join(ProcessAsset, ProcessAsset.process_id == BusinessProcess.id)
            .where(ProcessAsset.asset_id.in_(affected_ids))
        )
        result = await session.execute(stmt)
        procs = result.scalars().unique().all()
        processes_at_risk = [
            {"id": str(p.id), "name": p.name, "criticality": p.criticality}
            for p in procs
        ]

    # CVEImpact-Cache aktualisieren
    for aa in affected_assets:
        stmt = select(CVEImpact).where(
            CVEImpact.cve_id == cve_id,
            CVEImpact.asset_id == aa.asset_id,
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing:
            existing.risk_score = aa.risk_score
            existing.risk_level = aa.risk_level
        else:
            session.add(CVEImpact(
                cve_id=cve_id,
                asset_id=aa.asset_id,
                risk_score=aa.risk_score,
                risk_level=aa.risk_level,
                affected_pkg=aa.affected_package,
                affected_ver=aa.package_version,
            ))
    await session.flush()

    # Sortierung: höchstes Risiko zuerst
    affected_assets.sort(key=lambda x: x.risk_score, reverse=True)

    llm_analysis = None
    if use_llm and affected_assets and settings.openrouter_api_key:
        try:
            llm_analysis = await _get_llm_analysis(cve, affected_assets, processes_at_risk)
        except Exception as e:
            logger.warning("LLM-Analyse fehlgeschlagen: %s", e)

    return ImpactReport(
        cve_id=cve.cve_id,
        description=cve.description,
        cvss_score=cve.cvss_score,
        severity=cve.severity,
        affected_assets=affected_assets,
        llm_analysis=llm_analysis,
        business_processes_at_risk=processes_at_risk,
    )
