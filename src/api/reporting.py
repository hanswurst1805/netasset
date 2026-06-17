"""
Vorgefertigte Security-Reports – schnelle DB-Auswertung, optionale LLM-Summary.

Endpoints:
  GET  /reporting/security-posture
  GET  /reporting/network-exposure
  GET  /reporting/sbom-vulnerabilities
  GET  /reporting/process-risk
  POST /reporting/{report_type}/summary   ← LLM-Summary (async, optional)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.auth import AuthContext, get_current_user
from src.core.components import component_condition
from src.core.database import get_session
from src.models.all_models import (
    Application, ApplicationComponent, Asset, BusinessProcess, CVEEntry, CVEImpact,
    ProcessAsset, SBOMEntry,
)

log = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _risk_color(level: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(level, "gray")


def _stale(last_seen: Optional[datetime], hours: int = 24) -> bool:
    if not last_seen:
        return True
    return (datetime.utcnow() - last_seen).total_seconds() > hours * 3600


# ---------------------------------------------------------------------------
# 1. Security Posture Report
# ---------------------------------------------------------------------------

class AssetSummary(BaseModel):
    id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    asset_type: str
    exposure_level: str
    risk_score: float
    risk_level: str
    cve_count: int
    last_seen_at: Optional[datetime]
    is_stale: bool


class SecurityPostureReport(BaseModel):
    generated_at: datetime
    total_assets: int
    by_exposure: dict[str, int]
    by_type: dict[str, int]
    stale_assets: int
    cve_summary: dict[str, int]          # HIGH/MEDIUM/LOW counts
    top_risk_assets: list[AssetSummary]
    critical_assets: list[AssetSummary]  # EXTERN mit HIGH CVEs


@router.get("/security-posture", response_model=SecurityPostureReport)
async def security_posture(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    stmt = select(Asset).where(Asset.is_active == True, Asset.is_archived == False)
    if tag_filter := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(tag_filter))
    result = await session.execute(stmt.options(selectinload(Asset.cve_impacts)))
    assets = result.scalars().all()

    by_exposure: dict[str, int] = {}
    by_type: dict[str, int] = {}
    stale = 0
    cve_summary: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_risk: list[tuple[float, Asset, int, str]] = []

    for a in assets:
        by_exposure[a.exposure_level] = by_exposure.get(a.exposure_level, 0) + 1
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        if _stale(a.last_seen_at):
            stale += 1

        max_score = 0.0
        max_level = "LOW"
        for imp in a.cve_impacts:
            cve_summary[imp.risk_level] = cve_summary.get(imp.risk_level, 0) + 1
            if (imp.risk_score or 0) > max_score:
                max_score = imp.risk_score or 0
                max_level = imp.risk_level or "LOW"

        top_risk.append((max_score, a, len(a.cve_impacts), max_level))

    top_risk.sort(key=lambda x: x[0], reverse=True)

    def make_summary(item: tuple) -> AssetSummary:
        score, a, cve_count, level = item
        return AssetSummary(
            id=str(a.id),
            hostname=a.hostname,
            ip_address=a.ip_address,
            asset_type=a.asset_type,
            exposure_level=a.exposure_level,
            risk_score=round(score, 2),
            risk_level=level,
            cve_count=cve_count,
            last_seen_at=a.last_seen_at,
            is_stale=_stale(a.last_seen_at),
        )

    critical = [make_summary(x) for x in top_risk
                if x[1].exposure_level in ("EXTERN", "DMZ") and x[3] == "HIGH"]

    return SecurityPostureReport(
        generated_at=datetime.utcnow(),
        total_assets=len(assets),
        by_exposure=by_exposure,
        by_type=by_type,
        stale_assets=stale,
        cve_summary=cve_summary,
        top_risk_assets=[make_summary(x) for x in top_risk[:10]],
        critical_assets=critical[:10],
    )


# ---------------------------------------------------------------------------
# 2. Network Exposure Report
# ---------------------------------------------------------------------------

class ExposedAsset(BaseModel):
    id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    asset_type: str
    exposure_level: str
    network_zones: Optional[list[str]]
    internet_ports: list[int]
    all_ports: int
    high_cve_count: int
    risk_score: float


class NetworkExposureReport(BaseModel):
    generated_at: datetime
    extern_count: int
    dmz_count: int
    internet_facing_ports: dict[int, int]   # port → asset count
    exposed_assets: list[ExposedAsset]


@router.get("/network-exposure", response_model=NetworkExposureReport)
async def network_exposure(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    stmt = (
        select(Asset)
        .where(
            Asset.is_active == True,
            Asset.is_archived == False,
            Asset.exposure_level.in_(["EXTERN", "DMZ"]),
        )
        .options(selectinload(Asset.cve_impacts))
    )
    if tag_filter := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(tag_filter))

    result = await session.execute(stmt)
    assets = result.scalars().all()

    extern_count = sum(1 for a in assets if a.exposure_level == "EXTERN")
    dmz_count    = sum(1 for a in assets if a.exposure_level == "DMZ")
    port_freq: dict[int, int] = {}
    exposed: list[ExposedAsset] = []

    for a in assets:
        ports = a.open_ports or []
        inet_ports = [
            p["port"] for p in ports
            if "internet" in p.get("reachable_from", [])
        ]
        for p in inet_ports:
            port_freq[p] = port_freq.get(p, 0) + 1

        high_cvs = sum(1 for i in a.cve_impacts if i.risk_level == "HIGH")
        max_score = max((i.risk_score or 0 for i in a.cve_impacts), default=0.0)

        exposed.append(ExposedAsset(
            id=str(a.id),
            hostname=a.hostname,
            ip_address=a.ip_address,
            asset_type=a.asset_type,
            exposure_level=a.exposure_level,
            network_zones=a.network_zones,
            internet_ports=sorted(inet_ports),
            all_ports=len(ports),
            high_cve_count=high_cvs,
            risk_score=round(max_score, 2),
        ))

    exposed.sort(key=lambda x: (x.high_cve_count, x.risk_score), reverse=True)
    top_ports = dict(sorted(port_freq.items(), key=lambda x: x[1], reverse=True)[:20])

    return NetworkExposureReport(
        generated_at=datetime.utcnow(),
        extern_count=extern_count,
        dmz_count=dmz_count,
        internet_facing_ports=top_ports,
        exposed_assets=exposed,
    )


# ---------------------------------------------------------------------------
# 3. SBOM Vulnerability Report
# ---------------------------------------------------------------------------

class VulnPackage(BaseModel):
    pkg_name: str
    pkg_version: str
    cve_id: str
    cvss_score: Optional[float]
    severity: Optional[str]
    affected_assets: list[str]   # hostnames
    max_risk_score: float
    risk_level: str
    # Fachliche Einordnung über die Komponenten-Schicht (welche Anwendung
    # nutzt dieses Paket → welcher Prozess)
    affected_applications: list[str] = []
    affected_processes: list[str] = []


class SBOMVulnerabilityReport(BaseModel):
    generated_at: datetime
    total_packages_checked: int
    vulnerable_packages: int
    by_severity: dict[str, int]
    findings: list[VulnPackage]


@router.get("/sbom-vulnerabilities", response_model=SBOMVulnerabilityReport)
async def sbom_vulnerabilities(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    # CVE-Impacts mit Asset+SBOM laden
    stmt = (
        select(CVEImpact)
        .options(selectinload(CVEImpact.asset), selectinload(CVEImpact.cve))
        .where(CVEImpact.risk_score.is_not(None))
        .order_by(desc(CVEImpact.risk_score))
    )
    result = await session.execute(stmt)
    impacts = result.scalars().all()

    # Nach CVE+Paket gruppieren
    findings: dict[tuple, VulnPackage] = {}
    finding_asset_ids: dict[tuple, set] = {}   # key -> set(asset_id) für Komponenten-Mapping
    severity_count: dict[str, int] = {}
    pkg_names: set[str] = set()

    for imp in impacts:
        if not imp.asset or not imp.asset.is_active or imp.asset.is_archived:
            continue
        if tag_filter := ctx.filter_tags():
            if not imp.asset.tags or not set(imp.asset.tags) & set(tag_filter):
                continue

        key = (imp.cve_id, imp.affected_pkg or "", imp.affected_ver or "")
        hostname = imp.asset.hostname or imp.asset.ip_address or str(imp.asset.id)
        finding_asset_ids.setdefault(key, set()).add(imp.asset.id)

        if key not in findings:
            findings[key] = VulnPackage(
                pkg_name=imp.affected_pkg or "unbekannt",
                pkg_version=imp.affected_ver or "?",
                cve_id=imp.cve_id,
                cvss_score=imp.cve.cvss_score if imp.cve else None,
                severity=imp.cve.severity if imp.cve else None,
                affected_assets=[hostname],
                max_risk_score=imp.risk_score or 0,
                risk_level=imp.risk_level or "LOW",
            )
            severity_count[imp.risk_level or "LOW"] = severity_count.get(imp.risk_level or "LOW", 0) + 1
        else:
            if hostname not in findings[key].affected_assets:
                findings[key].affected_assets.append(hostname)
            if (imp.risk_score or 0) > findings[key].max_risk_score:
                findings[key].max_risk_score = imp.risk_score or 0

        pkg_names.add(imp.affected_pkg or "")

    # -----------------------------------------------------------------------
    # Komponenten-Schicht: welche Fachanwendung/Prozess nutzt das Paket?
    # Reverse-Index (asset_id, paket) → Anwendungen, gegen die SBOM aufgelöst.
    # -----------------------------------------------------------------------
    vuln_pkg_names = {p.lower() for p in pkg_names if p}
    if vuln_pkg_names:
        comps = (await session.execute(select(ApplicationComponent))).scalars().all()
        pair_to_apps: dict[tuple, set] = {}
        for comp in comps:
            stmt = (
                select(SBOMEntry.asset_id, SBOMEntry.pkg_name)
                .join(Asset, Asset.id == SBOMEntry.asset_id)
                .where(
                    component_condition(comp.match_kind, comp.match_value),
                    Asset.is_active == True, Asset.is_archived == False,
                )
            )
            if comp.asset_id:
                stmt = stmt.where(SBOMEntry.asset_id == comp.asset_id)
            for aid, pname in (await session.execute(stmt)).all():
                if pname.lower() in vuln_pkg_names:
                    pair_to_apps.setdefault((aid, pname.lower()), set()).add(comp.application_id)

        if pair_to_apps:
            app_ids = {a for s in pair_to_apps.values() for a in s}
            apps_map = {
                a.id: a for a in (await session.execute(
                    select(Application).where(Application.id.in_(app_ids))
                )).scalars().all()
            }
            proc_ids = {a.process_id for a in apps_map.values() if a.process_id}
            proc_map = {
                p.id: p.name for p in (await session.execute(
                    select(BusinessProcess).where(BusinessProcess.id.in_(proc_ids))
                )).scalars().all()
            } if proc_ids else {}

            for key, vp in findings.items():
                pkg_lower = (key[1] or "").lower()
                app_set: set = set()
                for aid in finding_asset_ids.get(key, set()):
                    app_set |= pair_to_apps.get((aid, pkg_lower), set())
                if app_set:
                    vp.affected_applications = sorted({
                        apps_map[a].name for a in app_set if a in apps_map
                    })
                    vp.affected_processes = sorted({
                        proc_map[apps_map[a].process_id]
                        for a in app_set
                        if a in apps_map and apps_map[a].process_id in proc_map
                    })

    sorted_findings = sorted(findings.values(), key=lambda x: x.max_risk_score, reverse=True)

    return SBOMVulnerabilityReport(
        generated_at=datetime.utcnow(),
        total_packages_checked=len(pkg_names),
        vulnerable_packages=len({f.pkg_name for f in sorted_findings}),
        by_severity=severity_count,
        findings=sorted_findings[:100],
    )


# ---------------------------------------------------------------------------
# 4. Process Risk Report
# ---------------------------------------------------------------------------

class ProcessRiskItem(BaseModel):
    process_id: str
    process_name: str
    criticality: int
    asset_count: int
    high_count: int
    medium_count: int
    low_count: int
    max_risk_score: float
    top_cves: list[dict]
    risk_rating: str   # KRITISCH / HOCH / MITTEL / NIEDRIG
    # Grundlage der Bewertung: "components" (über Fachanwendung→Paket) oder
    # "assets" (Fallback: alle Pakete der Prozess-Assets, wenn keine Komponenten)
    risk_basis: str = "components"
    component_count: int = 0


class ProcessRiskReport(BaseModel):
    generated_at: datetime
    process_count: int
    critical_processes: int
    findings: list[ProcessRiskItem]


@router.get("/process-risk", response_model=ProcessRiskReport)
async def process_risk(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    processes = (await session.execute(select(BusinessProcess))).scalars().all()
    findings: list[ProcessRiskItem] = []

    def _build(proc, impacts, asset_count, component_count, basis) -> ProcessRiskItem:
        high   = sum(1 for i in impacts if i.risk_level == "HIGH")
        medium = sum(1 for i in impacts if i.risk_level == "MEDIUM")
        low    = sum(1 for i in impacts if i.risk_level == "LOW")
        max_score = max((i.risk_score or 0 for i in impacts), default=0.0)
        # Top-CVEs nach Risiko, dedupliziert
        top_cves, seen = [], set()
        for i in sorted(impacts, key=lambda x: x.risk_score or 0, reverse=True):
            if i.cve_id in seen:
                continue
            seen.add(i.cve_id)
            top_cves.append({"cve_id": i.cve_id, "risk_score": i.risk_score, "risk_level": i.risk_level})
            if len(top_cves) >= 3:
                break

        if high > 0 and proc.criticality >= 4:
            rating = "KRITISCH"
        elif high > 0 or (medium > 2 and proc.criticality >= 3):
            rating = "HOCH"
        elif medium > 0:
            rating = "MITTEL"
        else:
            rating = "NIEDRIG"

        return ProcessRiskItem(
            process_id=str(proc.id),
            process_name=proc.name,
            criticality=proc.criticality,
            asset_count=asset_count,
            high_count=high, medium_count=medium, low_count=low,
            max_risk_score=round(max_score, 2),
            top_cves=top_cves,
            risk_rating=rating,
            risk_basis=basis,
            component_count=component_count,
        )

    for proc in processes:
        # 1. Bevorzugt: Komponenten-basiert (Fachanwendung → genutztes Paket)
        app_ids = (await session.execute(
            select(Application.id).where(
                Application.process_id == proc.id, Application.is_active == True
            )
        )).scalars().all()

        comps = []
        if app_ids:
            comps = (await session.execute(
                select(ApplicationComponent).where(
                    ApplicationComponent.application_id.in_(app_ids)
                )
            )).scalars().all()

        if comps:
            # Komponenten gegen SBOM auflösen → (asset_id, paket) Paare
            pairs: set[tuple] = set()
            systems: set = set()
            for comp in comps:
                stmt = (
                    select(SBOMEntry.asset_id, SBOMEntry.pkg_name)
                    .join(Asset, Asset.id == SBOMEntry.asset_id)
                    .where(
                        component_condition(comp.match_kind, comp.match_value),
                        Asset.is_active == True, Asset.is_archived == False,
                    )
                )
                if comp.asset_id:
                    stmt = stmt.where(SBOMEntry.asset_id == comp.asset_id)
                for aid, pname in (await session.execute(stmt)).all():
                    pairs.add((aid, pname.lower()))
                    systems.add(aid)

            impacts = []
            if pairs:
                pkg_names = {p for _, p in pairs}
                raw = (await session.execute(
                    select(CVEImpact).where(
                        CVEImpact.asset_id.in_(systems),
                        func.lower(CVEImpact.affected_pkg).in_(pkg_names),
                    )
                )).scalars().all()
                # nur exakte (System, Paket)-Treffer der Komponenten zählen
                impacts = [i for i in raw if (i.asset_id, (i.affected_pkg or "").lower()) in pairs]

            findings.append(_build(proc, impacts, len(systems), len(comps), "components"))
            continue

        # 2. Fallback: asset-basiert (keine Komponenten definiert)
        asset_ids = [row[0] for row in (await session.execute(
            select(ProcessAsset.asset_id)
            .join(Asset, Asset.id == ProcessAsset.asset_id)
            .where(
                ProcessAsset.process_id == proc.id,
                Asset.is_active == True, Asset.is_archived == False,
            )
        ))]

        impacts = []
        if asset_ids:
            impacts = (await session.execute(
                select(CVEImpact).where(CVEImpact.asset_id.in_(asset_ids))
            )).scalars().all()

        findings.append(_build(proc, impacts, len(asset_ids), 0, "assets"))

    findings.sort(key=lambda x: (
        {"KRITISCH": 3, "HOCH": 2, "MITTEL": 1, "NIEDRIG": 0}.get(x.risk_rating, 0),
        x.max_risk_score
    ), reverse=True)

    critical = sum(1 for f in findings if f.risk_rating in ("KRITISCH", "HOCH"))

    return ProcessRiskReport(
        generated_at=datetime.utcnow(),
        process_count=len(processes),
        critical_processes=critical,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# LLM-Summary (optional, wird separat aufgerufen)
# ---------------------------------------------------------------------------

class SummaryRequest(BaseModel):
    report_data: dict
    report_type: str


class SummaryResponse(BaseModel):
    summary: str
    model: str


@router.post("/{report_type}/summary", response_model=SummaryResponse)
async def generate_summary(
    report_type: str,
    body: SummaryRequest,
    ctx: AuthContext = Depends(get_current_user),
):
    """
    Generiert eine kurze Executive Summary (2-4 Sätze) für einen Report.
    Wird vom Frontend nach dem Datenladen optional aufgerufen.
    """
    from src.core.config import settings
    from src.core.llm import llm_complete

    if not settings.openrouter_api_key:
        return SummaryResponse(summary="(Kein API-Key konfiguriert)", model="none")

    templates = {
        "security-posture": """Fasse diesen Security-Posture-Report in 3 Sätzen zusammen.
Fokus: kritischste Risiken, dringendster Handlungsbedarf. Keine Aufzählungen, nur Fließtext.
Daten: {data}""",
        "network-exposure": """Fasse diesen Netzwerk-Exposure-Report in 3 Sätzen zusammen.
Fokus: extern exponierte Risiken, sofortiger Handlungsbedarf. Keine Aufzählungen.
Daten: {data}""",
        "sbom-vulnerabilities": """Fasse diesen SBOM-Vulnerability-Report in 3 Sätzen zusammen.
Fokus: kritischste verwundbare Pakete, Patch-Priorität. Keine Aufzählungen.
Daten: {data}""",
        "process-risk": """Fasse diesen Prozess-Risiko-Report in 3 Sätzen zusammen.
Fokus: kritischste Geschäftsprozesse, Risiko für den Betrieb. Keine Aufzählungen.
Daten: {data}""",
    }

    template = templates.get(report_type, "Fasse diesen Report in 3 Sätzen zusammen. Daten: {data}")

    # Kompaktes Daten-Subset für den Prompt (klein halten)
    import json
    data_str = json.dumps(body.report_data, ensure_ascii=False)[:2000]
    prompt = template.format(data=data_str)

    try:
        summary = llm_complete(prompt, max_tokens=200)
    except Exception as e:
        log.warning("LLM-Summary fehlgeschlagen: %s", e)
        summary = f"(LLM-Fehler: {e})"

    return SummaryResponse(summary=summary, model=settings.llm_model)
