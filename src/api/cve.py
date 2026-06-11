from __future__ import annotations
"""CVE & Security API Router"""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.ingest.kev_importer import import_kev, kev_asset_scan
from src.ingest.osv_importer import scan_all_assets_osv, scan_asset_osv
from src.rag.cve_impact import ImpactReport, get_cve_impact
from src.rag.query_engine import query_natural
from src.rag.vector_search import search_cves

router = APIRouter()


class NaturalQuery(BaseModel):
    question: str
    use_llm: bool = True


class QueryResponse(BaseModel):
    question: str
    answer: str
    sources_assets: list[str]
    sources_cves: list[str]
    context_size: int


@router.get("/{cve_id}/impact", response_model=ImpactReport)
async def cve_impact(
    cve_id: str,
    use_llm: bool = True,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    report = await get_cve_impact(cve_id, session=session, use_llm=use_llm)
    if not report:
        raise HTTPException(404, f"CVE {cve_id} nicht in lokaler Datenbank gefunden")
    return report


@router.post("/kev/import")
async def kev_import(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Importiert CISA KEV (Known Exploited Vulnerabilities). Kein API-Key nötig."""
    try:
        result = await import_kev(session)
        return result
    except RuntimeError as e:
        raise HTTPException(503, str(e))


@router.post("/kev/upload")
async def kev_upload(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """
    Manueller KEV-Import via Datei-Upload.
    Download: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    → „Download Vulnerability Catalog (JSON)"
    """
    from src.ingest.kev_importer import import_kev
    content = await file.read()
    import json as _json
    data = _json.loads(content)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise HTTPException(400, "Keine Vulnerabilities in der Datei gefunden")

    # Temporär in Funktion injizieren
    from src.ingest import kev_importer as _kev
    original = _kev.download_kev

    async def _mock():
        return vulns

    _kev.download_kev = _mock
    try:
        result = await import_kev(session)
    finally:
        _kev.download_kev = original
    return result


@router.post("/kev/scan/asset/{asset_id}")
async def kev_scan_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Prüft ein Asset auf KEV-betroffene Software (gut für Windows/macOS)."""
    try:
        return await kev_asset_scan(asset_id, session)
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/osv/scan/asset/{asset_id}")
async def osv_scan_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """
    Scannt ein einzelnes Asset gegen OSV (Open Source Vulnerabilities).
    Kein API-Key nötig. Findet CVEs für installierte Pakete.
    """
    try:
        result = await scan_asset_osv(asset_id, session)
        return result
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/osv/scan/all")
async def osv_scan_all(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Scannt alle aktiven Assets mit SBOM gegen OSV."""
    result = await scan_all_assets_osv(session)
    return result


@router.get("/list")
async def list_cves(
    affected_only: bool = False,
    q: str | None = None,
    min_cvss: float = 0.0,
    limit: int = 50,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """
    Listet CVEs absteigend nach CVSS-Score sortiert.
    affected_only=true: nur CVEs, die mindestens ein aktives Asset betreffen.
    """
    from sqlalchemy import desc, or_, select
    from src.models.all_models import Asset, CVEEntry, CVEImpact

    stmt = select(CVEEntry)

    if affected_only:
        stmt = (
            stmt.join(CVEImpact, CVEImpact.cve_id == CVEEntry.cve_id)
            .join(Asset, CVEImpact.asset_id == Asset.id)
            .where(Asset.is_active == True, Asset.is_obsolete == False)
            .distinct()
        )

    if min_cvss > 0:
        stmt = stmt.where(CVEEntry.cvss_score >= min_cvss)

    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(or_(CVEEntry.cve_id.ilike(pattern), CVEEntry.description.ilike(pattern)))

    stmt = stmt.order_by(desc(CVEEntry.cvss_score)).limit(limit)

    rows = await session.execute(stmt)
    cves = rows.scalars().all()

    # Betroffene Systeme pro CVE – Anzahl + Hostnamen
    affected_map: dict[str, list[str]] = {}
    if cves:
        cve_ids = [c.cve_id for c in cves]
        impact_rows = await session.execute(
            select(CVEImpact.cve_id, Asset.id, Asset.hostname, Asset.ip_address)
            .join(Asset, CVEImpact.asset_id == Asset.id)
            .where(CVEImpact.cve_id.in_(cve_ids), Asset.is_active == True, Asset.is_obsolete == False)
        )
        for row in impact_rows:
            label = row.hostname or str(row.ip_address) or str(row.id)
            affected_map.setdefault(row.cve_id, []).append(label)

    results = []
    for c in cves:
        hosts = affected_map.get(c.cve_id, [])
        results.append({
            "cve_id": c.cve_id,
            "description": c.description,
            "cvss_score": c.cvss_score,
            "severity": c.severity,
            "is_kev": c.is_kev,
            "affected_assets": len(hosts),
            "affected_hostnames": hosts,
        })

    results.sort(key=lambda r: (r["cvss_score"] or 0, r["affected_assets"]), reverse=True)
    return results


@router.get("/search")
async def search(
    q: str,
    top_k: int = 10,
    min_cvss: float = 0.0,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Semantische CVE-Suche — gibt auch Anzahl betroffener Systeme zurück."""
    from sqlalchemy import func, select
    from src.models.all_models import CVEImpact

    results = await search_cves(q, top_k=top_k, min_cvss=min_cvss, session=session)

    # Betroffene Systeme pro CVE – Anzahl + Hostnamen
    if results:
        from src.models.all_models import Asset
        cve_ids = [r["cve_id"] for r in results]
        rows = await session.execute(
            select(CVEImpact.cve_id, Asset.id, Asset.hostname, Asset.ip_address)
            .join(Asset, CVEImpact.asset_id == Asset.id)
            .where(CVEImpact.cve_id.in_(cve_ids), Asset.is_active == True, Asset.is_obsolete == False)
        )
        affected_map: dict[str, list[str]] = {}
        for row in rows:
            label = row.hostname or str(row.ip_address) or str(row.id)
            affected_map.setdefault(row.cve_id, []).append(label)
        for r in results:
            hosts = affected_map.get(r["cve_id"], [])
            r["affected_assets"] = len(hosts)
            r["affected_hostnames"] = hosts

    # Nach CVSS absteigend sortieren, danach Anzahl betroffener Systeme
    results.sort(key=lambda r: (r.get("cvss_score") or 0, r.get("affected_assets") or 0), reverse=True)

    return results


@router.get("/assets/{asset_id}/cve-exposure")
async def asset_cve_exposure(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Top CVEs für ein Asset — aufgeteilt nach SBOM (Software) und Ports."""
    import uuid
    from sqlalchemy import desc, select
    from src.models.all_models import CVEEntry, CVEImpact, SBOMEntry

    try:
        aid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(400, "Ungültige Asset-ID")

    # Alle CVE-Impacts für dieses Asset
    stmt = (
        select(CVEImpact, CVEEntry)
        .outerjoin(CVEEntry, CVEImpact.cve_id == CVEEntry.cve_id)
        .where(CVEImpact.asset_id == aid)
        .order_by(desc(CVEImpact.risk_score))
        .limit(20)
    )
    result = await session.execute(stmt)
    rows = result.all()

    # SBOM-Pakete für dieses Asset
    sbom_result = await session.execute(
        select(SBOMEntry.pkg_name).where(SBOMEntry.asset_id == aid)
    )
    sbom_names = {r[0].lower() for r in sbom_result}

    sbom_cves = []
    port_cves = []
    seen = set()

    for impact, cve in rows:
        if impact.cve_id in seen:
            continue
        seen.add(impact.cve_id)

        entry = {
            "cve_id": impact.cve_id,
            "risk_score": impact.risk_score,
            "risk_level": impact.risk_level,
            "affected_pkg": impact.affected_pkg,
            "affected_ver": impact.affected_ver,
            "cvss_score": cve.cvss_score if cve else None,
            "severity": cve.severity if cve else None,
            "description": (cve.description[:120] + "…") if cve and cve.description else "",
            "is_kev": cve.is_kev if cve else False,
        }

        # Zuordnung: Software-CVE wenn Paketname in SBOM, sonst Port/System-CVE
        pkg = (impact.affected_pkg or "").lower()
        if pkg and pkg in sbom_names:
            sbom_cves.append(entry)
        else:
            port_cves.append(entry)

    return {
        "asset_id": asset_id,
        "sbom_cves": sbom_cves[:5],
        "port_cves": port_cves[:5],
        "total": len(rows),
    }


@router.post("/query", response_model=QueryResponse)
async def natural_language_query(
    body: NaturalQuery,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """
    RAG-Freitext-Query – strikt datenbasiert.
    Das LLM antwortet ausschließlich auf Basis der echten Asset- und CVE-Daten.
    """
    result = await query_natural(
        body.question,
        session=session,
        allowed_tags=ctx.filter_tags(),
    )
    return QueryResponse(question=body.question, **result)
