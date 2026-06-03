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


@router.get("/search")
async def search(
    q: str,
    top_k: int = 10,
    min_cvss: float = 0.0,
    ctx: AuthContext = Depends(get_current_user),
):
    results = await search_cves(q, top_k=top_k, min_cvss=min_cvss)
    return results


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
