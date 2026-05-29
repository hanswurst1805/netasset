from __future__ import annotations
"""
CVE & Security API Router
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.rag.cve_impact import get_cve_impact, ImpactReport
from src.rag.query_engine import query_natural
from src.rag.vector_search import search_cves

router = APIRouter()


class NaturalQuery(BaseModel):
    question: str
    use_llm: bool = True


class CVESearchResult(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str | None
    similarity: float


@router.get("/{cve_id}/impact", response_model=ImpactReport)
async def cve_impact(
    cve_id: str,
    use_llm: bool = True,
    session: AsyncSession = Depends(get_session),
):
    """
    Vollständiger Impact-Report für eine CVE.
    Kombiniert SBOM-Match + Exposure + Business-Prozesse + LLM-Analyse.
    """
    report = await get_cve_impact(cve_id, session=session, use_llm=use_llm)
    if not report:
        raise HTTPException(404, f"CVE {cve_id} nicht in lokaler Datenbank gefunden")
    return report


@router.get("/search")
async def search(q: str, top_k: int = 10, min_cvss: float = 0.0):
    """Semantische CVE-Suche via pgvector."""
    results = await search_cves(q, top_k=top_k, min_cvss=min_cvss)
    return results


@router.post("/query")
async def natural_language_query(
    body: NaturalQuery,
    session: AsyncSession = Depends(get_session),
):
    """
    RAG-Freitext-Query.
    Beispiel: "Welche extern erreichbaren Systeme haben kritische OpenSSL-Lücken?"
    """
    answer = await query_natural(body.question, session=session)
    return {"question": body.question, "answer": answer}


@router.get("/assets/{asset_id}/cve-exposure")
async def asset_cve_exposure(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Alle relevanten CVEs für ein Asset, nach Risiko sortiert."""
    # Wird durch RAG implementiert – Asset-SBOM → CVE-Matching
    raise HTTPException(501, "In Implementierung")
