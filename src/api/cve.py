from __future__ import annotations
"""CVE & Security API Router"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
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
