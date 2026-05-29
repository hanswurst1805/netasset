"""Freitext-RAG-Query: Natürliche Sprache → CVE-Analyse via OpenRouter."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.config import settings
from src.core.llm import llm_complete
from src.models.all_models import Asset
from src.rag.vector_search import search_cves

logger = logging.getLogger(__name__)


async def query_natural(question: str, session: AsyncSession) -> str:
    """
    Beantwortet eine Freitextfrage über CVEs und Assets via RAG.
    Beispiel: "Welche extern erreichbaren Systeme haben kritische OpenSSL-Lücken?"
    """
    cve_results = await search_cves(question, top_k=5, session=session)

    if not cve_results:
        return "Keine relevanten CVEs in der lokalen Datenbank gefunden."

    stmt = (
        select(Asset)
        .where(Asset.is_active == True)
        .options(selectinload(Asset.sbom_entries))
        .limit(50)
    )
    result = await session.execute(stmt)
    assets = result.scalars().all()

    cve_context = "\n".join(
        f"- {r['cve_id']} (CVSS {r['cvss_score']}, {r['severity']}): {r['description'][:200]}"
        for r in cve_results
    )
    asset_context = "\n".join(
        f"- {a.hostname or a.ip_address} [{a.exposure_level}] "
        f"OS: {a.os_name or 'unbekannt'} "
        f"Pakete: {', '.join(e.pkg_name + ' ' + e.pkg_version for e in a.sbom_entries[:5])}"
        for a in assets[:20]
    )

    if not settings.openrouter_api_key:
        return (
            "LLM-Analyse nicht verfügbar (kein OPENROUTER_API_KEY). "
            f"Gefundene CVEs: {', '.join(r['cve_id'] for r in cve_results)}"
        )

    prompt = f"""Du bist ein Security-Analyst für eine CMDB. Beantworte die folgende Frage
basierend auf den CVE-Daten und Asset-Informationen aus der Datenbank.

Frage: {question}

Relevante CVEs (semantisch gesucht):
{cve_context}

Assets in der Datenbank (Auszug):
{asset_context}

Antworte präzise und strukturiert. Wenn du nicht genug Daten hast, sage es klar."""

    return llm_complete(prompt, max_tokens=800)
