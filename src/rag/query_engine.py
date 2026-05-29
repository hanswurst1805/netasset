"""
RAG Query Engine – strikt datenbasiert, keine Halluzinationen.

Ablauf:
1. Keywords aus der Frage extrahieren
2. Relevante Assets aus DB laden (mit vollständigem Kontext)
3. Passende CVEs via pgvector suchen
4. LLM mit striktem System-Prompt aufrufen
5. Antwort mit Quellenangaben zurückgeben
"""

from __future__ import annotations

import logging
import re

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.llm import llm_complete
from src.rag.asset_context import build_filtered_context, build_full_context
from src.rag.vector_search import search_cves

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Du bist ein Security-Analyst für eine CMDB (Configuration Management Database).

WICHTIGE REGELN – halte dich strikt daran:
1. Antworte NUR auf Basis der bereitgestellten Daten aus der Datenbank.
2. Wenn eine Information nicht in den Daten vorhanden ist, sage explizit: "Diese Information ist in der Datenbank nicht vorhanden."
3. Erfinde KEINE Software-Versionen, Ports, CVEs, Hostnamen oder Konfigurationen.
4. Zitiere konkrete Assets beim Namen (Hostname oder IP) wenn du über sie sprichst.
5. Wenn du unsicher bist, sage es klar.
6. Antworte auf Deutsch, strukturiert und präzise.

FORMAT deiner Antwort:
- Beginne direkt mit der Antwort, keine Wiederholung der Frage
- Nutze Aufzählungen für Listen von Assets oder CVEs
- Füge am Ende eine kurze "Quellen"-Sektion hinzu die listet welche Assets verwendet wurden
"""


def _extract_keywords(question: str) -> list[str]:
    """Extrahiert relevante Keywords aus der Frage für die Asset-Filterung."""
    # Stopwörter entfernen
    stop = {
        "welche", "welcher", "welches", "haben", "hat", "gibt", "sind", "ist",
        "die", "der", "das", "ein", "eine", "mit", "auf", "für", "und", "oder",
        "alle", "meine", "meiner", "von", "im", "in", "an", "zu",
        "kann", "können", "wie", "was", "wo", "wer", "warum",
    }
    words = re.findall(r'\b\w{3,}\b', question.lower())
    return [w for w in words if w not in stop]


async def query_natural(
    question: str,
    session: AsyncSession,
    allowed_tags: list[str] | None = None,
) -> dict:
    """
    Beantwortet eine Freitextfrage über die CMDB.

    Returns:
        {
            "answer": str,
            "sources_assets": list[str],
            "sources_cves": list[str],
            "context_size": int,
        }
    """
    if not settings.openrouter_api_key:
        return {
            "answer": "LLM nicht konfiguriert (OPENROUTER_API_KEY fehlt).",
            "sources_assets": [],
            "sources_cves": [],
            "context_size": 0,
        }

    keywords = _extract_keywords(question)
    logger.info("RAG Query: '%s' | Keywords: %s", question, keywords)

    # 1. Asset-Kontext laden
    # Bei kleinen Umgebungen (< 50 Assets) alles laden, sonst filtern
    try:
        asset_context, asset_names = await build_full_context(session, allowed_tags)
        # Falls zu groß: gefilterten Kontext nutzen
        if len(asset_context) > 80_000:
            asset_context, asset_names = await build_filtered_context(
                session, keywords, allowed_tags, max_assets=20
            )
    except Exception as e:
        logger.error("Asset-Kontext Fehler: %s", e)
        asset_context = "Fehler beim Laden der Asset-Daten."
        asset_names = []

    # 2. CVE-Kontext via pgvector
    cve_names = []
    cve_context = ""
    try:
        cve_results = await search_cves(question, top_k=8, session=session)
        if cve_results:
            cve_names = [r["cve_id"] for r in cve_results]
            cve_lines = []
            for r in cve_results:
                cve_lines.append(
                    f"- {r['cve_id']} | CVSS {r['cvss_score']} | {r['severity']}\n"
                    f"  Beschreibung: {r['description'][:300]}"
                )
            cve_context = "RELEVANTE CVEs AUS DER DATENBANK:\n" + "\n".join(cve_lines)
    except Exception as e:
        logger.warning("CVE-Suche Fehler (nicht kritisch): %s", e)

    # 3. Vollständigen Prompt aufbauen
    context_parts = []

    if asset_context:
        context_parts.append(
            f"ASSET-DATEN AUS DER CMDB-DATENBANK ({len(asset_names)} Assets):\n\n"
            + asset_context
        )

    if cve_context:
        context_parts.append(cve_context)

    if not context_parts:
        return {
            "answer": "Die Datenbank enthält noch keine Assets oder CVEs.",
            "sources_assets": [],
            "sources_cves": [],
            "context_size": 0,
        }

    full_context = "\n\n" + ("=" * 60) + "\n\n".join(context_parts)
    context_size = len(full_context)

    prompt = f"""{SYSTEM_PROMPT}

{full_context}

{"=" * 60}

FRAGE: {question}

ANTWORT (nur auf Basis der obigen Datenbankdaten):"""

    logger.info(
        "RAG Kontext: %d Zeichen, %d Assets, %d CVEs",
        context_size, len(asset_names), len(cve_names)
    )

    answer = llm_complete(prompt, max_tokens=1000)

    return {
        "answer": answer,
        "sources_assets": asset_names,
        "sources_cves": cve_names,
        "context_size": context_size,
    }
