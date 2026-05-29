from __future__ import annotations
"""pgvector-basierte CVE-Suche."""

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import async_session_factory
from src.models.all_models import CVEEntry


async def search_cves(
    query: str,
    top_k: int = 10,
    min_cvss: float = 0.0,
    session: AsyncSession | None = None,
) -> list[dict]:
    """
    Semantische Suche über CVE-Beschreibungen via pgvector.
    Gibt CVEs absteigend nach Cosine-Similarity sortiert zurück.
    """
    from src.rag.embedder import embed  # lazy – sentence-transformers erst bei Aufruf
    query_vec = embed(query)

    async def _run(s: AsyncSession) -> list[dict]:
        stmt = (
            select(
                CVEEntry,
                CVEEntry.embedding.cosine_distance(query_vec).label("distance"),
            )
            .where(CVEEntry.cvss_score >= min_cvss)
            .where(CVEEntry.embedding.is_not(None))
            .order_by("distance")
            .limit(top_k)
        )
        result = await s.execute(stmt)
        rows = result.all()
        return [
            {
                "cve_id": row.CVEEntry.cve_id,
                "description": row.CVEEntry.description,
                "cvss_score": row.CVEEntry.cvss_score,
                "severity": row.CVEEntry.severity,
                "similarity": round(1.0 - row.distance, 4),
            }
            for row in rows
        ]

    if session:
        return await _run(session)

    async with async_session_factory() as s:
        return await _run(s)


async def find_cves_for_package(
    pkg_name: str,
    pkg_version: str,
    session: AsyncSession,
    top_k: int = 5,
) -> list[CVEEntry]:
    """
    Findet CVEs die zu einem Paket passen.
    Kombiniert Paketname-Suche mit Semantic-Similarity.
    """
    from src.rag.embedder import embed
    query = f"{pkg_name} {pkg_version} vulnerability"
    query_vec = embed(query)

    stmt = (
        select(CVEEntry)
        .where(CVEEntry.embedding.is_not(None))
        .order_by(CVEEntry.embedding.cosine_distance(query_vec))
        .limit(top_k * 3)  # Mehr laden, dann filtern
    )
    result = await session.execute(stmt)
    candidates = result.scalars().all()

    # Nachfiltern: nur CVEs mit passendem affected_pkgs
    matched = []
    for cve in candidates:
        if not cve.affected_pkgs:
            matched.append(cve)  # Kein Filter-Info → potentiell relevant
            continue
        for pkg_info in cve.affected_pkgs:
            if pkg_name.lower() in pkg_info.get("pkg", "").lower():
                matched.append(cve)
                break

    return matched[:top_k]
