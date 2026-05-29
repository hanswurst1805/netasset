from __future__ import annotations
"""NVD JSON 2.0 Feed Importer – liest CVEs aus der NVD API und speichert mit Embedding."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.database import async_session_factory
from src.models.all_models import CVEEntry
from src.rag.embedder import embed_batch

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_cve(item: dict) -> Optional[dict]:
    """Parsed ein NVD CVE-Item in unser internes Format."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id")
    if not cve_id:
        return None

    # Beschreibung (bevorzuge Englisch)
    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS Score (v3.1 bevorzugt, dann v3.0, dann v2)
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    cvss_vector = None
    attack_vector = None
    severity = None

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if metric_list:
            m = metric_list[0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")
            attack_vector = m.get("attackVector")
            severity = metric_list[0].get("baseSeverity") or m.get("baseSeverity")
            break

    # Betroffene Pakete aus CPE
    affected_pkgs = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    cpe = cpe_match.get("criteria", "")
                    parts = cpe.split(":")
                    pkg_name = parts[4] if len(parts) > 4 else ""
                    affected_pkgs.append({
                        "cpe": cpe,
                        "pkg": pkg_name,
                        "min": cpe_match.get("versionStartIncluding", ""),
                        "max": cpe_match.get("versionEndIncluding", ""),
                    })

    def _parse_dt(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "attack_vector": attack_vector,
        "severity": severity,
        "affected_pkgs": affected_pkgs or None,
        "published_at": _parse_dt(cve_data.get("published")),
        "modified_at": _parse_dt(cve_data.get("lastModified")),
        "raw": item,
    }


async def fetch_nvd_page(
    client: httpx.AsyncClient,
    start_index: int,
    pub_start: Optional[str] = None,
    pub_end: Optional[str] = None,
) -> dict:
    params: dict = {"startIndex": start_index, "resultsPerPage": 2000}
    if pub_start:
        params["pubStartDate"] = pub_start
    if pub_end:
        params["pubEndDate"] = pub_end
    if settings.nvd_api_key:
        params["apiKey"] = settings.nvd_api_key

    resp = await client.get(NVD_BASE, params=params, timeout=60.0)
    resp.raise_for_status()
    return resp.json()


async def import_cves(days: int = 7, session: AsyncSession | None = None):
    """
    Importiert CVEs der letzten `days` Tage aus dem NVD-Feed.
    Generiert Embeddings und speichert in die DB.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    logger.info("NVD-Import: %s bis %s", pub_start, pub_end)

    async def _run(s: AsyncSession):
        async with httpx.AsyncClient() as client:
            start_index = 0
            total_imported = 0

            while True:
                data = await fetch_nvd_page(client, start_index, pub_start, pub_end)
                items = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                logger.info(
                    "Seite %d: %d/%d CVEs", start_index // 2000 + 1, start_index + len(items), total_results
                )

                # Embeddings für alle CVEs auf einmal
                parsed = [_parse_cve(i) for i in items if _parse_cve(i)]
                descriptions = [p["description"] for p in parsed]

                if descriptions:
                    vectors = embed_batch(descriptions)

                    for p, vec in zip(parsed, vectors):
                        existing = await s.get(CVEEntry, p["cve_id"])
                        if existing:
                            for k, v in p.items():
                                if k != "cve_id":
                                    setattr(existing, k, v)
                            existing.embedding = vec
                        else:
                            entry = CVEEntry(**p, embedding=vec)
                            s.add(entry)
                        total_imported += 1

                    await s.flush()
                    logger.info("%d CVEs importiert", total_imported)

                start_index += len(items)
                if start_index >= total_results:
                    break

                # NVD Rate-Limit: ohne API-Key 5 req/30s
                await asyncio.sleep(6 if not settings.nvd_api_key else 0.6)

        logger.info("Import abgeschlossen: %d CVEs", total_imported)
        return total_imported

    if session:
        return await _run(session)

    async with async_session_factory() as s:
        result = await _run(s)
        await s.commit()
        return result
