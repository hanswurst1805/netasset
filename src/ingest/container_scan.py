"""
OSV-Abgleich für Container-Images.

Eigener Abgleich statt scan_asset_osv: Images bringen ihre Distribution im purl
mit (Alpine 3.23, Debian 13 …), OSV braucht genau diese Ecosystem-Variante und
den Quellpaket-Namen samt voller Version. Details (Schweregrad, Fix-Version)
liefert nur /v1/vulns/{id}, querybatch gibt lediglich IDs zurück.
"""

from __future__ import annotations

import asyncio
import logging
import math
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import parse_qs, unquote

import httpx
from sqlalchemy import delete, select

from src.core.database import async_session_factory
from src.models.all_models import CVEEntry, ContainerImage, ContainerPackage, ContainerVuln

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"
BATCH_SIZE = 500
DETAIL_CONCURRENCY = 8

PURL_ECOSYSTEM = {
    "pypi": "PyPI", "npm": "npm", "golang": "Go", "cargo": "crates.io",
    "maven": "Maven", "gem": "RubyGems", "composer": "Packagist", "nuget": "NuGet",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def parse_purl(purl: str) -> Optional[dict]:
    """pkg:type/namespace/name@version?qualifiers → Bestandteile."""
    if not purl or not purl.startswith("pkg:"):
        return None
    rest, _, query = purl[4:].partition("?")
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    ptype, _, tail = path.partition("/")
    namespace, _, name = tail.rpartition("/")
    qualifiers = {k: v[0] for k, v in parse_qs(query).items()}
    return {
        "type": ptype.lower(),
        "namespace": unquote(namespace),
        "name": unquote(name),
        "version": unquote(version),
        "qualifiers": qualifiers,
    }


def _distro_ecosystem(ptype: str, namespace: str, distro: str) -> Optional[str]:
    """(apk, alpine, alpine-3.23.6) → Alpine:v3.23; (deb, debian, debian-13.7) → Debian:13."""
    version = distro.partition("-")[2]
    if ptype == "apk" and namespace == "alpine":
        parts = version.split(".")
        return f"Alpine:v{parts[0]}.{parts[1]}" if len(parts) >= 2 else None
    if ptype == "deb" and namespace == "debian":
        major = version.split(".")[0]
        return f"Debian:{major}" if major else None
    if ptype == "deb" and namespace == "ubuntu":
        if not version:
            return None
        major, _, minor = version.partition(".")
        lts = minor.startswith("04") and major.isdigit() and int(major) % 2 == 0
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    return None


def osv_query_for(purl: str) -> Optional[tuple[str, str, str]]:
    """purl → (ecosystem, name, version) für OSV, None wenn OSV es nicht kennt."""
    p = parse_purl(purl)
    if not p or not p["name"] or not p["version"]:
        return None
    q = p["qualifiers"]

    if p["type"] in ("apk", "deb"):
        eco = _distro_ecosystem(p["type"], p["namespace"], q.get("distro", ""))
        if not eco:
            return None
        # OSV führt Distributionspakete unter dem Quellpaket
        name, _, upstream_version = q.get("upstream", "").partition("@")
        version = upstream_version or p["version"]
        if q.get("epoch") and ":" not in version:
            version = f'{q["epoch"]}:{version}'
        return eco, name or p["name"], version

    eco = PURL_ECOSYSTEM.get(p["type"])
    if not eco:
        return None
    version = p["version"]
    name = p["name"]
    if p["type"] == "golang":
        version = version.lstrip("v")
        name = f'{p["namespace"]}/{name}' if p["namespace"] else name
    elif p["type"] == "npm" and p["namespace"]:
        name = f'{p["namespace"]}/{name}'
    elif p["type"] == "maven" and p["namespace"]:
        name = f'{p["namespace"]}:{name}'
    elif p["type"] == "composer" and p["namespace"]:
        name = f'{p["namespace"]}/{name}'
    return eco, name, version


def cvss3_base_score(vector: str) -> Optional[float]:
    """Base Score aus einem CVSS-3.x-Vektor."""
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        impact_sub = 1 - (
            (1 - {"H": 0.56, "L": 0.22, "N": 0}[m["C"]])
            * (1 - {"H": 0.56, "L": 0.22, "N": 0}[m["I"]])
            * (1 - {"H": 0.56, "L": 0.22, "N": 0}[m["A"]])
        )
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        exploitability = (
            8.22 * {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
            * {"L": 0.77, "H": 0.44}[m["AC"]] * pr * {"N": 0.85, "R": 0.62}[m["UI"]]
        )
    except (KeyError, ValueError):
        return None
    impact = (7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15) if changed else 6.42 * impact_sub
    if impact <= 0:
        return 0.0
    score = min((1.08 if changed else 1) * (impact + exploitability), 10)
    return math.ceil(score * 10 - 1e-9) / 10


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def _normalize_label(label: Optional[str]) -> Optional[str]:
    label = (label or "").strip().upper()
    if label in ("MODERATE", "MEDIUM"):
        return "MEDIUM"
    if label in ("CRITICAL", "HIGH", "LOW"):
        return label
    return None


def vuln_rating(vuln: dict) -> tuple[Optional[float], str]:
    """(CVSS, Schweregrad) aus einem OSV-Datensatz."""
    scores = []
    for sev in vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS_V3"):
            s = cvss3_base_score(sev.get("score", ""))
            if s is not None:
                scores.append(s)
    if scores:
        return max(scores), severity_from_score(max(scores))
    labels = [_normalize_label((vuln.get("database_specific") or {}).get("severity"))]
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "Ubuntu":
            labels.append(_normalize_label(sev.get("score")))
    for aff in vuln.get("affected") or []:
        labels.append(_normalize_label((aff.get("ecosystem_specific") or {}).get("severity")))
    for level in SEVERITY_ORDER:
        if level in labels:
            return None, level
    return None, "UNKNOWN"


def fixed_version(vuln: dict, ecosystem: str, name: str) -> Optional[str]:
    fixed = None
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed = event["fixed"]
    return fixed


def canonical_id(vuln: dict) -> str:
    """CVE-ID bevorzugen, damit DSA/GHSA zum selben CVE nur einmal zählen."""
    vuln_id = vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for key in ("aliases", "upstream"):
        for ref in vuln.get(key) or []:
            if ref.startswith("CVE-"):
                return ref
    return vuln_id


async def _query_ids(client: httpx.AsyncClient, queries: list[tuple[str, str, str]]) -> list[list[str]]:
    """OSV querybatch inkl. Blättern. Eine ID-Liste pro Query."""
    result: list[list[str]] = [[] for _ in queries]
    for start in range(0, len(queries), BATCH_SIZE):
        chunk = queries[start:start + BATCH_SIZE]
        pending = list(range(len(chunk)))
        tokens: dict[int, str] = {}
        while pending:
            payload = [
                {"version": chunk[i][2], "package": {"ecosystem": chunk[i][0], "name": chunk[i][1]},
                 **({"page_token": tokens[i]} if i in tokens else {})}
                for i in pending
            ]
            resp = await client.post(f"{OSV_API}/querybatch", json={"queries": payload}, timeout=60)
            resp.raise_for_status()
            next_pending = []
            for i, entry in zip(pending, resp.json().get("results", [])):
                result[start + i].extend(v["id"] for v in entry.get("vulns") or [])
                if entry.get("next_page_token"):
                    tokens[i] = entry["next_page_token"]
                    next_pending.append(i)
            pending = next_pending
    return result


async def _fetch_details(client: httpx.AsyncClient, ids: set[str], cache: dict[str, dict]) -> None:
    sem = asyncio.Semaphore(DETAIL_CONCURRENCY)

    async def one(vuln_id: str) -> None:
        async with sem:
            for attempt in range(3):
                try:
                    resp = await client.get(f"{OSV_API}/vulns/{vuln_id}", timeout=30)
                    resp.raise_for_status()
                    cache[vuln_id] = resp.json()
                    return
                except httpx.HTTPError as e:
                    if attempt == 2:
                        log.warning("OSV-Details %s: %s", vuln_id, e)
                    await asyncio.sleep(1 + attempt)

    await asyncio.gather(*(one(i) for i in ids if i not in cache))


async def scan_images(image_pks: list[uuid.UUID]) -> dict:
    """Gleicht Images gegen OSV ab und ersetzt ihre Treffer. Details werden geteilt."""
    cache: dict[str, dict] = {}
    totals = {"images": 0, "packages": 0, "vulns": 0, "failed": 0}
    async with httpx.AsyncClient() as client:
        for pk in image_pks:
            async with async_session_factory() as session:
                image = await session.get(ContainerImage, pk)
                if image is None:
                    continue
                packages = (await session.execute(
                    select(ContainerPackage).where(ContainerPackage.image_pk == pk)
                )).scalars().all()

                queries: dict[tuple[str, str, str], list[ContainerPackage]] = {}
                for pkg in packages:
                    q = osv_query_for(pkg.purl or "")
                    if q:
                        queries.setdefault(q, []).append(pkg)
                keys = list(queries)
                try:
                    id_lists = await _query_ids(client, keys)
                    await _fetch_details(client, {i for ids in id_lists for i in ids}, cache)
                except httpx.HTTPError as e:
                    # Alte Treffer behalten: lieber veraltet als fälschlich „sauber“
                    log.error("OSV-Abgleich %s fehlgeschlagen: %s", image.image_ref, e)
                    totals["failed"] += 1
                    continue

                findings: dict[tuple[str, str], ContainerVuln] = {}
                for key, ids in zip(keys, id_lists):
                    eco, name, _ = key
                    for osv_id in ids:
                        vuln = cache.get(osv_id)
                        if vuln is None or vuln.get("withdrawn"):
                            continue
                        canon = canonical_id(vuln)
                        cvss, severity = vuln_rating(vuln)
                        fixed = fixed_version(vuln, eco, name)
                        current = findings.get((canon, name))
                        if current is not None:
                            # Mehrere Advisories zum selben CVE: das aussagekräftigste behalten
                            if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(current.severity):
                                current.severity, current.cvss = severity, cvss
                            current.fixed_version = current.fixed_version or fixed
                            continue
                        findings[(canon, name)] = ContainerVuln(
                            image_pk=pk, vuln_id=canon[:100], osv_id=osv_id[:100], pkg_name=name[:300],
                            pkg_version=queries[key][0].pkg_version[:200], ecosystem=eco.split(":")[0],
                            severity=severity, cvss=cvss, fixed_version=(fixed or "")[:200] or None,
                            summary=(vuln.get("summary") or vuln.get("details") or "")[:1000],
                        )

                # Debian/Alpine liefern oft keinen Schweregrad – NVD-Daten aus der DB nutzen
                unknown = [f for f in findings.values() if f.severity == "UNKNOWN" and f.vuln_id.startswith("CVE-")]
                if unknown:
                    rows = (await session.execute(
                        select(CVEEntry.cve_id, CVEEntry.cvss_score, CVEEntry.severity)
                        .where(CVEEntry.cve_id.in_({f.vuln_id for f in unknown}))
                    )).all()
                    known = {r.cve_id: r for r in rows}
                    for f in unknown:
                        row = known.get(f.vuln_id)
                        if row and row.cvss_score:
                            f.cvss = row.cvss_score
                            f.severity = severity_from_score(row.cvss_score)

                await session.execute(delete(ContainerVuln).where(ContainerVuln.image_pk == pk))
                session.add_all(findings.values())
                image.osv_at = datetime.utcnow()
                await session.commit()

                totals["images"] += 1
                totals["packages"] += len(packages)
                totals["vulns"] += len(findings)
                log.info("Container-OSV: %s – %d Pakete, %d Schwachstellen",
                         image.image_ref, len(packages), len(findings))
    return totals


async def scan_all_images() -> dict:
    async with async_session_factory() as session:
        pks = list((await session.execute(select(ContainerImage.id))).scalars().all())
    return await scan_images(pks)
