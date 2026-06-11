"""
OSV (Open Source Vulnerabilities) CVE-Mapping.

Abfragt https://api.osv.dev für installierte Pakete und speichert
CVE-Impacts in der Datenbank.

Kein API-Key nötig. Unterstützt: PyPI, npm, Maven, Go, Debian,
Ubuntu, Alpine, RedHat, crates.io, RubyGems, NuGet, etc.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.all_models import Asset, CVEEntry, CVEImpact, SBOMEntry
from src.rag.cve_impact import (
    _calc_risk_score,
    _is_vm,
    _is_vm_irrelevant_pkg,
    _risk_level,
    get_hide_vm_microcode_setting,
)

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"

# Mapping: (pkg_source, pkg_type) → OSV-Ecosystem
ECOSYSTEM_MAP: dict[tuple[str, str], str] = {
    ("dpkg", "os-package"):     "Debian",
    ("apt", "os-package"):      "Debian",
    ("rpm", "os-package"):      "RedHat",
    ("yum", "os-package"):      "RedHat",
    ("dnf", "os-package"):      "RedHat",
    ("pip", "library"):         "PyPI",
    ("pip", "application"):     "PyPI",
    ("pip3", "library"):        "PyPI",
    ("npm", "library"):         "npm",
    ("npm", "application"):     "npm",
    ("yarn", "library"):        "npm",
    ("maven", "library"):       "Maven",
    ("gradle", "library"):      "Maven",
    ("go", "library"):          "Go",
    ("cargo", "library"):       "crates.io",
    ("gem", "library"):         "RubyGems",
    ("nuget", "library"):       "NuGet",
    ("composer", "library"):    "Packagist",
    ("homebrew", "application"):"Homebrew",
    ("homebrew", "library"):    "Homebrew",
    ("apk", "os-package"):      "Alpine",
}

# Fallback: nur nach Source
SOURCE_ECOSYSTEM: dict[str, str] = {
    "dpkg": "Debian", "apt": "Debian",
    "rpm": "RedHat", "yum": "RedHat", "dnf": "RedHat",
    "pip": "PyPI", "pip3": "PyPI",
    "npm": "npm", "yarn": "npm",
    "maven": "Maven", "gradle": "Maven",
    "go": "Go", "cargo": "crates.io",
    "gem": "RubyGems", "nuget": "NuGet",
    "composer": "Packagist",
    "homebrew": "Homebrew",
    "apk": "Alpine",
}


def parse_cpe(cpe: str) -> dict:
    """
    Parsed einen CPE-2.3-String in seine Komponenten.
    cpe:2.3:a:vendor:product:version:... → {vendor, product, version}
    """
    parts = cpe.split(":")
    if len(parts) < 6:
        return {}
    return {
        "part":    parts[2],  # a=application, o=os, h=hardware
        "vendor":  parts[3],
        "product": parts[4],
        "version": parts[5] if parts[5] != "*" else "",
    }


def _get_ecosystem(entry: SBOMEntry, os_name: str = "") -> Optional[str]:
    src = (entry.source or "").lower()
    typ = (entry.pkg_type or "").lower()
    eco = ECOSYSTEM_MAP.get((src, typ)) or SOURCE_ECOSYSTEM.get(src)

    # Ubuntu hat ein eigenes OSV-Ecosystem — viel präziser als Debian.
    # Ubuntu-Packages die als "Debian" klassifiziert würden → "Ubuntu" verwenden.
    # Das Debian-Ecosystem enthält viele CVEs die Ubuntu bereits gepatcht hat.
    if eco == "Debian" and "ubuntu" in os_name.lower():
        eco = "Ubuntu"

    return eco


# Debian-Advisory-Präfixe: nicht automatisch auf Ubuntu übertragbar
DEBIAN_ONLY_PREFIXES = ("DEBIAN-", "DLA-", "DSA-")


def _cve_aliases(vuln: dict) -> list[str]:
    """
    Sammelt CVE-IDs aus 'aliases' und 'upstream'.
    DSA-/DEBIAN-CVE-Records tragen ihre CVE-Nummern in 'upstream', nicht in 'aliases'.
    """
    ids: list[str] = []
    for key in ("aliases", "upstream"):
        for ref in vuln.get(key, []) or []:
            if ref.startswith("CVE-") and ref not in ids:
                ids.append(ref)
    return ids


def _parse_severity(osv_vuln: dict) -> tuple[float | None, str | None]:
    """Extrahiert CVSS-Score und Severity aus einem OSV-Vuln-Objekt."""
    cvss = None
    severity = None
    for sev in osv_vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            # CVSS-Vektor → Score extrahieren (z.B. CVSS:3.1/AV:N/.../7.5)
            parts = score_str.split("/")
            try:
                cvss = float(parts[-1])
            except (ValueError, IndexError):
                pass
            if cvss:
                if cvss >= 9.0: severity = "CRITICAL"
                elif cvss >= 7.0: severity = "HIGH"
                elif cvss >= 4.0: severity = "MEDIUM"
                else: severity = "LOW"
    return cvss, severity


async def query_osv_batch(
    packages: list[dict],  # [{"name": ..., "version": ..., "ecosystem": ...}]
    timeout: int = 30,
) -> list[list[dict]]:
    """
    Batch-Abfrage bei OSV. Gibt eine Liste von Vuln-Listen zurück
    (eine pro Paket, gleiche Reihenfolge).
    """
    if not packages:
        return []

    queries = [
        {
            "version": p["version"],
            "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
        }
        for p in packages
    ]

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{OSV_API}/querybatch",
                json={"queries": queries},
                timeout=timeout,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            return [r.get("vulns", []) for r in results]
        except Exception as e:
            log.warning("OSV-Batch-Fehler: %s", e)
            return [[] for _ in packages]


async def scan_asset_osv(
    asset_id: str,
    session: AsyncSession,
    max_pkgs: int = 200,
) -> dict:
    """
    Scannt alle SBOM-Einträge eines Assets gegen OSV.
    Legt CVEEntry + CVEImpact in der DB an.
    Gibt Statistiken zurück.
    """
    import uuid
    asset = await session.get(Asset, uuid.UUID(asset_id))
    if not asset:
        raise ValueError(f"Asset {asset_id} nicht gefunden")

    # SBOM laden
    sbom_result = await session.execute(
        select(SBOMEntry).where(SBOMEntry.asset_id == asset.id)
    )
    sbom = sbom_result.scalars().all()

    # Pakete mit bekanntem Ecosystem vorbereiten
    pkg_list = []
    entry_map = []  # Zuordnung: index → SBOMEntry
    os_name = asset.os_name or ""
    log.info("OSV-Scan: %s (OS: %s)", asset.hostname or asset_id, os_name)

    # Aufräumen: Debian-spezifische Advisory-IDs (DSA-/DEBIAN-CVE-*/DLA-*) aus
    # früheren Scans sind für Ubuntu-Assets nicht aussagekräftig
    if "ubuntu" in os_name.lower():
        from sqlalchemy import or_
        await session.execute(
            delete(CVEImpact).where(
                CVEImpact.asset_id == asset.id,
                or_(*[CVEImpact.cve_id.startswith(p) for p in DEBIAN_ONLY_PREFIXES]),
            )
        )

    for entry in sbom[:max_pkgs]:
        # Strategie 1: direkt über bekanntes Ecosystem (OS-aware)
        eco = _get_ecosystem(entry, os_name)

        # Strategie 2: CPE-basiert für Windows/macOS-Programme ohne Ecosystem
        if not eco and entry.cpe:
            parsed = parse_cpe(entry.cpe)
            product = parsed.get("product", "")
            version = parsed.get("version", "") or entry.pkg_version
            # Versuche bekannte CPE-Vendor→Ecosystem Mappings
            vendor = parsed.get("vendor", "").lower()
            # Für bekannte Open-Source-Produkte über CPE
            if product:
                # Keine direkte Ecosystem-Zuordnung möglich → überspringen
                # (wird durch KEV-Scan abgedeckt)
                pass

        if not eco:
            continue

        # Debian-Suffixe entfernen: 1.2.3-4ubuntu1 → 1.2.3
        version = entry.pkg_version.split("+")[0].split("~")[0].split("-")[0]
        if not version:
            version = entry.pkg_version

        pkg_list.append({"name": entry.pkg_name, "version": version, "ecosystem": eco})
        entry_map.append(entry)

    if not pkg_list:
        log.info("Keine mapbaren Pakete für Asset %s", asset.hostname)
        return {"asset": asset.hostname, "scanned": 0, "vulns_found": 0, "new_cves": 0}

    log.info("OSV-Scan: %s — %d Pakete", asset.hostname or asset_id, len(pkg_list))

    # Batch-Abfrage in Chunks von 100
    all_vulns: list[list[dict]] = []
    chunk_size = 100
    for i in range(0, len(pkg_list), chunk_size):
        chunk = pkg_list[i:i + chunk_size]
        chunk_vulns = await query_osv_batch(chunk)
        all_vulns.extend(chunk_vulns)

    # Ergebnisse verarbeiten
    new_cves = 0
    vulns_found = 0
    found_cves: list[dict] = []   # für die Rückgabe

    is_ubuntu = "ubuntu" in os_name.lower()
    hide_vm_microcode = await get_hide_vm_microcode_setting(session)
    is_vm_asset = _is_vm(asset)

    for entry, vulns in zip(entry_map, all_vulns):
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            if not vuln_id:
                continue

            cve_aliases = _cve_aliases(vuln)

            # Für Ubuntu-Systeme: Debian-spezifische Advisories (DSA-/DEBIAN-CVE-*/DLA-*)
            # sind nicht Ubuntu-spezifisch — die "fixed"-Versionen aus Debian lassen sich
            # nicht zuverlässig mit Ubuntus eigenem Versionsschema (...ubuntuX.Y) vergleichen.
            if is_ubuntu and vuln_id.startswith(DEBIAN_ONLY_PREFIXES):
                if not cve_aliases:
                    continue  # Kein CVE-Bezug → für Ubuntu nicht relevant
                vuln_id = cve_aliases[0]
            vulns_found += 1

            # Bevorzuge echte CVE-IDs aus aliases/upstream (DSA-/DEBIAN-CVE-Records
            # tragen ihre CVE-Nummern in "upstream", nicht in "aliases")
            cve_id = cve_aliases[0] if cve_aliases else vuln_id

            # CVEEntry anlegen / aktualisieren
            existing_cve = await session.get(CVEEntry, cve_id)
            if not existing_cve:
                cvss, severity = _parse_severity(vuln)
                description = vuln.get("summary") or vuln.get("details") or ""
                description = description[:2000]

                existing_cve = CVEEntry(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss,
                    severity=severity,
                    affected_pkgs=[{
                        "pkg": entry.pkg_name,
                        "cpe": entry.cpe or "",
                        "min": "",
                        "max": entry.pkg_version,
                    }],
                    published_at=datetime.utcnow(),
                    modified_at=datetime.utcnow(),
                    raw={"osv_id": vuln_id, "source": "osv"},
                )
                session.add(existing_cve)
                new_cves += 1
                await session.flush()

            # Microcode/Firmware-CVEs sind auf VMs/Containern nicht exploitierbar
            # und werden komplett ausgeblendet (kein CVEImpact-Eintrag)
            if hide_vm_microcode and is_vm_asset and _is_vm_irrelevant_pkg(entry.pkg_name):
                await session.execute(
                    delete(CVEImpact).where(
                        CVEImpact.cve_id == cve_id,
                        CVEImpact.asset_id == asset.id,
                    )
                )
                continue

            # Risk Score berechnen
            cvss_val = existing_cve.cvss_score or 5.0
            risk_score = _calc_risk_score(cvss_val, asset.exposure_level, asset.open_ports)
            risk_level = _risk_level(risk_score)

            # CVEImpact anlegen / aktualisieren
            existing_impact = (await session.execute(
                select(CVEImpact).where(
                    CVEImpact.cve_id == cve_id,
                    CVEImpact.asset_id == asset.id,
                )
            )).scalar_one_or_none()

            if existing_impact:
                existing_impact.risk_score = risk_score
                existing_impact.risk_level = risk_level
                existing_impact.affected_pkg = entry.pkg_name
                existing_impact.affected_ver = entry.pkg_version
            else:
                session.add(CVEImpact(
                    cve_id=cve_id,
                    asset_id=asset.id,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    affected_pkg=entry.pkg_name,
                    affected_ver=entry.pkg_version,
                    reasoning=f"OSV-Scan: {vuln_id} betrifft {entry.pkg_name} {entry.pkg_version}",
                ))

            found_cves.append({
                "cve_id":      cve_id,
                "pkg_name":    entry.pkg_name,
                "pkg_version": entry.pkg_version,
                "risk_level":  risk_level,
                "risk_score":  risk_score,
                "cvss":        existing_cve.cvss_score,
                "description": (existing_cve.description or "")[:120],
                "is_new":      new_cves > 0 and cve_id not in {c["cve_id"] for c in found_cves},
            })

    await session.flush()
    log.info(
        "OSV-Scan fertig: %s — %d Pakete, %d Schwachstellen, %d neue CVEs",
        asset.hostname or asset_id, len(pkg_list), vulns_found, new_cves,
    )
    # Nach Risiko sortieren
    found_cves.sort(key=lambda c: c["risk_score"] or 0, reverse=True)

    return {
        "asset":      asset.hostname or asset_id,
        "scanned":    len(pkg_list),
        "vulns_found": vulns_found,
        "new_cves":   new_cves,
        "packages":   [{"name": p["name"], "version": p["version"], "ecosystem": p["ecosystem"]} for p in pkg_list],
        "cves":       found_cves,
    }


async def scan_all_assets_osv(session: AsyncSession) -> dict:
    """Scannt alle aktiven Assets mit SBOM."""
    result = await session.execute(
        select(Asset).where(Asset.is_active == True, Asset.is_archived == False)
    )
    assets = result.scalars().all()
    total = {"scanned_assets": 0, "scanned_pkgs": 0, "vulns_found": 0, "new_cves": 0}
    for asset in assets:
        stats = await scan_asset_osv(str(asset.id), session)
        total["scanned_assets"] += 1
        total["scanned_pkgs"] += stats["scanned"]
        total["vulns_found"] += stats["vulns_found"]
        total["new_cves"] += stats["new_cves"]
    return total
