"""
Identity Resolver – stabiles Geräte-Matching.

Matching-Strategie (nach Quell-Typ):

  AGENTEN (osquery, mikrotik-collector, fritzbox-collector, snmp):
    1. UUID                          → MATCH  1.00
    2. 1 Stable Key (MAC/Serial/…)   → MATCH  0.95
    3. ≥2 beliebige Felder           → MATCH  0.80
    4. 1 Soft Key                    → CONFLICT 0.40

  ENRICHMENT-QUELLEN (nmap, arp, fritzbox-hosts, mikrotik-arp, lldp, wlan):
    Liefern nur Ergänzungsdaten – kein Überschreiben, keine neuen Assets.
    1. UUID                          → MATCH  1.00
    2. 1 Stable Key (MAC/Serial/…)   → MATCH  0.95
    3. ≥2 beliebige Felder           → MATCH  0.80
    4. 1 Soft Key                    → MATCH  0.50  (kein CONFLICT!)
    5. Kein Treffer                  → SKIP   (kein neues Asset)

Ergebnis:
  - MATCH   → vorhandenes Asset gefunden, Daten mergen
  - CONFLICT → mehrdeutiger Treffer, in Conflict Queue (nur bei Agenten)
  - NEW      → kein Treffer, neues Asset anlegen (nur bei Agenten)
  - SKIP     → kein Treffer bei Enrichment-Quelle → ignorieren

Merge-Strategie:
  - Prioritätsbasiert: höhere Quelle überschreibt niedrigere
  - open_ports: additiv (Union aller gemeldeten Ports)
  - tags: immer additiv
  - sources: Protokoll aller Quellen mit Zeitstempel + gemeldete Felder
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, UTC
from enum import Enum
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from src.models.all_models import Asset


# ---------------------------------------------------------------------------
# Quell-Prioritäten (höher = vertrauenswürdiger)
# ---------------------------------------------------------------------------

SOURCE_PRIORITY: dict[str, int] = {
    "manual":               100,   # Manuell eingetragen – höchste Prio
    "osquery":               80,   # Direkter Agent auf dem System
    "mikrotik-collector":    70,   # MikroTik REST API
    "fritzbox-collector":    65,   # Fritz!Box TR-064
    "snmp":                  60,   # SNMP-Abfrage
    "nmap-discovery":        50,   # Nmap-Scan (aktiv)
    "mikrotik-arp":          40,   # MikroTik ARP-Tabelle
    "fritzbox-hosts":        35,   # Fritz!Box Host-Liste
    "arp-discovered":        30,   # Generische ARP-Discovery
    "lldp":                  25,   # LLDP-Neighbor
    "wlan":                  20,   # WLAN-Registration
    "default":                0,   # Unbekannte Quelle
}

# Felder die durch Quell-Priorität gesteuert werden
PRIORITY_FIELDS = [
    "hostname", "ip_address", "fqdn", "mac_address",
    "os_name", "os_version", "os_arch",
    "manufacturer", "model", "firmware_version",
    "asset_type",   # VM-Erkennung: osquery setzt "vm" wenn Hypervisor erkannt
    "exposure_level", "rack_id", "rack_unit", "location",
]


def _source_prio(source: str) -> int:
    """Gibt die Priorität einer Quelle zurück."""
    return SOURCE_PRIORITY.get(source, SOURCE_PRIORITY["default"])


def _merge_ports(existing: list | None, new_ports: list | None) -> list:
    """
    Merged zwei Port-Listen (Union).
    Gleicher Port+Proto → neuere Daten gewinnen, neue Ports werden hinzugefügt.
    """
    if not new_ports:
        return existing or []
    if not existing:
        return new_ports

    merged = {(p["port"], p.get("proto", "tcp")): p for p in existing}
    for p in new_ports:
        key = (p["port"], p.get("proto", "tcp"))
        if key not in merged:
            merged[key] = p
        else:
            # reachable_from kombinieren
            existing_reach = set(merged[key].get("reachable_from", []))
            new_reach = set(p.get("reachable_from", []))
            merged[key] = {**merged[key], **p,
                           "reachable_from": list(existing_reach | new_reach)}
    return sorted(merged.values(), key=lambda x: x["port"])


# ---------------------------------------------------------------------------
# Matching-Strukturen
# ---------------------------------------------------------------------------

class MatchResult(str, Enum):
    MATCH    = "MATCH"
    CONFLICT = "CONFLICT"
    NEW      = "NEW"


@dataclass
class IdentityResult:
    result: MatchResult
    asset_id: Optional[uuid.UUID] = None
    confidence: float = 0.0
    matched_on: list[str] = None

    def __post_init__(self):
        if self.matched_on is None:
            self.matched_on = []


@dataclass
class DeviceFingerprint:
    """Eingehende Gerätedaten für das Matching."""
    internal_id: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    chassis_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None


# ---------------------------------------------------------------------------
# Quell-Klassifizierung
# ---------------------------------------------------------------------------

# Enrichment-Quellen liefern nur Ergänzungsdaten.
# Sie überschreiben keine hochprioritären Felder, legen keine neuen Assets an
# und erzeugen keinen CONFLICT-Eintrag – stattdessen wird bei einem einzigen
# Soft-Key-Treffer direkt gemergt (confidence 0.50).
ENRICHMENT_SOURCES: set[str] = {
    "nmap-discovery",
    "mikrotik-arp",
    "fritzbox-hosts",
    "arp-discovered",
    "lldp",
    "wlan",
}

# Alle Keys, die für das Matching herangezogen werden
STABLE_KEYS = ["mac_address", "serial_number", "chassis_id"]
SOFT_KEYS   = ["hostname", "ip_address", "fqdn"]
ALL_MATCH_KEYS = STABLE_KEYS + SOFT_KEYS


# ---------------------------------------------------------------------------
# Identity Resolver
# ---------------------------------------------------------------------------

class IdentityResolver:

    def __init__(self, session: AsyncSession):
        self.session = session

    async def resolve(self, fp: DeviceFingerprint, source: str = "default") -> IdentityResult:
        is_enrichment = source in ENRICHMENT_SOURCES

        # 1. Direkt per UUID
        if fp.internal_id:
            try:
                uid = uuid.UUID(fp.internal_id)
                asset = await self.session.get(Asset, uid)
                if asset:
                    return IdentityResult(
                        result=MatchResult.MATCH,
                        asset_id=uid,
                        confidence=1.0,
                        matched_on=["internal_uuid"],
                    )
            except ValueError:
                pass

        # 2. Alle Keys gemeinsam auswerten – zählt Treffer pro Kandidat
        #    Stable und Soft Keys fließen in dieselbe Auswertung.
        field_matches: dict[uuid.UUID, list[str]] = {}
        for key in ALL_MATCH_KEYS:
            value = getattr(fp, key, None)
            if not value:
                continue
            asset = await self._find_by_field(key, value)
            if asset:
                field_matches.setdefault(asset.id, []).append(key)

        # Kein Treffer
        if not field_matches:
            if is_enrichment:
                # Enrichment-Quellen legen keine neuen Assets an
                return IdentityResult(result=MatchResult.NEW, confidence=0.0,
                                      matched_on=["skip:no-match"])
            return IdentityResult(result=MatchResult.NEW, confidence=0.0)

        # Mehrere verschiedene Assets getroffen → echter Konflikt
        if len(field_matches) > 1:
            if is_enrichment:
                # Enrichment-Quellen bei echtem Konflikt lieber skippen
                return IdentityResult(result=MatchResult.NEW, confidence=0.0,
                                      matched_on=["skip:ambiguous"])
            return IdentityResult(
                result=MatchResult.CONFLICT,
                confidence=0.5,
                matched_on=list({k for keys in field_matches.values() for k in keys}),
            )

        # Genau ein Kandidat
        asset_id, matched_keys = next(iter(field_matches.items()))
        has_stable  = any(k in STABLE_KEYS for k in matched_keys)
        match_count = len(matched_keys)

        # ≥1 Stable Key → sehr sicherer Treffer
        if has_stable:
            return IdentityResult(
                result=MatchResult.MATCH,
                asset_id=asset_id,
                confidence=0.95,
                matched_on=matched_keys,
            )

        # ≥2 beliebige Keys → sicherer Treffer
        if match_count >= 2:
            return IdentityResult(
                result=MatchResult.MATCH,
                asset_id=asset_id,
                confidence=0.80,
                matched_on=matched_keys,
            )

        # Genau 1 Soft Key
        if is_enrichment:
            # Enrichment-Quelle: mergen mit niedrigerer Konfidenz, kein Conflict
            return IdentityResult(
                result=MatchResult.MATCH,
                asset_id=asset_id,
                confidence=0.50,
                matched_on=matched_keys,
            )

        # Agent mit nur 1 Soft Key → Operator entscheiden lassen
        return IdentityResult(
            result=MatchResult.CONFLICT,
            asset_id=asset_id,
            confidence=0.40,
            matched_on=matched_keys,
        )

    async def _find_by_field(self, field: str, value: str) -> Optional[Asset]:
        stmt = select(Asset).where(
            getattr(Asset, field) == value,
            Asset.is_active == True,
            Asset.is_archived == False,
        ).limit(1)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def merge_data(self, asset_id: uuid.UUID, new_data: dict) -> Asset:
        """
        Prioritätsbasiertes Merge:
        - Felder werden nur überschrieben wenn die neue Quelle höhere Priorität hat
        - open_ports: Union (alle gemeldeten Ports bleiben erhalten)
        - tags: immer additiv
        - sources: vollständiges Protokoll
        """
        asset = await self.session.get(Asset, asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} nicht gefunden")

        new_source  = new_data.get("source", "default")
        new_prio    = _source_prio(new_source)
        now_iso     = datetime.now(timezone.utc).isoformat()

        # Bisherige Quell-Prioritäten aus sources rekonstruieren
        existing_sources = {s["origin"]: s for s in (asset.sources or [])}
        field_prios: dict[str, int] = {}
        for src_entry in existing_sources.values():
            src_name = src_entry.get("origin", "default")
            src_p = _source_prio(src_name)
            for field in src_entry.get("fields", []):
                field_prios[field] = max(field_prios.get(field, 0), src_p)

        # Felder prioritätsbasiert mergen
        updated_fields = []
        for field in PRIORITY_FIELDS:
            if field not in new_data or new_data[field] is None:
                continue
            current_prio = field_prios.get(field, -1)
            current_val  = getattr(asset, field, None)

            if current_val is None or new_prio >= current_prio:
                setattr(asset, field, new_data[field])
                updated_fields.append(field)

        # open_ports: IMMER mergen (Union)
        if "open_ports" in new_data and new_data["open_ports"]:
            asset.open_ports = _merge_ports(asset.open_ports, new_data["open_ports"])
            flag_modified(asset, "open_ports")  # JSONB Mutation explizit markieren
            updated_fields.append("open_ports")

        # tags: additiv — ABER dynamische Status-Tags werden ersetzt
        if "tags" in new_data and new_data["tags"] is not None:
            existing_tags = set(asset.tags or [])

            # Dynamische Tags die der Collector vollständig kontrolliert:
            # Diese werden ENTFERNT und durch die neuen Werte ersetzt
            DYNAMIC_PREFIXES = (
                "updates:", "security-updates:", "reboot-required", "os:",
                # VM-Erkennung: wird bei jedem osquery-Lauf neu gesetzt
                "vm", "kvm", "vmware", "virtualbox", "xen", "hyper-v",
                "parallels", "bhyve", "lxc", "docker", "aws-ec2", "gcp",
            )
            new_tags_set = set(new_data["tags"])
            # Nur dynamic tags aus dem aktuellen Source entfernen
            if new_source in ("osquery",):
                existing_tags = {
                    t for t in existing_tags
                    if not any(t.startswith(p) or t == p for p in DYNAMIC_PREFIXES)
                }

            existing_tags.update(new_tags_set)
            asset.tags = list(existing_tags)
            flag_modified(asset, "tags")

        # sources: Protokoll aktualisieren
        sources = list(existing_sources.values())
        sources = [s for s in sources if s.get("origin") != new_source]
        sources.append({
            "origin":     new_source,
            "last_seen":  now_iso,
            "priority":   new_prio,
            "fields":     updated_fields,
        })
        asset.sources = sources
        flag_modified(asset, "sources")

        # last_seen_at: immer aktualisieren (auch ohne Daten-Änderungen)
        asset.last_seen_at = datetime.utcnow()

        await self.session.flush()
        return asset
