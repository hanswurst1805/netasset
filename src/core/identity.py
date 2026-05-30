"""
Identity Resolver – stabiles Geräte-Matching.

Priorität:
  1. internal UUID (wenn mitgeliefert)
  2. Stable Keys: mac_address, serial_number, chassis_id
  3. Soft Keys: hostname + ip kombiniert (≥2 Treffer → Kandidat)

Ergebnis:
  - MATCH   → vorhandenes Asset gefunden, Daten mergen
  - CONFLICT → mehrdeutiger Treffer, in Conflict Queue
  - NEW      → kein Treffer, neues Asset anlegen

Merge-Strategie:
  - Prioritätsbasiert: höhere Quelle überschreibt niedrigere
  - open_ports: additive (Union aller gemeldeten Ports)
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
# Identity Resolver
# ---------------------------------------------------------------------------

class IdentityResolver:
    STABLE_KEYS    = ["mac_address", "serial_number", "chassis_id"]
    SOFT_KEYS      = ["hostname", "ip_address", "fqdn"]
    SOFT_THRESHOLD = 2

    def __init__(self, session: AsyncSession):
        self.session = session

    async def resolve(self, fp: DeviceFingerprint) -> IdentityResult:
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

        # 2. Stable Keys
        for key in self.STABLE_KEYS:
            value = getattr(fp, key)
            if not value:
                continue
            asset = await self._find_by_field(key, value)
            if asset:
                return IdentityResult(
                    result=MatchResult.MATCH,
                    asset_id=asset.id,
                    confidence=0.95,
                    matched_on=[key],
                )

        # 3. Soft Keys
        soft_matches: dict[uuid.UUID, list[str]] = {}
        for key in self.SOFT_KEYS:
            value = getattr(fp, key)
            if not value:
                continue
            asset = await self._find_by_field(key, value)
            if asset:
                soft_matches.setdefault(asset.id, []).append(key)

        if soft_matches:
            strong = {aid: keys for aid, keys in soft_matches.items()
                      if len(keys) >= self.SOFT_THRESHOLD}
            if len(strong) == 1:
                asset_id, matched_keys = next(iter(strong.items()))
                return IdentityResult(
                    result=MatchResult.MATCH,
                    asset_id=asset_id,
                    confidence=0.80,
                    matched_on=matched_keys,
                )
            if len(soft_matches) > 1:
                return IdentityResult(
                    result=MatchResult.CONFLICT,
                    confidence=0.5,
                    matched_on=list({k for keys in soft_matches.values() for k in keys}),
                )
            if len(soft_matches) == 1:
                asset_id, matched_keys = next(iter(soft_matches.items()))
                return IdentityResult(
                    result=MatchResult.CONFLICT,
                    asset_id=asset_id,
                    confidence=0.4,
                    matched_on=matched_keys,
                )

        return IdentityResult(result=MatchResult.NEW, confidence=0.0)

    async def _find_by_field(self, field: str, value: str) -> Optional[Asset]:
        stmt = select(Asset).where(
            getattr(Asset, field) == value,
            Asset.is_active == True,
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

        # tags: IMMER additiv
        if "tags" in new_data and new_data["tags"]:
            existing_tags = set(asset.tags or [])
            existing_tags.update(new_data["tags"])
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
