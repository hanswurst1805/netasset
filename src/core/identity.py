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
"""

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.all_models import Asset


class MatchResult(str, Enum):
    MATCH    = "MATCH"
    CONFLICT = "CONFLICT"
    NEW      = "NEW"


@dataclass
class IdentityResult:
    result: MatchResult
    asset_id: Optional[uuid.UUID] = None
    confidence: float = 0.0
    matched_on: list[str] = None  # welche Keys haben gematcht

    def __post_init__(self):
        if self.matched_on is None:
            self.matched_on = []


@dataclass
class DeviceFingerprint:
    """Eingehende Gerätedaten für das Matching."""
    internal_id: Optional[str] = None    # UUID falls bekannt
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    chassis_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None


class IdentityResolver:
    """
    Löst Geräte-Identitäten auf.
    Verwendung:
        resolver = IdentityResolver(db_session)
        result = await resolver.resolve(fingerprint)
    """

    STABLE_KEYS  = ["mac_address", "serial_number", "chassis_id"]
    SOFT_KEYS    = ["hostname", "ip_address", "fqdn"]
    SOFT_THRESHOLD = 2  # Wie viele Soft-Key-Matches nötig für Kandidat

    def __init__(self, session: AsyncSession):
        self.session = session

    async def resolve(self, fp: DeviceFingerprint) -> IdentityResult:
        """Hauptmethode: Fingerprint → IdentityResult."""

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

        # 2. Stable Keys (einzeln reichen für sicheres Match)
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

        # 3. Soft Keys – Kombination nötig
        soft_matches: dict[uuid.UUID, list[str]] = {}
        for key in self.SOFT_KEYS:
            value = getattr(fp, key)
            if not value:
                continue
            asset = await self._find_by_field(key, value)
            if asset:
                soft_matches.setdefault(asset.id, []).append(key)

        if soft_matches:
            # Nur ein Asset matcht auf ≥ SOFT_THRESHOLD Keys → sicheres Match
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

            # Mehrere Assets matchen → Conflict
            if len(soft_matches) > 1:
                return IdentityResult(
                    result=MatchResult.CONFLICT,
                    confidence=0.5,
                    matched_on=list({k for keys in soft_matches.values() for k in keys}),
                )

            # Genau ein Asset, aber nur 1 Soft Key → schwacher Kandidat
            if len(soft_matches) == 1:
                asset_id, matched_keys = next(iter(soft_matches.items()))
                return IdentityResult(
                    result=MatchResult.CONFLICT,  # zur Bestätigung flaggen
                    asset_id=asset_id,
                    confidence=0.4,
                    matched_on=matched_keys,
                )

        # 4. Kein Match
        return IdentityResult(result=MatchResult.NEW, confidence=0.0)

    async def _find_by_field(self, field: str, value: str) -> Optional[Asset]:
        """Sucht ein Asset anhand eines einzelnen Feldes."""
        stmt = select(Asset).where(
            getattr(Asset, field) == value,
            Asset.is_active == True,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def merge_data(self, asset_id: uuid.UUID, new_data: dict) -> Asset:
        """
        Merged neue Daten in ein bestehendes Asset.
        Bestehende Werte werden nur überschrieben wenn der neue Wert nicht None ist.
        """
        asset = await self.session.get(Asset, asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} nicht gefunden")

        # Felder mergen (None-Werte ignorieren)
        updatable = [
            "hostname", "ip_address", "fqdn", "mac_address",
            "os_name", "os_version", "os_arch",
            "manufacturer", "model", "firmware_version",
            "exposure_level", "open_ports", "rack_id", "rack_unit", "location",
        ]
        for field in updatable:
            if field in new_data and new_data[field] is not None:
                setattr(asset, field, new_data[field])

        # Tags mergen (addieren, nicht ersetzen)
        if "tags" in new_data and new_data["tags"]:
            existing = set(asset.tags or [])
            existing.update(new_data["tags"])
            asset.tags = list(existing)

        # Sources-Liste aktualisieren
        if "source" in new_data:
            sources = asset.sources or []
            sources = [s for s in sources if s.get("origin") != new_data["source"]]
            sources.append({
                "origin": new_data["source"],
                "last_seen": new_data.get("last_seen", ""),
            })
            asset.sources = sources

        await self.session.flush()
        return asset
