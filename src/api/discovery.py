"""Discovery-Ingest API – nimmt automatisch erkannte Geräte entgegen."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.core.identity import DeviceFingerprint, IdentityResolver, MatchResult
from src.core.network_classifier import classify_asset_and_update
from src.models.all_models import Asset, ConflictQueueEntry

router = APIRouter()


class DiscoveredDevice(BaseModel):
    """Ein von einem Collector gemeldetes Gerät zur Identity-Auflösung und Ingestion."""

    internal_id: Optional[str] = Field(
        None,
        description="Interne UUID des Assets (falls bereits bekannt). Stärkster Match-Key (Konfidenz 1.0).",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    mac_address: Optional[str] = Field(
        None,
        description="MAC-Adresse des primären Netzwerk-Interfaces. Stable Key (Konfidenz 0.95).",
        examples=["aa:bb:cc:dd:ee:ff"],
    )
    serial_number: Optional[str] = Field(
        None,
        description="Hardware-Seriennummer. Stable Key (Konfidenz 0.95).",
        examples=["SN-123456789"],
    )
    chassis_id: Optional[str] = Field(
        None,
        description="System-UUID aus BIOS/DMI. Stable Key (Konfidenz 0.95). Entspricht osquery system_info.uuid.",
        examples=["6ba7b810-9dad-11d1-80b4-00c04fd430c8"],
    )
    hostname: Optional[str] = Field(
        None,
        description="Hostname des Geräts. Soft Key (Konfidenz 0.80). Allein nicht ausreichend für MATCH.",
        examples=["web-server-01"],
    )
    ip_address: Optional[str] = Field(
        None,
        description="Primäre IPv4-Adresse. Soft Key (Konfidenz 0.80).",
        examples=["192.168.1.100"],
    )
    fqdn: Optional[str] = Field(
        None,
        description="Vollständiger Domainname. Soft Key (Konfidenz 0.80).",
        examples=["web-server-01.example.com"],
    )
    asset_type: str = Field(
        "server",
        description="Gerätetyp. Erlaubte Werte: server, client, switch, router, firewall, printer, access-point.",
        examples=["server"],
    )
    os_name: Optional[str] = Field(None, description="Name des Betriebssystems.", examples=["Ubuntu"])
    os_version: Optional[str] = Field(None, description="OS-Version.", examples=["22.04"])
    manufacturer: Optional[str] = Field(None, description="Gerätehersteller.", examples=["Dell"])
    model: Optional[str] = Field(None, description="Gerätemodell.", examples=["PowerEdge R740"])
    exposure_level: str = Field(
        "INTERN",
        description="Netzwerk-Exposition. Erlaubte Werte: INTERN, DMZ, EXTERN.",
        examples=["INTERN"],
    )
    open_ports: Optional[list] = Field(
        None,
        description='Liste offener Ports. Wird additiv gemergt (nie überschrieben). Format: [{"port": 22, "proto": "tcp", "service": "ssh"}]',
        examples=[[{"port": 22, "proto": "tcp", "service": "ssh"}]],
    )
    tags: Optional[list[str]] = Field(
        None,
        description="Tags zur Kategorisierung und Zugriffssteuerung. Werden additiv gemergt.",
        examples=[["production", "os:linux"]],
    )
    source: str = Field(
        "discovery",
        description="Quell-Identifier des Collectors. Bestimmt Merge-Priorität (osquery=80, mikrotik=70, nmap=50, arp=30).",
        examples=["osquery"],
    )


class IngestResult(BaseModel):
    """Ergebnis der Identity-Auflösung für ein einzelnes gemeldetes Gerät."""

    device_index: int = Field(
        description="0-basierter Index des Geräts im Eingabe-Array.",
        examples=[0],
    )
    match_result: str = Field(
        description="Ergebnis der Identity-Auflösung: NEW | MATCH | CONFLICT.",
        examples=["NEW"],
    )
    asset_id: Optional[str] = Field(
        None,
        description="UUID des betroffenen Assets. Null bei CONFLICT ohne eindeutigen Kandidaten.",
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )
    confidence: float = Field(
        description="Match-Konfidenz (0.0–1.0).",
        examples=[0.95],
    )
    matched_on: list[str] = Field(
        description="Felder auf denen der Match basiert.",
        examples=[["mac_address"]],
    )
    action: str = Field(
        description="Durchgeführte Aktion: created | merged | queued | skipped.",
        examples=["created"],
    )


@router.post("/ingest", response_model=list[IngestResult])
async def ingest_devices(
    devices: list[DiscoveredDevice],
    session: AsyncSession = Depends(get_session),
):
    """
    Bulk-Ingest: Liste erkannter Geräte.
    MATCH  → automatisch mergen
    NEW    → neues Asset anlegen
    CONFLICT → in Conflict Queue zur manuellen Prüfung
    """
    if not devices:
        raise HTTPException(400, "Keine Geräte übergeben")
    if len(devices) > 500:
        raise HTTPException(400, "Maximal 500 Geräte pro Request")

    resolver = IdentityResolver(session)
    results = []

    for idx, device in enumerate(devices):
        fp = DeviceFingerprint(
            internal_id=device.internal_id,
            mac_address=device.mac_address,
            serial_number=device.serial_number,
            chassis_id=device.chassis_id,
            hostname=device.hostname,
            ip_address=device.ip_address,
            fqdn=device.fqdn,
        )

        identity = await resolver.resolve(fp)
        action = "queued"

        if identity.result == MatchResult.MATCH and identity.asset_id:
            # Konfidenz-Check: Asset kann Mindest-Konfidenz setzen
            existing = await session.get(Asset, identity.asset_id)
            min_conf = getattr(existing, "min_confidence", 0.0) or 0.0
            if identity.confidence < min_conf:
                action = "skipped"  # Konfidenz zu niedrig → ignorieren
            else:
                merge_data = device.model_dump(exclude={"internal_id", "source"}, exclude_none=True)
                merge_data["source"] = device.source
                await resolver.merge_data(identity.asset_id, merge_data)
                action = "merged"

        elif identity.result == MatchResult.NEW:
            asset_data = device.model_dump(
                exclude={"internal_id", "source"},
                exclude_none=True,
            )
            asset = Asset(**asset_data)
            asset.sources = [{"origin": device.source, "last_seen": datetime.now(timezone.utc).isoformat()}]
            asset.last_seen_at = datetime.utcnow()
            session.add(asset)
            await session.flush()
            # Automatische Netzwerk-Zuordnung per IP
            await classify_asset_and_update(asset, session)
            identity.asset_id = asset.id
            action = "created"

        elif identity.result == MatchResult.CONFLICT:
            # min_confidence des Kandidaten prüfen
            skip = False
            if identity.asset_id:
                candidate = await session.get(Asset, identity.asset_id)
                min_conf = getattr(candidate, "min_confidence", 0.0) or 0.0
                if identity.confidence < min_conf:
                    skip = True

            if skip:
                action = "skipped"  # Konfidenz unter Schwelle → ignorieren
            else:
                # → Conflict Queue: Operator entscheidet
                entry = ConflictQueueEntry(
                    incoming_data=device.model_dump(),
                    source=device.source,
                    confidence=identity.confidence,
                    matched_on=identity.matched_on,
                    candidate_asset_id=identity.asset_id,
                    status="pending",
                )
                session.add(entry)
                await session.flush()
                action = "queued"

        results.append(
            IngestResult(
                device_index=idx,
                match_result=identity.result.value,
                asset_id=str(identity.asset_id) if identity.asset_id else None,
                confidence=identity.confidence,
                matched_on=identity.matched_on,
                action=action,
            )
        )

    return results
