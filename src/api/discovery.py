"""Discovery-Ingest API – nimmt automatisch erkannte Geräte entgegen."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.core.identity import ENRICHMENT_SOURCES, DeviceFingerprint, IdentityResolver, MatchResult
from src.core.network_classifier import classify_asset_and_update
from src.core.services import bind_scope, resolve_service_pkg
from src.models.all_models import Asset, ConflictQueueEntry, SBOMEntry, Service

router = APIRouter()


class DiscoveredDevice(BaseModel):
    internal_id: Optional[str] = None
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    chassis_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    asset_type: str = "server"
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    exposure_level: str = "INTERN"
    open_ports: Optional[list] = None
    tags: Optional[list[str]] = None
    source: str = "discovery"
    min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Lauschende Dienste (Port → Prozess → Container), inkl. localhost-Binds
    services: Optional[list[dict]] = None


class IngestResult(BaseModel):
    device_index: int
    match_result: str
    asset_id: Optional[str]
    confidence: float
    matched_on: list[str]
    action: str  # created | merged | queued | skipped


async def _store_services(asset_id, services: list[dict], source: str, session: AsyncSession) -> None:
    """Ersetzt die von dieser Quelle gemeldeten Dienste eines Assets."""
    await session.execute(
        sa_delete(Service).where(Service.asset_id == asset_id, Service.source == source)
    )
    # SBOM des Assets für die Paket-Auflösung
    sbom = (await session.execute(
        select(SBOMEntry.pkg_name).where(SBOMEntry.asset_id == asset_id)
    )).scalars().all()
    sbom_lower = {s.lower(): s for s in sbom}

    seen: set = set()
    for s in services:
        try:
            port = int(s.get("port"))
        except (TypeError, ValueError):
            continue
        proto = (s.get("proto") or "tcp").lower()
        addr = s.get("bind_address") or s.get("address")
        key = (port, proto, addr)
        if port <= 0 or key in seen:
            continue
        seen.add(key)
        session.add(Service(
            asset_id=asset_id,
            port=port,
            proto=proto,
            bind_address=addr,
            bind_scope=s.get("bind_scope") or bind_scope(addr),
            process_name=s.get("process_name"),
            process_path=s.get("process_path"),
            sbom_pkg=resolve_service_pkg(
                s.get("process_name"), s.get("process_path"), s.get("container_image"), sbom_lower
            ),
            container_name=s.get("container_name"),
            container_image=s.get("container_image"),
            source=source,
        ))
    await session.flush()


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

        identity = await resolver.resolve(fp, source=device.source)
        action = "queued"

        # Enrichment-Quellen legen keine neuen Assets an
        is_enrichment = device.source in ENRICHMENT_SOURCES
        if (identity.result == MatchResult.NEW
                and is_enrichment
                and any(s.startswith("skip:") for s in identity.matched_on)):
            results.append(IngestResult(
                device_index=idx,
                match_result="NEW",
                asset_id=None,
                confidence=0.0,
                matched_on=identity.matched_on,
                action="skipped",
            ))
            continue

        if identity.result == MatchResult.MATCH and identity.asset_id:
            # Konfidenz-Check: Asset kann Mindest-Konfidenz setzen
            existing = await session.get(Asset, identity.asset_id)
            min_conf = getattr(existing, "min_confidence", 0.0) or 0.0
            if existing is not None and existing.is_archived:
                action = "skipped"  # Asset ist archiviert → keine Updates mehr
            elif identity.confidence < min_conf:
                action = "skipped"  # Konfidenz zu niedrig → ignorieren
            else:
                merge_data = device.model_dump(exclude={"internal_id", "source", "services"}, exclude_none=True)
                merge_data["source"] = device.source
                await resolver.merge_data(identity.asset_id, merge_data)
                action = "merged"

        elif identity.result == MatchResult.NEW:
            asset_data = device.model_dump(
                exclude={"internal_id", "source", "services"},
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
                if candidate is not None and candidate.is_archived:
                    skip = True  # Asset ist archiviert → keine Updates mehr
                elif identity.confidence < min_conf:
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

        # Dienste/Listener speichern (nur bei aktualisiertem/neuem Asset)
        if device.services and action in ("merged", "created") and identity.asset_id:
            await _store_services(identity.asset_id, device.services, device.source, session)

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
