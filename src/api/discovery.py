"""Discovery-Ingest API – nimmt automatisch erkannte Geräte entgegen."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_session
from src.core.identity import DeviceFingerprint, IdentityResolver, MatchResult
from src.models.all_models import Asset

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


class IngestResult(BaseModel):
    device_index: int
    match_result: str
    asset_id: Optional[str]
    confidence: float
    matched_on: list[str]
    action: str  # created | merged | flagged


@router.post("/ingest", response_model=list[IngestResult])
async def ingest_devices(
    devices: list[DiscoveredDevice],
    session: AsyncSession = Depends(get_session),
):
    """
    Bulk-Ingest: Liste erkannter Geräte.
    Jedes Gerät wird durch den IdentityResolver geschickt.
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
        action = "flagged"

        if identity.result == MatchResult.MATCH and identity.asset_id:
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
            if device.source:
                asset.sources = [{"origin": device.source}]
            session.add(asset)
            await session.flush()
            identity.asset_id = asset.id
            action = "created"

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
