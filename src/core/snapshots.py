"""
Asset-Snapshot-Service.

Erstellt täglich einen Snapshot des Asset-Zustands inkl. SBOM.
Berechnet einen Diff zum Vortag der zeigt was sich geändert hat.
Hält max. 30 Snapshots pro Asset (ältere werden gelöscht).
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models.all_models import Asset, AssetSnapshot, SBOMEntry

log = logging.getLogger(__name__)

MAX_SNAPSHOTS = 30

# Felder die im Snapshot gespeichert werden
SNAPSHOT_FIELDS = [
    "hostname", "ip_address", "fqdn", "mac_address",
    "asset_type", "os_name", "os_version", "os_arch",
    "manufacturer", "model", "firmware_version",
    "exposure_level", "network_zones", "open_ports",
    "tags", "location",
]


def _asset_to_dict(asset: Asset, sbom: list[SBOMEntry]) -> dict:
    """Wandelt ein Asset in ein serialisierbares Dict um."""
    data = {field: getattr(asset, field, None) for field in SNAPSHOT_FIELDS}
    data["sbom"] = [
        {"pkg_name": e.pkg_name, "pkg_version": e.pkg_version,
         "pkg_type": e.pkg_type, "cpe": e.cpe}
        for e in sorted(sbom, key=lambda x: x.pkg_name)
    ]
    return data


def _compute_diff(old: dict, new: dict) -> dict:
    """
    Berechnet den Diff zwischen zwei Snapshots.
    Gibt ein Dict mit 'changed', 'added', 'removed' zurück.
    """
    diff: dict = {"changed": {}, "added": {}, "removed": {}}

    all_keys = set(old) | set(new)
    for key in all_keys:
        old_val = old.get(key)
        new_val = new.get(key)

        if key == "sbom":
            # SBOM-Diff: nach pkg_name+version
            old_set = {(p["pkg_name"], p["pkg_version"]) for p in (old_val or [])}
            new_set = {(p["pkg_name"], p["pkg_version"]) for p in (new_val or [])}
            added = new_set - old_set
            removed = old_set - new_set
            if added:
                diff["added"]["sbom"] = [
                    {"pkg_name": n, "pkg_version": v} for n, v in sorted(added)
                ]
            if removed:
                diff["removed"]["sbom"] = [
                    {"pkg_name": n, "pkg_version": v} for n, v in sorted(removed)
                ]

        elif key == "open_ports":
            # Port-Diff: nach port+proto
            def port_key(p: dict) -> tuple:
                return (p.get("port", 0), p.get("proto", "tcp"))
            old_ports = {port_key(p): p for p in (old_val or [])}
            new_ports = {port_key(p): p for p in (new_val or [])}
            added_ports = {k: v for k, v in new_ports.items() if k not in old_ports}
            removed_ports = {k: v for k, v in old_ports.items() if k not in new_ports}
            if added_ports:
                diff["added"]["open_ports"] = list(added_ports.values())
            if removed_ports:
                diff["removed"]["open_ports"] = list(removed_ports.values())

        elif key in ("tags", "network_zones"):
            # Listen-Diff
            old_set = set(old_val or [])
            new_set = set(new_val or [])
            added = new_set - old_set
            removed = old_set - new_set
            if added:
                diff["added"][key] = sorted(added)
            if removed:
                diff["removed"][key] = sorted(removed)

        else:
            # Einfacher Wert-Vergleich
            if old_val != new_val:
                diff["changed"][key] = {"from": old_val, "to": new_val}

    # Leere Diffs bereinigen
    return {k: v for k, v in diff.items() if v}


async def snapshot_asset(
    asset: Asset,
    sbom: list[SBOMEntry],
    session: AsyncSession,
    snap_date: Optional[date] = None,
) -> AssetSnapshot:
    """
    Erstellt einen Snapshot für ein einzelnes Asset.
    Falls für heute bereits einer existiert, wird er aktualisiert.
    """
    today = snap_date or date.today()
    today_dt = datetime.combine(today, datetime.min.time())

    current_data = _asset_to_dict(asset, sbom)

    # Vorheriger Snapshot für Diff
    prev_stmt = (
        select(AssetSnapshot)
        .where(
            AssetSnapshot.asset_id == asset.id,
            AssetSnapshot.snapshot_date < today_dt,
        )
        .order_by(desc(AssetSnapshot.snapshot_date))
        .limit(1)
    )
    prev = (await session.execute(prev_stmt)).scalar_one_or_none()
    diff = _compute_diff(prev.data, current_data) if prev else None

    # Heutiger Snapshot: upsert
    existing_stmt = select(AssetSnapshot).where(
        AssetSnapshot.asset_id == asset.id,
        AssetSnapshot.snapshot_date == today_dt,
    )
    snapshot = (await session.execute(existing_stmt)).scalar_one_or_none()

    if snapshot:
        snapshot.data = current_data
        snapshot.diff = diff
    else:
        snapshot = AssetSnapshot(
            asset_id=asset.id,
            snapshot_date=today_dt,
            data=current_data,
            diff=diff,
        )
        session.add(snapshot)

    await session.flush()

    # Alte Snapshots löschen (max 30)
    all_stmt = (
        select(AssetSnapshot)
        .where(AssetSnapshot.asset_id == asset.id)
        .order_by(desc(AssetSnapshot.snapshot_date))
    )
    all_snaps = (await session.execute(all_stmt)).scalars().all()
    if len(all_snaps) > MAX_SNAPSHOTS:
        for old in all_snaps[MAX_SNAPSHOTS:]:
            await session.delete(old)

    return snapshot


async def run_daily_snapshots(session: AsyncSession) -> dict:
    """
    Erstellt Snapshots für alle aktiven Assets.
    Typischer Aufruf: täglich per Cron oder manuell via API.
    """
    result = await session.execute(
        select(Asset)
        .where(Asset.is_active == True, Asset.is_archived == False)
        .options(selectinload(Asset.sbom_entries))
    )
    assets = result.scalars().all()

    created = 0
    updated = 0
    errors = 0

    for asset in assets:
        try:
            existing = (await session.execute(
                select(AssetSnapshot).where(
                    AssetSnapshot.asset_id == asset.id,
                    AssetSnapshot.snapshot_date == datetime.combine(date.today(), datetime.min.time()),
                )
            )).scalar_one_or_none()

            await snapshot_asset(asset, asset.sbom_entries, session)

            if existing:
                updated += 1
            else:
                created += 1
        except Exception as e:
            log.error("Snapshot-Fehler für Asset %s: %s", asset.id, e)
            errors += 1

    await session.flush()
    log.info("Snapshots: %d neu, %d aktualisiert, %d Fehler", created, updated, errors)
    return {"created": created, "updated": updated, "errors": errors, "total": len(assets)}
