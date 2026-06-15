"""
IP-Netzwerk-Klassifizierung: Weist Assets anhand ihrer IP-Adresse
automatisch dem passenden benannten Netzwerk zu.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.all_models import Asset, IpNetwork

log = logging.getLogger(__name__)


def _asset_type_is_manual(asset: Asset) -> bool:
    """Prüft ob asset_type zuletzt manuell (PUT /assets/{id}) gesetzt wurde."""
    for src in (asset.sources or []):
        if src.get("origin") == "manual" and "asset_type" in src.get("fields", []):
            return True
    return False


def ip_in_network(ip_str: str, cidr: str) -> bool:
    """Prüft ob eine IP-Adresse in einem CIDR-Netz liegt (inkl. /32 Einzelhost-Netze)."""
    if not ip_str or not ip_str.strip():
        return False
    try:
        ip  = ipaddress.ip_address(ip_str.strip())
        net = ipaddress.ip_network(cidr, strict=False)
        return ip in net
    except ValueError:
        return False


async def classify_asset(asset: Asset, session: AsyncSession) -> Optional[IpNetwork]:
    """
    Findet das passende Netz für ein Asset anhand seiner IP-Adresse.
    Bei mehreren Treffern gewinnt das spezifischste (größtes Präfix = kleinste Netzgröße).
    """
    if not asset.ip_address:
        return None

    result = await session.execute(select(IpNetwork))
    networks = result.scalars().all()

    matches = []
    for net in networks:
        if ip_in_network(asset.ip_address, net.cidr):
            try:
                prefix_len = ipaddress.ip_network(net.cidr, strict=False).prefixlen
                matches.append((prefix_len, net))
            except ValueError:
                pass

    if not matches:
        return None

    # Spezifischstes Netz gewinnt (größtes Präfix, z.B. /24 vor /8)
    matches.sort(key=lambda x: x[0], reverse=True)
    return matches[0][1]


async def classify_asset_and_update(asset: Asset, session: AsyncSession) -> None:
    """
    Klassifiziert ein Asset anhand ALLER IP-Adressen (primär + additional_ips).
    - network_id   → Netz der primären IP
    - network_zones → Netznamen aller passenden IPs
    """
    exp_rank = {"INTERN": 0, "DMZ": 1, "EXTERN": 2}
    # network_zones wird komplett neu aus den aktuellen IPs berechnet,
    # damit veraltete Zonen (z.B. von gelöschten Netzen) nicht erhalten bleiben.
    zones: set[str] = set()

    # 1. Primäre IP → network_id
    matched = await classify_asset(asset, session)
    if matched:
        asset.network_id = matched.id
        zones.add(matched.name)
        if exp_rank.get(matched.exposure_level, 0) > exp_rank.get(asset.exposure_level, 0):
            asset.exposure_level = matched.exposure_level
        log.debug("Asset %s → Netz '%s'", asset.ip_address, matched.name)
    else:
        if asset.network_id:
            asset.network_id = None

    # 2. Zusätzliche IPs → weitere network_zones
    for extra_ip in (getattr(asset, "additional_ips", None) or []):
        if not extra_ip:
            continue
        # Temporäres Objekt mit der extra IP für den Classifier
        extra_matched = None
        result = await session.execute(select(IpNetwork))
        for net in result.scalars().all():
            if ip_in_network(extra_ip, net.cidr):
                extra_matched = net
                break
        if extra_matched:
            zones.add(extra_matched.name)
            if exp_rank.get(extra_matched.exposure_level, 0) > exp_rank.get(asset.exposure_level, 0):
                asset.exposure_level = extra_matched.exposure_level
            log.debug("Asset %s (additional %s) → Netz '%s'",
                      asset.ip_address, extra_ip, extra_matched.name)

    asset.network_zones = list(zones)

    # 3. Asset in 2+ Netzwerk-Zonen → automatisch Router (außer manuell gesetzt)
    if (len(zones) >= 2 and asset.asset_type not in ("router", "firewall")
            and not _asset_type_is_manual(asset)):
        log.info("Asset %s hat %d Zonen → asset_type=router",
                 asset.ip_address or asset.hostname, len(zones))
        asset.asset_type = "router"


async def reclassify_all(session: AsyncSession) -> int:
    """
    Klassifiziert alle aktiven Assets neu.
    Nutzt Python-ipaddress für das Matching (<<= Semantik inkl. /32).
    """
    # Alle Netze und Assets laden
    networks = (await session.execute(select(IpNetwork))).scalars().all()
    assets = (await session.execute(
        select(Asset).where(
            Asset.is_active == True,
            Asset.is_archived == False,
            Asset.ip_address.is_not(None),
            Asset.ip_address != "",
        )
    )).scalars().all()

    log.info("Reklassifizierung: %d Assets, %d Netze", len(assets), len(networks))

    count = 0
    for asset in assets:
        old_network_id = asset.network_id
        # network_zones komplett neu berechnen (siehe classify_asset_and_update)
        zones: set[str] = set()

        # Alle IPs des Assets prüfen (primär + additional)
        all_ips = [asset.ip_address] + list(getattr(asset, "additional_ips", None) or [])
        best_match: IpNetwork | None = None
        best_prefix = -1

        for ip in all_ips:
            if not ip:
                continue
            for net in networks:
                if ip_in_network(ip, net.cidr):
                    prefix = ipaddress.ip_network(net.cidr, strict=False).prefixlen
                    zones.add(net.name)
                    # Primäre IP bestimmt network_id (spezifischstes Netz)
                    if ip == asset.ip_address and prefix > best_prefix:
                        best_prefix = prefix
                        best_match = net

        # network_id setzen
        if best_match:
            asset.network_id = best_match.id
        elif asset.network_id:
            asset.network_id = None

        # network_zones aktualisieren
        asset.network_zones = list(zones)

        # Router-Auto-Erkennung (außer manuell gesetzt)
        if (len(zones) >= 2 and asset.asset_type not in ("router", "firewall")
                and not _asset_type_is_manual(asset)):
            asset.asset_type = "router"

        if asset.network_id != old_network_id:
            count += 1

    await session.flush()
    log.info("Reklassifizierung abgeschlossen: %d/%d aktualisiert", count, len(assets))
    return count
