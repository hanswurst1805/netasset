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


def ip_in_network(ip_str: str, cidr: str) -> bool:
    """Prüft ob eine IP-Adresse in einem CIDR-Netz liegt."""
    try:
        ip  = ipaddress.ip_address(ip_str)
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
    Klassifiziert ein Asset und setzt network_id + aktualisiert network_zones.
    Wird bei jedem Asset-Import aufgerufen.
    """
    matched = await classify_asset(asset, session)

    if matched:
        asset.network_id = matched.id
        # network_zones: nur den Namen hinzufügen (CIDR steht in ip_networks.cidr)
        zones = set(asset.network_zones or [])
        zones.add(matched.name)
        # Exposure aus Netz übernehmen wenn höher als aktuelles
        exp_rank = {"INTERN": 0, "DMZ": 1, "EXTERN": 2}
        if exp_rank.get(matched.exposure_level, 0) > exp_rank.get(asset.exposure_level, 0):
            asset.exposure_level = matched.exposure_level
        asset.network_zones = list(zones)

    # Asset in 2+ Netzwerk-Zonen → automatisch Router
    zone_count = len(asset.network_zones or [])
    if zone_count >= 2 and asset.asset_type not in ("router", "firewall"):
        log.info("Asset %s hat %d Zonen → asset_type=router",
                 asset.ip_address or asset.hostname, zone_count)
        asset.asset_type = "router"
        log.info("Asset %s → Netz '%s' (%s)",
                 asset.ip_address, matched.name, matched.cidr)
    else:
        if asset.network_id:
            # Netz wurde gelöscht oder IP hat sich geändert
            asset.network_id = None


async def reclassify_all(session: AsyncSession) -> int:
    """
    Klassifiziert alle aktiven Assets neu.
    Nützlich nach dem Anlegen neuer Netze.
    """
    result = await session.execute(
        select(Asset).where(Asset.is_active == True, Asset.ip_address.is_not(None))
    )
    assets = result.scalars().all()

    count = 0
    for asset in assets:
        old_id = asset.network_id
        await classify_asset_and_update(asset, session)
        if asset.network_id != old_id:
            count += 1

    await session.flush()
    log.info("Reklassifizierung: %d/%d Assets aktualisiert", count, len(assets))
    return count
