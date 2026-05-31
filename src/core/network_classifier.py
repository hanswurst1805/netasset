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
    """Prüft ob eine IP-Adresse in einem CIDR-Netz liegt (inkl. /32 Einzelhost-Netze)."""
    try:
        ip  = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(cidr, strict=False)
        # ip in net: inklusiv, d.h. /32 matcht den exakten Host
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
    zones = set(asset.network_zones or [])

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

    # 3. Asset in 2+ Netzwerk-Zonen → automatisch Router
    if len(zones) >= 2 and asset.asset_type not in ("router", "firewall"):
        log.info("Asset %s hat %d Zonen → asset_type=router",
                 asset.ip_address or asset.hostname, len(zones))
        asset.asset_type = "router"


async def reclassify_all(session: AsyncSession) -> int:
    """
    Klassifiziert alle aktiven Assets neu via direktem SQL (zuverlässig).
    Nützlich nach dem Anlegen neuer Netze.
    """
    from sqlalchemy import text

    # Netzwerke vorab laden für Logging
    net_result = await session.execute(select(IpNetwork))
    networks = net_result.scalars().all()
    log.info("Reklassifizierung gestartet: %d Netze verfügbar", len(networks))

    # Direktes SQL mit <<= (inklusiv, matcht auch /32)
    update_sql = text("""
        UPDATE assets
        SET network_id = (
            SELECT i.id FROM ip_networks i
            WHERE assets.ip_address::inet <<= i.cidr::inet
            ORDER BY masklen(i.cidr::inet) DESC
            LIMIT 1
        )
        WHERE ip_address IS NOT NULL AND is_active = true
    """)
    result = await session.execute(update_sql)
    updated = result.rowcount

    # network_zones + asset_type auch per Python aktualisieren
    asset_result = await session.execute(
        select(Asset).where(Asset.is_active == True, Asset.ip_address.is_not(None))
    )
    assets = asset_result.scalars().all()
    for asset in assets:
        # Zonen aus IP ableiten
        zones = set(asset.network_zones or [])
        for net in networks:
            if ip_in_network(asset.ip_address or "", net.cidr):
                zones.add(net.name)
        for extra in (getattr(asset, "additional_ips", None) or []):
            for net in networks:
                if ip_in_network(extra, net.cidr):
                    zones.add(net.name)
        if zones != set(asset.network_zones or []):
            asset.network_zones = list(zones)
        # Router-Auto-Erkennung
        if len(zones) >= 2 and asset.asset_type not in ("router", "firewall"):
            asset.asset_type = "router"

    await session.flush()
    log.info("Reklassifizierung: %d Assets network_id gesetzt", updated)
    return updated
