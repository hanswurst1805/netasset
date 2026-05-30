"""Tests für den Identity Resolver."""

import uuid

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.identity import DeviceFingerprint, IdentityResolver, MatchResult
from src.models.all_models import Asset


@pytest_asyncio.fixture
async def asset(session: AsyncSession) -> Asset:
    a = Asset(
        hostname="testhost-01",
        ip_address="10.0.0.99",
        mac_address="aa:bb:cc:dd:ee:ff",
        serial_number="SN-TEST-001",
        asset_type="server",
    )
    session.add(a)
    await session.flush()
    return a


async def test_resolve_by_uuid(session: AsyncSession, asset: Asset):
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(internal_id=str(asset.id))
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.MATCH
    assert result.asset_id == asset.id
    assert result.confidence == 1.0
    assert "internal_uuid" in result.matched_on


async def test_resolve_by_mac(session: AsyncSession, asset: Asset):
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(mac_address="aa:bb:cc:dd:ee:ff")
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.MATCH
    assert result.asset_id == asset.id
    assert "mac_address" in result.matched_on


async def test_resolve_by_serial(session: AsyncSession, asset: Asset):
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(serial_number="SN-TEST-001")
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.MATCH
    assert result.asset_id == asset.id


async def test_resolve_soft_keys_match(session: AsyncSession, asset: Asset):
    """Hostname + IP zusammen → sicheres Match."""
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(hostname="testhost-01", ip_address="10.0.0.99")
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.MATCH
    assert result.asset_id == asset.id
    assert result.confidence == 0.8


async def test_resolve_single_soft_key_conflict(session: AsyncSession, asset: Asset):
    """Nur ein Soft Key → CONFLICT (zu wenig Sicherheit)."""
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(hostname="testhost-01")
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.CONFLICT


async def test_resolve_no_match(session: AsyncSession):
    """Kein passendes Asset → NEW."""
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(hostname="unknown-host", ip_address="192.168.255.255")
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.NEW


async def test_resolve_invalid_uuid(session: AsyncSession):
    """Ungültige UUID → kein Crash, fällt durch auf andere Keys."""
    resolver = IdentityResolver(session)
    fp = DeviceFingerprint(internal_id="not-a-uuid")
    result = await resolver.resolve(fp)
    assert result.result == MatchResult.NEW


async def test_merge_data(session: AsyncSession, asset: Asset):
    """merge_data: Felder werden prioritätsbasiert gemergt."""
    resolver = IdentityResolver(session)

    # Erst mit niedrigerer Quelle (nmap)
    await resolver.merge_data(asset.id, {
        "ip_address": "10.0.0.100",
        "os_name": "Linux (nmap-guess)",
        "hostname": None,   # None → ignoriert
        "tags": ["new-tag"],
        "source": "nmap-discovery",
    })
    await session.refresh(asset)
    assert asset.ip_address == "10.0.0.100"
    assert asset.os_name == "Linux (nmap-guess)"
    assert asset.hostname == "testhost-01"  # None wurde ignoriert
    assert "new-tag" in asset.tags
    assert any(s["origin"] == "nmap-discovery" for s in asset.sources)

    # Dann mit höherer Quelle (osquery) → überschreibt os_name
    await resolver.merge_data(asset.id, {
        "os_name": "Ubuntu 22.04",
        "source": "osquery",
    })
    await session.refresh(asset)
    assert asset.os_name == "Ubuntu 22.04"  # osquery > nmap

    # Nochmal nmap → darf os_name NICHT überschreiben
    await resolver.merge_data(asset.id, {
        "os_name": "Linux (nmap-guess-2)",
        "source": "nmap-discovery",
    })
    await session.refresh(asset)
    assert asset.os_name == "Ubuntu 22.04"  # nmap < osquery → kein Überschreiben


async def test_merge_ports_additive(session: AsyncSession, asset: Asset):
    """open_ports werden aus allen Quellen zusammengeführt."""
    resolver = IdentityResolver(session)

    await resolver.merge_data(asset.id, {
        "open_ports": [{"port": 22, "proto": "tcp", "reachable_from": ["intern"]}],
        "source": "nmap-discovery",
    })
    await resolver.merge_data(asset.id, {
        "open_ports": [{"port": 443, "proto": "tcp", "reachable_from": ["internet"]}],
        "source": "fritzbox-hosts",
    })
    await session.refresh(asset)
    ports = {p["port"] for p in (asset.open_ports or [])}
    assert 22 in ports
    assert 443 in ports  # beide Ports erhalten
