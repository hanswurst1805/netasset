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
    """merge_data aktualisiert Felder, None-Werte werden ignoriert."""
    resolver = IdentityResolver(session)
    await resolver.merge_data(asset.id, {
        "ip_address": "10.0.0.100",
        "os_name": "Ubuntu",
        "hostname": None,  # soll ignoriert werden
        "tags": ["new-tag"],
        "source": "nmap",
    })
    await session.refresh(asset)
    assert asset.ip_address == "10.0.0.100"
    assert asset.os_name == "Ubuntu"
    assert asset.hostname == "testhost-01"  # nicht überschrieben
    assert "new-tag" in asset.tags
    assert any(s["origin"] == "nmap" for s in asset.sources)
