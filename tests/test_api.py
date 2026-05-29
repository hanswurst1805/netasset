"""Integration-Tests für die FastAPI-Endpunkte."""

import pytest
from httpx import AsyncClient


async def test_health(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

async def test_create_asset(client: AsyncClient):
    resp = await client.post("/api/v1/assets", json={
        "hostname": "api-test-01",
        "ip_address": "10.0.0.1",
        "asset_type": "server",
        "exposure_level": "INTERN",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["hostname"] == "api-test-01"
    assert "id" in data


async def test_list_assets(client: AsyncClient):
    # Erst anlegen
    await client.post("/api/v1/assets", json={"hostname": "list-test", "asset_type": "server"})
    resp = await client.get("/api/v1/assets")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
    assert len(resp.json()) >= 1


async def test_get_asset_not_found(client: AsyncClient):
    resp = await client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


async def test_update_asset(client: AsyncClient):
    create_resp = await client.post("/api/v1/assets", json={
        "hostname": "update-test",
        "asset_type": "server",
    })
    asset_id = create_resp.json()["id"]

    resp = await client.put(f"/api/v1/assets/{asset_id}", json={
        "hostname": "update-test",
        "asset_type": "server",
        "os_name": "Ubuntu",
        "os_version": "22.04",
    })
    assert resp.status_code == 200
    assert resp.json()["os_name"] == "Ubuntu"


async def test_filter_assets_by_type(client: AsyncClient):
    await client.post("/api/v1/assets", json={"hostname": "sw-01", "asset_type": "switch"})
    resp = await client.get("/api/v1/assets?asset_type=switch")
    assert resp.status_code == 200
    assert all(a["asset_type"] == "switch" for a in resp.json())


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------

async def test_add_and_get_sbom(client: AsyncClient):
    create_resp = await client.post("/api/v1/assets", json={
        "hostname": "sbom-test",
        "asset_type": "server",
    })
    asset_id = create_resp.json()["id"]

    sbom_resp = await client.post(f"/api/v1/sbom/assets/{asset_id}/sbom", json=[
        {"pkg_name": "openssl", "pkg_version": "3.0.2", "pkg_type": "library"},
        {"pkg_name": "nginx", "pkg_version": "1.24.0", "pkg_type": "application"},
    ])
    assert sbom_resp.status_code == 201
    assert len(sbom_resp.json()) == 2

    get_resp = await client.get(f"/api/v1/sbom/assets/{asset_id}/sbom")
    assert get_resp.status_code == 200
    assert len(get_resp.json()) == 2


# ---------------------------------------------------------------------------
# Business-Prozesse
# ---------------------------------------------------------------------------

async def test_create_and_get_process(client: AsyncClient):
    resp = await client.post("/api/v1/processes", json={
        "name": "Test-Prozess",
        "criticality": 3,
    })
    assert resp.status_code == 201
    proc_id = resp.json()["id"]

    get_resp = await client.get(f"/api/v1/processes/{proc_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Test-Prozess"


async def test_process_criticality_validation(client: AsyncClient):
    resp = await client.post("/api/v1/processes", json={
        "name": "Invalid",
        "criticality": 6,  # zu hoch
    })
    assert resp.status_code == 400


async def test_process_assets(client: AsyncClient):
    asset_resp = await client.post("/api/v1/assets", json={"hostname": "proc-asset", "asset_type": "server"})
    asset_id = asset_resp.json()["id"]

    proc_resp = await client.post("/api/v1/processes", json={"name": "Proc mit Asset", "criticality": 2})
    proc_id = proc_resp.json()["id"]

    link_resp = await client.post(f"/api/v1/processes/{proc_id}/assets", json={
        "asset_id": asset_id,
        "role": "primary",
    })
    assert link_resp.status_code == 201

    assets_resp = await client.get(f"/api/v1/processes/{proc_id}/assets")
    assert assets_resp.status_code == 200
    assert len(assets_resp.json()) == 1
    assert assets_resp.json()[0]["hostname"] == "proc-asset"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

async def test_discovery_ingest_new(client: AsyncClient):
    resp = await client.post("/api/v1/discovery/ingest", json=[
        {
            "hostname": "discovered-host",
            "ip_address": "192.168.1.100",
            "mac_address": "11:22:33:44:55:66",
            "asset_type": "server",
            "source": "nmap",
        }
    ])
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["action"] == "created"
    assert results[0]["match_result"] == "NEW"


async def test_discovery_ingest_merge(client: AsyncClient):
    # Erst anlegen
    await client.post("/api/v1/discovery/ingest", json=[{
        "hostname": "merge-host",
        "mac_address": "aa:11:22:33:44:55",
        "asset_type": "server",
        "source": "nmap",
    }])

    # Nochmal mit gleicher MAC → merge
    resp = await client.post("/api/v1/discovery/ingest", json=[{
        "hostname": "merge-host-updated",
        "mac_address": "aa:11:22:33:44:55",
        "ip_address": "10.5.5.5",
        "source": "nmap",
    }])
    assert resp.status_code == 200
    assert resp.json()[0]["action"] == "merged"
