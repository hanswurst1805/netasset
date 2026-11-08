"""Container-Images: purl→OSV-Abbildung, CVSS, Ingest und CycloneDX-Export."""

import pytest
from httpx import AsyncClient

from src.ingest.container_scan import (
    canonical_id, cvss3_base_score, fixed_version, has_inverted_range, osv_query_for, vuln_rating,
)


@pytest.mark.parametrize("purl,expected", [
    ("pkg:apk/alpine/alpine-baselayout-data@3.7.2-r0?arch=x86_64&distro=alpine-3.23.6&upstream=alpine-baselayout",
     ("Alpine:v3.23", "alpine-baselayout", "3.7.2-r0")),
    ("pkg:deb/debian/adduser@3.152?arch=all&distro=debian-13.7", ("Debian:13", "adduser", "3.152")),
    ("pkg:deb/debian/libssl3t64@3.5.1-1?arch=amd64&upstream=openssl&distro=debian-13.7",
     ("Debian:13", "openssl", "3.5.1-1")),
    ("pkg:deb/debian/libgcc-s1@14.2.0-19?arch=amd64&upstream=gcc-14%4014.2.0-19&distro=debian-13.7",
     ("Debian:13", "gcc-14", "14.2.0-19")),
    ("pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg2-9?arch=amd64&distro=debian-13.7&epoch=1",
     ("Debian:13", "libdb5.3", "1:5.3.28+dfsg2-9")),
    ("pkg:deb/ubuntu/bash@5.2-1?arch=amd64&distro=ubuntu-24.04", ("Ubuntu:24.04:LTS", "bash", "5.2-1")),
    ("pkg:deb/ubuntu/bash@5.2-1?arch=amd64&distro=ubuntu-25.10", ("Ubuntu:25.10", "bash", "5.2-1")),
    ("pkg:pypi/alembic@1.20.0", ("PyPI", "alembic", "1.20.0")),
    ("pkg:npm/%40babel/core@7.25.0", ("npm", "@babel/core", "7.25.0")),
    ("pkg:golang/github.com/caddyserver/caddy/v2@v2.10.0", ("Go", "github.com/caddyserver/caddy/v2", "2.10.0")),
    ("pkg:golang/stdlib@1.25.1", ("Go", "stdlib", "1.25.1")),
    ("pkg:cargo/serde@1.0.200", ("crates.io", "serde", "1.0.200")),
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", ("Maven", "org.apache.logging.log4j:log4j-core", "2.17.1")),
])
def test_osv_query_for(purl, expected):
    assert osv_query_for(purl) == expected


@pytest.mark.parametrize("purl", [
    "pkg:cpan/Foo@1.0", "pkg:deb/debian/x@1?arch=all", "", "kein-purl", "pkg:pypi/nur-name",
])
def test_osv_query_for_unknown(purl):
    assert osv_query_for(purl) is None


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


def test_vuln_rating_and_fix():
    vuln = {
        "id": "DSA-1", "upstream": ["CVE-2026-1"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:13"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.5.2-1"}]}]}],
    }
    assert vuln_rating(vuln) == (9.8, "CRITICAL")
    assert canonical_id(vuln) == "CVE-2026-1"
    assert fixed_version(vuln, "Debian:13", "openssl") == "3.5.2-1"
    assert fixed_version(vuln, "Debian:12", "openssl") is None
    assert vuln_rating({"database_specific": {"severity": "MODERATE"}}) == (None, "MEDIUM")
    assert vuln_rating({"id": "X"}) == (None, "UNKNOWN")


def _affected(*ranges):
    return {"affected": [{"package": {"name": "perl", "ecosystem": "Alpine:v3.22"},
                          "ranges": [{"events": e} for e in ranges]}]}


def test_inverted_range_is_detected():
    # Echter OSV-Datensatz: ALPINE-CVE-2018-18311
    assert has_inverted_range(_affected([{"introduced": "5.28.0"}, {"fixed": "5.26.3-r0"}]), "Alpine:v3.22", "perl")
    assert not has_inverted_range(_affected([{"introduced": "0"}, {"fixed": "5.26.3-r0"}]), "Alpine:v3.22", "perl")
    assert not has_inverted_range(_affected([{"introduced": "5.0"}]), "Alpine:v3.22", "perl")
    assert not has_inverted_range(_affected(
        [{"introduced": "5.28.0"}, {"fixed": "5.26.3-r0"}],
        [{"introduced": "5.30.0"}, {"fixed": "5.40.5-r0"}],
    ), "Alpine:v3.22", "perl")


def test_fixed_version_picks_next_fix():
    vuln = _affected(
        [{"introduced": "1.25.0"}, {"fixed": "1.26.9"}],
        [{"introduced": "1.27.0"}, {"fixed": "1.27.2"}],
    )
    assert fixed_version(vuln, "Alpine:v3.22", "perl", "1.26.8") == "1.26.9"
    assert fixed_version(vuln, "Alpine:v3.22", "perl", "1.27.1") == "1.27.2"


async def _new_asset(client: AsyncClient, name: str) -> str:
    resp = await client.post("/api/v1/discovery/ingest", json=[{
        "hostname": name, "serial_number": f"SN-{name}", "asset_type": "server", "source": "osquery",
    }])
    return resp.json()[0]["asset_id"]


def _image(image_id="sha256:aaa", packages=True):
    return {
        "image_id": image_id, "image_ref": "docker.io/library/caddy:2-alpine", "distro": "alpine 3.23.6",
        "containers": ["web"],
        "packages": [
            {"name": "zlib", "version": "1.3-r0", "type": "apk",
             "purl": "pkg:apk/alpine/zlib@1.3-r0?distro=alpine-3.23.6"},
            {"name": "zlib", "version": "1.3-r0", "type": "apk",
             "purl": "pkg:apk/alpine/zlib@1.3-r0?distro=alpine-3.23.6"},
        ] if packages else None,
    }


async def test_ingest_list_export_and_remove(client: AsyncClient, monkeypatch):
    scanned = []

    async def fake_scan(pks):
        scanned.extend(pks)

    monkeypatch.setattr("src.api.container_images.scan_images", fake_scan)
    asset_id = await _new_asset(client, "container-host")

    resp = await client.post(f"/api/v1/container-images/assets/{asset_id}", json={"images": [_image()]})
    assert resp.status_code == 202
    assert resp.json()["scan_queued"] == 1
    assert len(scanned) == 1

    row = next(r for r in (await client.get("/api/v1/container-images")).json() if r["asset_id"] == asset_id)
    assert row["package_count"] == 1          # Duplikate zusammengefasst
    assert row["containers"] == ["web"]
    assert row["vuln_counts"]["CRITICAL"] == 0

    # Unverändertes Image ohne Paketliste: kein neuer Scan, Pakete bleiben
    resp = await client.post(f"/api/v1/container-images/assets/{asset_id}",
                             json={"images": [_image(packages=False)]})
    assert resp.json()["scan_queued"] == 0
    assert len((await client.get(f'/api/v1/container-images/{row["id"]}/packages')).json()) == 1

    bom = (await client.get(f'/api/v1/container-images/{row["id"]}/cyclonedx')).json()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["metadata"]["component"]["type"] == "container"
    assert [c["name"] for c in bom["components"]] == ["zlib"]

    # Image läuft nicht mehr → wird entfernt
    resp = await client.post(f"/api/v1/container-images/assets/{asset_id}", json={"images": []})
    assert resp.json()["removed"] == 1
    assert not [r for r in (await client.get("/api/v1/container-images")).json() if r["asset_id"] == asset_id]


async def test_ingest_unknown_asset(client: AsyncClient):
    resp = await client.post("/api/v1/container-images/assets/00000000-0000-0000-0000-000000000001",
                             json={"images": []})
    assert resp.status_code == 404
