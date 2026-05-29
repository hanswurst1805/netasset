"""
Demo-Daten für NetAsset.
Legt Beispiel-Assets, SBOM-Einträge und Business-Prozesse an.

Verwendung:
    python scripts/seed_demo_data.py
"""

import asyncio
import uuid
import sys
sys.path.insert(0, ".")

from src.core.database import async_session_factory
from src.models.all_models import Asset, SBOMEntry, BusinessProcess, ProcessAsset, Owner

DEMO_ASSETS = [
    {
        "id": uuid.uuid4(),
        "hostname": "web-prod-01",
        "ip_address": "10.0.1.10",
        "mac_address": "aa:bb:cc:dd:01:01",
        "serial_number": "SRV-2024-001",
        "asset_type": "server",
        "os_name": "ubuntu",
        "os_version": "24.04",
        "exposure_level": "EXTERN",
        "open_ports": [
            {"port": 80,  "proto": "tcp", "reachable_from": ["internet"]},
            {"port": 443, "proto": "tcp", "reachable_from": ["internet"]},
            {"port": 22,  "proto": "tcp", "reachable_from": ["management-vlan"]},
        ],
        "tags": ["site:kiel", "role:webserver", "env:prod"],
        "sbom": [
            ("openssl",  "3.1.2", "library",     "cpe:2.3:a:openssl:openssl:3.1.2:*"),
            ("nginx",    "1.24.0","application",  "cpe:2.3:a:nginx:nginx:1.24.0:*"),
            ("python3",  "3.12.0","application",  None),
            ("libssl3",  "3.1.2", "os-package",   None),
        ],
    },
    {
        "id": uuid.uuid4(),
        "hostname": "db-prod-01",
        "ip_address": "10.0.2.10",
        "mac_address": "aa:bb:cc:dd:02:01",
        "serial_number": "SRV-2024-002",
        "asset_type": "server",
        "os_name": "ubuntu",
        "os_version": "22.04",
        "exposure_level": "INTERN",
        "open_ports": [
            {"port": 5432, "proto": "tcp", "reachable_from": ["app-vlan"]},
        ],
        "tags": ["site:kiel", "role:database", "env:prod"],
        "sbom": [
            ("postgresql",  "16.2",  "application", "cpe:2.3:a:postgresql:postgresql:16.2:*"),
            ("openssl",     "3.0.8", "library",     "cpe:2.3:a:openssl:openssl:3.0.8:*"),
            ("libssl3",     "3.0.8", "os-package",  None),
        ],
    },
    {
        "id": uuid.uuid4(),
        "hostname": "fw-extern-01",
        "ip_address": "192.168.1.1",
        "mac_address": "aa:bb:cc:dd:03:01",
        "serial_number": "CP-2024-001",
        "asset_type": "firewall",
        "os_name": "Gaia",
        "os_version": "R81.20",
        "exposure_level": "EXTERN",
        "open_ports": [
            {"port": 443, "proto": "tcp", "reachable_from": ["internet"]},
        ],
        "tags": ["site:kiel", "role:firewall", "vendor:checkpoint"],
        "sbom": [
            ("openssl", "1.1.1w", "library", "cpe:2.3:a:openssl:openssl:1.1.1w:*"),
        ],
    },
    {
        "id": uuid.uuid4(),
        "hostname": "sw-core-01",
        "ip_address": "10.0.0.1",
        "mac_address": "aa:bb:cc:dd:04:01",
        "serial_number": "CAT-2024-001",
        "asset_type": "switch",
        "os_name": "IOS-XE",
        "os_version": "17.9.3",
        "exposure_level": "INTERN",
        "open_ports": [
            {"port": 22,  "proto": "tcp", "reachable_from": ["management-vlan"]},
            {"port": 161, "proto": "udp", "reachable_from": ["management-vlan"]},
        ],
        "tags": ["site:kiel", "role:core-switch", "vendor:cisco"],
        "sbom": [],
    },
    {
        "id": uuid.uuid4(),
        "hostname": "app-crm-01",
        "ip_address": "10.0.1.20",
        "mac_address": "aa:bb:cc:dd:05:01",
        "asset_type": "server",
        "os_name": "ubuntu",
        "os_version": "26.04",
        "exposure_level": "DMZ",
        "open_ports": [
            {"port": 8080, "proto": "tcp", "reachable_from": ["internet", "intern"]},
            {"port": 22,   "proto": "tcp", "reachable_from": ["management-vlan"]},
        ],
        "tags": ["site:kiel", "role:appserver", "app:crm", "env:prod"],
        "sbom": [
            ("openssl",    "3.1.4", "library",    "cpe:2.3:a:openssl:openssl:3.1.4:*"),
            ("openjdk-21", "21.0.2","application", None),
            ("log4j",      "2.23.0","library",     "cpe:2.3:a:apache:log4j:2.23.0:*"),
        ],
    },
]

DEMO_PROCESSES = [
    {
        "name": "Angebot schreiben",
        "criticality": 3,
        "sla_rto_hours": 4,
        "asset_hostnames": ["app-crm-01", "web-prod-01"],
    },
    {
        "name": "Abrechnung / Invoicing",
        "criticality": 5,
        "sla_rto_hours": 1,
        "asset_hostnames": ["db-prod-01", "app-crm-01"],
    },
    {
        "name": "Webauftritt / Marketing",
        "criticality": 2,
        "sla_rto_hours": 8,
        "asset_hostnames": ["web-prod-01"],
    },
]


async def seed():
    async with async_session_factory() as session:
        # Owner
        owner = Owner(name="IT-Team Kiel", team="IT", department="NetUSE")
        session.add(owner)
        await session.flush()

        # Assets + SBOM
        asset_by_hostname: dict[str, Asset] = {}
        for a in DEMO_ASSETS:
            sbom_data = a.pop("sbom")
            asset = Asset(**a)
            session.add(asset)
            await session.flush()

            for pkg_name, pkg_ver, pkg_type, cpe in sbom_data:
                session.add(SBOMEntry(
                    asset_id=asset.id,
                    pkg_name=pkg_name,
                    pkg_version=pkg_ver,
                    pkg_type=pkg_type,
                    cpe=cpe,
                    source="manual",
                ))
            asset_by_hostname[asset.hostname] = asset

        # Business-Prozesse
        for p in DEMO_PROCESSES:
            hostnames = p.pop("asset_hostnames")
            proc = BusinessProcess(**p, owner_id=owner.id)
            session.add(proc)
            await session.flush()

            for hostname in hostnames:
                asset = asset_by_hostname.get(hostname)
                if asset:
                    session.add(ProcessAsset(
                        process_id=proc.id,
                        asset_id=asset.id,
                        role="primary",
                    ))

        await session.commit()
        print(f"✓ {len(DEMO_ASSETS)} Assets, {len(DEMO_PROCESSES)} Prozesse angelegt")
        print("\nDemo-Assets:")
        for a in asset_by_hostname.values():
            print(f"  {a.hostname:<20} {a.exposure_level:<8} {a.os_name} {a.os_version}")


if __name__ == "__main__":
    asyncio.run(seed())
