#!/usr/bin/env python3
"""
CISA KEV Import — Known Exploited Vulnerabilities.
Kostenlos, kein API-Key nötig.

Aufruf:
    python scripts/import_kev.py
    python scripts/import_kev.py --file kev.json   # manuell heruntergeladene Datei

Empfohlen: täglich per Cron (die Liste wird täglich aktualisiert).
    0 6 * * * root python3 /opt/netasset/scripts/import_kev.py

Falls der Server von CISA blockiert wird (HTTP 403, z.B. bei Hosting-IPs),
die Datei manuell herunterladen und mit --file importieren:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

from src.core.database import async_session_factory
from src.ingest.kev_importer import import_kev, load_kev_file


async def main():
    parser = argparse.ArgumentParser(description="CISA KEV Import")
    parser.add_argument("--file", help="Manuell heruntergeladene KEV-JSON-Datei statt Download")
    args = parser.parse_args()

    vulns = load_kev_file(args.file) if args.file else None

    async with async_session_factory() as session:
        result = await import_kev(session, vulns=vulns)
        await session.commit()
    print(f"KEV-Import: {result['marked']} markiert, {result['created']} neu, {result['total_kev']} gesamt")


if __name__ == "__main__":
    asyncio.run(main())
