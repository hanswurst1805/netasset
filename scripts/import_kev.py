#!/usr/bin/env python3
"""
CISA KEV Import — Known Exploited Vulnerabilities.
Kostenlos, kein API-Key nötig.

Aufruf:
    python scripts/import_kev.py

Empfohlen: täglich per Cron (die Liste wird täglich aktualisiert).
    0 6 * * * root python3 /opt/netasset/scripts/import_kev.py
"""

import asyncio, logging, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

from src.core.database import async_session_factory
from src.ingest.kev_importer import import_kev


async def main():
    async with async_session_factory() as session:
        result = await import_kev(session)
        await session.commit()
    print(f"KEV-Import: {result['marked']} markiert, {result['created']} neu, {result['total_kev']} gesamt")


if __name__ == "__main__":
    asyncio.run(main())
