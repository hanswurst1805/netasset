#!/usr/bin/env python3
"""
Täglicher Snapshot-Job: Erstellt Snapshots aller aktiven Assets.

Aufruf (manuell):
    python scripts/daily_snapshots.py

Cron-Job (täglich um 02:00):
    0 2 * * * root python3 /opt/netasset/scripts/daily_snapshots.py

Oder per API:
    POST /api/v1/snapshots/run
"""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

from src.core.database import async_session_factory
from src.core.snapshots import run_daily_snapshots


async def main():
    async with async_session_factory() as session:
        result = await run_daily_snapshots(session)
        await session.commit()
    print(f"Snapshots: {result['created']} neu, {result['updated']} aktualisiert, "
          f"{result['errors']} Fehler / {result['total']} Assets gesamt")


if __name__ == "__main__":
    asyncio.run(main())
