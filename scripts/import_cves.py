#!/usr/bin/env python3
"""Cronjob: NVD-CVEs importieren.

Aufruf:
    python scripts/import_cves.py --days 7
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingest.nvd_importer import import_cves

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


async def main():
    parser = argparse.ArgumentParser(description="NVD CVE Import")
    parser.add_argument("--days", type=int, default=7, help="Wie viele Tage zurück importieren")
    args = parser.parse_args()

    count = await import_cves(days=args.days)
    print(f"Import abgeschlossen: {count} CVEs verarbeitet")


if __name__ == "__main__":
    asyncio.run(main())
