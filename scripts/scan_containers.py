#!/usr/bin/env python3
"""Cronjob: alle Container-Images neu gegen OSV abgleichen."""

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingest.container_scan import scan_all_images

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)

if __name__ == "__main__":
    print(asyncio.run(scan_all_images()))
