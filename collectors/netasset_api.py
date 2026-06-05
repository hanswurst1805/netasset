#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset API-Hilfsfunktionen – gemeinsam genutzt von allen Collectors.

Stellt bereit:
  - negotiate_api_version(): wählt die beste API-Version per /health-Abfrage
  - api_base(): gibt den vollständigen API-Basispfad zurück (z.B. https://host/api/v1)
"""

import json
import logging
import urllib.error
import urllib.request

log = logging.getLogger(__name__)


def negotiate_api_version(
    api_url: str,
    supported_versions: list[str],
    preferred: str = "v1",
) -> str:
    """
    Fragt GET /health ab und wählt die beste gemeinsam unterstützte API-Version.

    Der Server antwortet mit:
      {"status": "ok", "api_versions": ["v1"], "current_version": "v1", ...}

    `supported_versions` wird vom jeweiligen Collector übergeben (neueste zuerst).

    Gibt die ausgehandelte Version zurück (z.B. "v1").
    Fällt bei Verbindungsfehlern auf `preferred` zurück.
    """
    try:
        req = urllib.request.Request(api_url.rstrip("/") + "/health", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        server_versions = data.get("api_versions", [preferred])
        # Neueste gemeinsam unterstützte Version wählen
        for v in reversed(server_versions):
            if v in supported_versions:
                log.debug("API-Version ausgehandelt: %s (Server bietet: %s)", v, server_versions)
                return v
        log.warning(
            "Keine gemeinsame API-Version gefunden. Server: %s, Client: %s – verwende %s",
            server_versions, supported_versions, preferred,
        )
    except Exception as e:
        log.debug("API-Versionsaushandlung fehlgeschlagen: %s – verwende %s", e, preferred)
    return preferred


def api_base(
    api_url: str,
    supported_versions: list[str],
    version: str | None = None,
) -> str:
    """
    Gibt den vollständigen API-Basispfad zurück.

    `supported_versions` wird vom jeweiligen Collector übergeben (neueste zuerst).
    Wenn `version` nicht angegeben wird, wird negotiate_api_version() aufgerufen.

    Beispiel:
        api_base("https://netasset.example.com", ["v1"])         → "https://netasset.example.com/api/v1"
        api_base("https://netasset.example.com", ["v1"], "v1")   → "https://netasset.example.com/api/v1"
    """
    v = version or negotiate_api_version(api_url, supported_versions)
    return api_url.rstrip("/") + f"/api/{v}"
