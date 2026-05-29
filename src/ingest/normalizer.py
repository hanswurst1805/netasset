from __future__ import annotations
"""Daten-Normalisierung für Discovery-Eingaben."""

import re


def normalize_mac(mac: str | None) -> str | None:
    """Vereinheitlicht MAC-Adressen auf lowercase XX:XX:XX:XX:XX:XX."""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2)).lower()


def normalize_ip(ip: str | None) -> str | None:
    """Entfernt Leerzeichen, gibt None bei leerem String zurück."""
    if not ip:
        return None
    ip = ip.strip()
    return ip or None


def normalize_hostname(hostname: str | None) -> str | None:
    """Lowercase hostname, ohne trailing dots."""
    if not hostname:
        return None
    return hostname.strip().lower().rstrip(".")


def normalize_version(version: str | None) -> str | None:
    """Normalisiert Package-Versionen (entfernt Epoche, Distro-Suffix)."""
    if not version:
        return None
    # Entfernt Epoch (z.B. "1:3.1.2" → "3.1.2")
    version = re.sub(r"^\d+:", "", version.strip())
    # Entfernt Debian/Ubuntu Build-Suffix (z.B. "3.1.2-1ubuntu1" → "3.1.2")
    version = re.sub(r"-\d+\w*$", "", version)
    return version


def normalize_device_data(raw: dict) -> dict:
    """Normalisiert ein eingehendes Discovery-Device-Dict."""
    return {
        **raw,
        "mac_address": normalize_mac(raw.get("mac_address")),
        "ip_address": normalize_ip(raw.get("ip_address")),
        "hostname": normalize_hostname(raw.get("hostname")),
        "fqdn": normalize_hostname(raw.get("fqdn")),
    }
