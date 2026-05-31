"""
Lynis Report Parser.

Parsed das lynis-report.dat Format:
  key=value
  warning[]=PLUGIN-ID|Beschreibung|Details
  suggestion[]=PLUGIN-ID|Beschreibung|Details

Lynis-Report.dat liegt standardmäßig in /var/log/lynis-report.dat
"""

from __future__ import annotations

import re
from typing import Optional


def parse_lynis_report(content: str) -> dict:
    """
    Parsed den Inhalt einer lynis-report.dat Datei.
    Gibt ein strukturiertes Dict zurück.
    """
    data: dict = {
        "hardening_index": None,
        "lynis_version": None,
        "report_datetime": None,
        "hostname": None,
        "os": None,
        "os_version": None,
        "kernel": None,
        "warnings": [],
        "suggestions": [],
        "tests_performed": 0,
        "tests_skipped": 0,
        "plugins_enabled": [],
        "services": [],
        "users": [],
        "network_interfaces": [],
        "listening_ports": [],
        "installed_packages": 0,
        "vulnerable_packages": [],
        "file_integrity": [],
        "extra": {},
    }

    # Direkte Felder (Präfix-Map)
    scalar_map = {
        "hardening_index":       ("hardening_index", int),
        "lynis_version":         ("lynis_version", str),
        "report_datetime":       ("report_datetime", str),
        "hostname":              ("hostname", str),
        "os":                    ("os", str),
        "os_version":            ("os_version", str),
        "linux_version":         ("kernel", str),
        "tests_performed":       ("tests_performed", int),
        "tests_skipped":         ("tests_skipped", int),
        "installed_packages":    ("installed_packages", int),
    }

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Warnings: warning[]=PLUGIN-ID|Beschreibung|Details
        if line.startswith("warning[]="):
            val = line[len("warning[]="):]
            parts = val.split("|")
            data["warnings"].append({
                "id":          parts[0] if len(parts) > 0 else val,
                "description": parts[1] if len(parts) > 1 else "",
                "detail":      parts[2] if len(parts) > 2 else "",
                "solution":    parts[3] if len(parts) > 3 else "",
            })
            continue

        # Suggestions: suggestion[]=PLUGIN-ID|Beschreibung|Details
        if line.startswith("suggestion[]="):
            val = line[len("suggestion[]="):]
            parts = val.split("|")
            data["suggestions"].append({
                "id":          parts[0] if len(parts) > 0 else val,
                "description": parts[1] if len(parts) > 1 else "",
                "detail":      parts[2] if len(parts) > 2 else "",
                "solution":    parts[3] if len(parts) > 3 else "",
            })
            continue

        # Listening Ports: network_listen_port[]=port|proto|...
        if line.startswith("network_listen_port[]="):
            val = line[len("network_listen_port[]="):]
            parts = val.split("|")
            if parts:
                try:
                    data["listening_ports"].append({
                        "port":    int(parts[0]) if parts[0].isdigit() else parts[0],
                        "proto":   parts[1] if len(parts) > 1 else "tcp",
                        "service": parts[2] if len(parts) > 2 else None,
                    })
                except (ValueError, IndexError):
                    pass
            continue

        # Vulnerable packages: vulnerable_package[]=name|version
        if line.startswith("vulnerable_package[]="):
            val = line[len("vulnerable_package[]="):]
            parts = val.split("|")
            data["vulnerable_packages"].append({
                "name":    parts[0],
                "version": parts[1] if len(parts) > 1 else "",
            })
            continue

        # File integrity issues
        if line.startswith("file_integrity_tool_installed[]="):
            data["file_integrity"].append(line.split("=", 1)[1])
            continue

        # Plugin enabled
        if line.startswith("plugin_enabled[]="):
            data["plugins_enabled"].append(line.split("=", 1)[1])
            continue

        # Einfache Key=Value Felder
        if "=" in line and not line.startswith("["):
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()

            if key in scalar_map:
                field, cast = scalar_map[key]
                try:
                    data[field] = cast(val) if val else None
                except (ValueError, TypeError):
                    data[field] = val
            elif not line.startswith(("warning", "suggestion", "network_listen",
                                       "vulnerable_package", "file_integrity",
                                       "plugin_enabled")):
                # Unbekannte Felder in extra
                if val and key not in data["extra"]:
                    data["extra"][key] = val

    # Score-Kategorie berechnen
    idx = data.get("hardening_index")
    if idx is not None:
        if idx >= 80:
            data["score_label"] = "GUT"
            data["score_color"] = "green"
        elif idx >= 60:
            data["score_label"] = "MITTEL"
            data["score_color"] = "yellow"
        else:
            data["score_label"] = "NIEDRIG"
            data["score_color"] = "red"

    # Extra bereinigen (max 50 Felder)
    data["extra"] = dict(list(data["extra"].items())[:50])

    return data


def detect_report_type(content: str, filename: str) -> str:
    """Erkennt den Report-Typ anhand von Inhalt oder Dateiname."""
    if "hardening_index" in content or "lynis_version" in content:
        return "lynis"
    if filename.endswith(".xml") and "nmap" in content.lower():
        return "nmap"
    if filename.endswith(".json"):
        return "json"
    return "text"
