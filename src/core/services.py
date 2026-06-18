"""
Auflösung von Listening-Diensten auf SBOM-Pakete.

Ein Dienst (Prozess hinter einem offenen Port) wird auf das SBOM-Paket des
Assets abgebildet – über eine Alias-Tabelle für die üblichen Fälle und
ansonsten per Namensabgleich gegen die SBOM.
"""

from __future__ import annotations

import os
from typing import Optional

# Prozessname → typischer SBOM-Paketname
SERVICE_ALIAS: dict[str, str] = {
    "sshd": "openssh-server",
    "nginx": "nginx",
    "httpd": "apache2",
    "apache2": "apache2",
    "postgres": "postgresql",
    "postmaster": "postgresql",
    "mysqld": "mysql",
    "mariadbd": "mariadb",
    "redis-server": "redis",
    "mongod": "mongodb",
    "dockerd": "docker",
    "docker-proxy": "docker",
    "containerd": "containerd",
    "haproxy": "haproxy",
    "traefik": "traefik",
    "named": "bind9",
    "smbd": "samba",
    "php-fpm": "php-fpm",
    "node": "nodejs",
}

LOCALHOST = {"127.0.0.1", "::1", "localhost"}
ALL_IFACES = {"0.0.0.0", "::", ""}


def bind_scope(address: Optional[str]) -> str:
    """localhost | all | lan – Erreichbarkeit anhand der Bind-Adresse."""
    a = (address or "").strip()
    if a in LOCALHOST:
        return "localhost"
    if a in ALL_IFACES:
        return "all"
    return "lan"


def resolve_service_pkg(
    process_name: Optional[str],
    process_path: Optional[str],
    container_image: Optional[str],
    sbom_lower: dict[str, str],
) -> Optional[str]:
    """
    Liefert den passenden SBOM-Paketnamen (Original-Schreibweise) oder None.
    sbom_lower: {pkg_name.lower(): pkg_name} des Assets.
    """
    candidates: list[str] = []
    name = (process_name or "").strip().lower()
    if name:
        candidates.append(SERVICE_ALIAS.get(name, name))
        candidates.append(name)
    if process_path:
        base = os.path.basename(process_path).lower()
        if base:
            candidates.append(SERVICE_ALIAS.get(base, base))
            candidates.append(base)
    if container_image:
        # z.B. "library/nginx:1.27" → "nginx"
        img = container_image.split("/")[-1].split(":")[0].lower()
        if img:
            candidates.append(SERVICE_ALIAS.get(img, img))
            candidates.append(img)

    for c in candidates:
        if c in sbom_lower:
            return sbom_lower[c]
    return None
