"""Generischer Discovery-Adapter – wandelt verschiedene Quellformate in das interne Format."""

from typing import Any

from src.ingest.normalizer import normalize_device_data


class DiscoveryAdapter:
    """
    Basis-Adapter: transformiert source-spezifische Daten in ein
    normalisiertes Dict, das der IdentityResolver verarbeiten kann.
    """

    SOURCE_NAME = "generic"

    def transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Überschreiben in Subklassen für source-spezifische Felder."""
        return normalize_device_data({**raw, "source": self.SOURCE_NAME})

    def transform_batch(self, items: list[dict]) -> list[dict]:
        return [self.transform(item) for item in items]


class NmapAdapter(DiscoveryAdapter):
    """Wandelt Nmap XML-geparste Dicts (z.B. python-nmap) ins interne Format."""

    SOURCE_NAME = "nmap"

    def transform(self, raw: dict) -> dict:
        host = raw.get("host", raw)
        addresses = host.get("addresses", {})
        ports_raw = host.get("ports", {}).get("port", [])

        open_ports = []
        if isinstance(ports_raw, dict):
            ports_raw = [ports_raw]
        for p in ports_raw:
            if p.get("state", {}).get("@state") == "open":
                open_ports.append({
                    "port": int(p.get("@portid", 0)),
                    "proto": p.get("@protocol", "tcp"),
                    "service": p.get("service", {}).get("@name"),
                    "reachable_from": ["intern"],
                })

        return normalize_device_data({
            "ip_address": addresses.get("ipv4"),
            "mac_address": addresses.get("mac"),
            "hostname": (host.get("hostnames") or {}).get("hostname", {}).get("@name"),
            "os_name": (host.get("os") or {}).get("osmatch", {}).get("@name"),
            "open_ports": open_ports,
            "source": self.SOURCE_NAME,
            "asset_type": "server",
        })


class SNMPAdapter(DiscoveryAdapter):
    """Wandelt SNMP-Walk-Ergebnisse ins interne Format."""

    SOURCE_NAME = "snmp"

    def transform(self, raw: dict) -> dict:
        return normalize_device_data({
            "hostname": raw.get("sysName"),
            "ip_address": raw.get("ip"),
            "fqdn": raw.get("sysName"),
            "manufacturer": raw.get("entPhysicalMfgName"),
            "model": raw.get("entPhysicalModelName"),
            "serial_number": raw.get("entPhysicalSerialNum"),
            "firmware_version": raw.get("entPhysicalFirmwareRev"),
            "os_name": raw.get("sysDescr"),
            "source": self.SOURCE_NAME,
        })


class LLDPAdapter(DiscoveryAdapter):
    """Wandelt LLDP-Neighbor-Daten ins interne Format."""

    SOURCE_NAME = "lldp"

    def transform(self, raw: dict) -> dict:
        return normalize_device_data({
            "hostname": raw.get("system_name"),
            "fqdn": raw.get("system_name"),
            "chassis_id": raw.get("chassis_id"),
            "mac_address": raw.get("chassis_id"),  # Chassis-ID ist oft die MAC
            "ip_address": raw.get("management_address"),
            "manufacturer": raw.get("system_description", "").split(" ")[0] if raw.get("system_description") else None,
            "source": self.SOURCE_NAME,
        })


ADAPTERS: dict[str, type[DiscoveryAdapter]] = {
    "nmap": NmapAdapter,
    "snmp": SNMPAdapter,
    "lldp": LLDPAdapter,
    "generic": DiscoveryAdapter,
}


def get_adapter(source_type: str) -> DiscoveryAdapter:
    cls = ADAPTERS.get(source_type, DiscoveryAdapter)
    return cls()
