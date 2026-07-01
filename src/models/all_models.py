"""
SQLAlchemy-Modelle für alle BASIS-Schichten.
O – Owners / B – Business / A – Application / S – System / H – Hardware / I – Infrastructure
"""

import uuid
from datetime import datetime
from typing import Optional

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    UUID, Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# O – Owners
# ---------------------------------------------------------------------------

class Owner(Base):
    __tablename__ = "owners"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(200))
    team: Mapped[Optional[str]] = mapped_column(String(200))
    department: Mapped[Optional[str]] = mapped_column(String(200))
    role: Mapped[Optional[str]] = mapped_column(String(100))  # Owner, Operator, User
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    business_processes: Mapped[list["BusinessProcess"]] = relationship(back_populates="owner")


# ---------------------------------------------------------------------------
# B – Business Processes
# ---------------------------------------------------------------------------

class BusinessProcess(Base):
    """BASIS B-Layer: Business-Prozesse mit Owner-Verknüpfung."""
    __tablename__ = "business_processes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1–5
    sla_rto_hours: Mapped[Optional[int]] = mapped_column(Integer)  # Recovery Time Objective
    sla_rpo_hours: Mapped[Optional[int]] = mapped_column(Integer)  # Recovery Point Objective
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("owners.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    owner: Mapped[Optional["Owner"]] = relationship(back_populates="business_processes")
    process_assets: Mapped[list["ProcessAsset"]] = relationship(back_populates="process")
    applications: Mapped[list["Application"]] = relationship(back_populates="process", cascade="all, delete-orphan")


class ProcessAsset(Base):
    """Verknüpfung Business-Prozess ↔ Asset (mit Rolle)."""
    __tablename__ = "process_assets"

    process_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("business_processes.id", ondelete="CASCADE"), primary_key=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[Optional[str]] = mapped_column(String(100))  # primary, secondary, dependency

    process: Mapped["BusinessProcess"] = relationship(back_populates="process_assets")
    asset: Mapped["Asset"] = relationship(back_populates="process_assets")


# ---------------------------------------------------------------------------
# A – Application (BASIS A-Layer)
# Fachliche Anwendungen/Services – KEINE Software-Pakete (die gehören in S)
# ---------------------------------------------------------------------------

class Application(Base):
    """
    BASIS A-Layer: Fachliche Anwendung oder Service.

    Beispiele: "Webshop Frontend", "CRM-System", "Zahlungsgateway", "ERP"
    – nicht: nginx, OpenSSL, PostgreSQL (die gehören ins SBOM / S-Layer)
    """
    __tablename__ = "applications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Typ der Anwendung
    app_type: Mapped[Optional[str]] = mapped_column(String(50))
    # web, api, batch, integration, desktop, mobile, service

    version: Mapped[Optional[str]] = mapped_column(String(100))
    url: Mapped[Optional[str]] = mapped_column(String(500))

    # Primärer/erster Prozess (Abwärtskompatibilität). Die maßgebliche
    # Prozess-Zuordnung läuft über process_applications (n:m).
    process_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("business_processes.id", ondelete="SET NULL"),
        index=True, nullable=True
    )

    # Optionaler Owner auf App-Ebene (kann abweichen vom Prozess-Owner)
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("owners.id", ondelete="SET NULL"), nullable=True
    )

    # Kritikalität der Anwendung selbst (kann von Prozess abweichen)
    criticality: Mapped[Optional[int]] = mapped_column(Integer)  # 1–5

    # Auf welchen Assets läuft diese Anwendung (JSONB-Liste von Asset-UUIDs)
    # Einfacher als Many-to-Many für diesen Use-Case
    asset_ids: Mapped[Optional[list]] = mapped_column(JSONB, default=list)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    process: Mapped["BusinessProcess"] = relationship(back_populates="applications")
    owner: Mapped[Optional["Owner"]] = relationship()
    components: Mapped[list["ApplicationComponent"]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )


# ---------------------------------------------------------------------------
# A↔S Zwischenschicht: Application Components
# Welche SBOM-Pakete eine Fachanwendung nutzt – als Regel auf Paket-Identität,
# die gegen die SBOM aufgelöst wird (überlebt Rescans, gilt über Systeme).
# ---------------------------------------------------------------------------

class ApplicationComponent(Base):
    """
    Verknüpfung Fachanwendung ↔ genutztes SBOM-Paket (Regel, nicht konkrete Zeile).

    Auflösung: match_value wird je nach match_kind gegen sbom_entries gematcht;
    daraus ergeben sich konkrete Versionen, Systeme (asset_id) und CVEs.
    """
    __tablename__ = "application_components"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), index=True, nullable=False
    )

    name: Mapped[str] = mapped_column(String(300), nullable=False)          # Anzeige, z.B. "OpenSSL"
    match_kind: Mapped[str] = mapped_column(String(20), default="name")     # name | prefix | purl | cpe
    match_value: Mapped[str] = mapped_column(String(500), nullable=False)   # z.B. "openssl"

    # Optionale Eingrenzung auf ein bestimmtes System (gegen Über-Zuordnung
    # bei sehr verbreiteten Paketen wie openssl/glibc)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    origin: Mapped[str] = mapped_column(String(20), default="manual")       # manual | auto
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)         # Auto-Vorschlag bestätigt?
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    application: Mapped["Application"] = relationship(back_populates="components")

    __table_args__ = (
        UniqueConstraint("application_id", "match_kind", "match_value", "asset_id",
                         name="uq_app_component"),
    )


# ---------------------------------------------------------------------------
# Fachanwendung ↔ Prozess (n:m) und Fachanwendung ↔ Netz-Elemente
# Eine Fachanwendung (applications) wird einmal definiert (Assets, Netze,
# Komponenten) und in beliebig viele Prozesse "reingezogen".
# ---------------------------------------------------------------------------

class ProcessApplication(Base):
    """Zuordnung Business-Prozess ↔ Fachanwendung (n:m)."""
    __tablename__ = "process_applications"

    process_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("business_processes.id", ondelete="CASCADE"), primary_key=True
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True
    )


class ApplicationIpNetwork(Base):
    """Verknüpfung Fachanwendung ↔ benanntes IP-Netz."""
    __tablename__ = "application_ip_networks"

    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True
    )
    network_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_networks.id", ondelete="CASCADE"), primary_key=True
    )


class ApplicationGateway(Base):
    """Verknüpfung Fachanwendung ↔ Gateway (Router/Firewall)."""
    __tablename__ = "application_gateways"

    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True
    )
    gateway_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_gateways.id", ondelete="CASCADE"), primary_key=True
    )


# ---------------------------------------------------------------------------
# H – Hardware (Assets)
# ---------------------------------------------------------------------------

class Asset(Base):
    """
    BASIS H-Layer: Hardware-Assets.
    Enthält auch S-Layer (OS/System-Daten) da eng verknüpft.
    """
    __tablename__ = "assets"

    # Stabile Identifikatoren
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mac_address: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(200), index=True)
    chassis_id: Mapped[Optional[str]] = mapped_column(String(200))  # LLDP

    # Soft-Identifikatoren (können sich ändern)
    hostname: Mapped[Optional[str]] = mapped_column(String(300), index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), index=True)
    additional_ips: Mapped[Optional[list]] = mapped_column(ARRAY(String(50)))
    # Weitere IP-Adressen (z.B. WAN-IP, Management-IP, zweites Interface)
    fqdn: Mapped[Optional[str]] = mapped_column(String(500))

    # Gerättyp
    asset_type: Mapped[str] = mapped_column(String(50), default="server")
    # server, switch, router, firewall, client, printer, vm, container

    # S-Layer: OS / System
    os_name: Mapped[Optional[str]] = mapped_column(String(100))
    os_version: Mapped[Optional[str]] = mapped_column(String(100))
    os_arch: Mapped[Optional[str]] = mapped_column(String(50))

    # Hardware-Details
    manufacturer: Mapped[Optional[str]] = mapped_column(String(200))
    model: Mapped[Optional[str]] = mapped_column(String(200))
    firmware_version: Mapped[Optional[str]] = mapped_column(String(100))

    # I-Layer: Exposure + Netzwerk-Zugehörigkeit
    exposure_level: Mapped[str] = mapped_column(String(20), default="INTERN")
    # INTERN | DMZ | EXTERN – höchste Risikostufe (für CVE-Impact)

    network_zones: Mapped[Optional[list]] = mapped_column(ARRAY(String))
    # Alle Netze in denen das Asset aktiv ist, z.B.:
    # ["INTERN", "DMZ"]  oder  ["192.168.178.0/24", "10.0.0.0/8", "EXTERN"]
    # Router/Firewalls haben typisch mehrere Einträge

    # Automatisch zugeordnetes primäres Netzwerk (aus IP-Adresse ermittelt)
    network_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_networks.id", ondelete="SET NULL"), nullable=True
    )

    open_ports: Mapped[Optional[dict]] = mapped_column(JSONB, default=list)
    # [{"port": 22, "proto": "tcp", "reachable_from": ["internet"]}]

    # Rack-Position
    rack_id: Mapped[Optional[str]] = mapped_column(String(200))
    rack_unit: Mapped[Optional[int]] = mapped_column(Integer)
    location: Mapped[Optional[str]] = mapped_column(String(300))  # Freitext oder Tag

    # Tags (flexibel, kein Pflichtschema)
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=list)

    # Quellinformationen
    sources: Mapped[Optional[dict]] = mapped_column(JSONB, default=list)
    # [{"origin": "snmp-discovery", "last_seen": "2026-05-29T10:00:00Z"}]

    # Mindest-Konfidenz für automatische Merges (0.0 = alles, 1.0 = nur UUID-Match)
    min_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    # Referenz: 0.95 = Stable Key, 0.80 = 2 Soft Keys, 0.40 = 1 Soft Key

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Archiviert: Asset existiert noch, wird aber nicht mehr betrachtet —
    # ausgeblendet aus Reports/Auswertungen und nicht mehr durch Discovery aktualisiert.
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    # Erzwingt die VM/Container-Erkennung unabhängig von Tags/Hersteller
    # (z.B. Microcode-CVEs werden dann immer als nicht-exploitierbar gewertet).
    force_vm: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # Wird bei jedem Collector-Report aktualisiert (auch wenn keine Daten geändert wurden)

    # Relations
    sbom_entries: Mapped[list["SBOMEntry"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    process_assets: Mapped[list["ProcessAsset"]] = relationship(back_populates="asset")
    cve_impacts: Mapped[list["CVEImpact"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    port_scans: Mapped[list["PortScan"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    gateways: Mapped[list["NetworkGateway"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    network: Mapped[Optional["IpNetwork"]] = relationship(
        back_populates="assets",
        foreign_keys="[Asset.network_id]",
    )


# ---------------------------------------------------------------------------
# A – Application / SBOM
# ---------------------------------------------------------------------------

class SBOMEntry(Base):
    """Software Bill of Materials – installierte Pakete pro Asset."""
    __tablename__ = "sbom_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    pkg_name: Mapped[str] = mapped_column(String(300), nullable=False)
    pkg_version: Mapped[str] = mapped_column(String(100), nullable=False)
    pkg_type: Mapped[Optional[str]] = mapped_column(String(50))
    # library, application, os-package, container, firmware

    cpe: Mapped[Optional[str]] = mapped_column(String(500))
    # cpe:2.3:a:openssl:openssl:3.1.2:*:*:*:*:*:*:*

    purl: Mapped[Optional[str]] = mapped_column(String(500))
    # pkg:deb/ubuntu/openssl@3.1.2

    source: Mapped[Optional[str]] = mapped_column(String(100))
    # dpkg, rpm, pip, npm, manual, cyclonedx, spdx

    scanned_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="sbom_entries")

    __table_args__ = (
        UniqueConstraint("asset_id", "pkg_name", "pkg_version", name="uq_sbom_asset_pkg_ver"),
    )


# ---------------------------------------------------------------------------
# I – Infrastructure: Port Scans
# ---------------------------------------------------------------------------

class PortScan(Base):
    """Portscan-Ergebnisse pro Asset (Nmap o.ä.)."""
    __tablename__ = "port_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20))  # open, closed, filtered
    service: Mapped[Optional[str]] = mapped_column(String(100))  # ssh, http, https
    version: Mapped[Optional[str]] = mapped_column(String(200))  # Banner / Version
    scanned_from: Mapped[Optional[str]] = mapped_column(String(50))
    # intern, extern, dmz – wo wurde gescannt?
    scanned_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="port_scans")


# ---------------------------------------------------------------------------
# Services / Listener (Brücke I ↔ C/S): Port → Prozess → SBOM-Paket
# ---------------------------------------------------------------------------

class Service(Base):
    """
    Lauschender Dienst auf einem Asset.

    Verbindet einen offenen Port (inkl. Bind-Adresse/-Scope, auch localhost)
    mit dem dahinterliegenden Prozess und – aufgelöst – dem SBOM-Paket.
    Optional Docker-Container-Bezug (Image/Name) für Dienste hinter Proxies.
    """
    __tablename__ = "services"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    proto: Mapped[str] = mapped_column(String(10), default="tcp")

    bind_address: Mapped[Optional[str]] = mapped_column(String(64))
    bind_scope: Mapped[str] = mapped_column(String(16), default="lan")  # localhost | lan | all

    process_name: Mapped[Optional[str]] = mapped_column(String(200))
    process_path: Mapped[Optional[str]] = mapped_column(String(500))
    sbom_pkg: Mapped[Optional[str]] = mapped_column(String(300))         # aufgelöstes SBOM-Paket

    container_name: Mapped[Optional[str]] = mapped_column(String(200))
    container_image: Mapped[Optional[str]] = mapped_column(String(300))

    source: Mapped[Optional[str]] = mapped_column(String(100))
    scanned_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("asset_id", "port", "proto", "bind_address", name="uq_service_asset_port"),
    )


# ---------------------------------------------------------------------------
# Alarme / Detections (z.B. ESET Incident Management)
# ---------------------------------------------------------------------------

class Alert(Base):
    """Sicherheits-Alarm/Detection einer externen Quelle (z.B. ESET /v2/detections)."""
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Externe ID (Detection-UUID) zur Deduplizierung / Upsert
    external_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="eset")

    # Verknüpfung zum Asset (per Geräte-UUID/Hostname aufgelöst, optional)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), index=True, nullable=True
    )
    device_uuid: Mapped[Optional[str]] = mapped_column(String(128))
    device_name: Mapped[Optional[str]] = mapped_column(String(255))

    severity: Mapped[Optional[str]] = mapped_column(String(30), index=True)   # HIGH/MEDIUM/LOW/…
    severity_score: Mapped[Optional[int]] = mapped_column(Integer)
    threat: Mapped[Optional[str]] = mapped_column(String(500))                # Bedrohungs-/Anzeigename
    type_name: Mapped[Optional[str]] = mapped_column(String(200))
    category: Mapped[Optional[str]] = mapped_column(String(120))
    resolved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    occurred_at: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ---------------------------------------------------------------------------
# IP-Netzwerke (I-Layer: definierte Subnetze mit Namen)
# ---------------------------------------------------------------------------

class IpNetwork(Base):
    """
    Benanntes IP-Netzwerk (Subnetz).
    Assets werden automatisch anhand ihrer IP-Adresse zugeordnet.
    """
    __tablename__ = "ip_networks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cidr: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    # z.B. "192.168.178.0/24", "10.0.0.0/8", "172.16.0.0/12"
    description: Mapped[Optional[str]] = mapped_column(Text)
    exposure_level: Mapped[str] = mapped_column(String(20), default="INTERN")
    color: Mapped[Optional[str]] = mapped_column(String(20))  # Farbe für UI
    # Optionaler Router/Firewall der dieses Netz nach oben verbindet
    gateway_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    assets: Mapped[list["Asset"]] = relationship(
        back_populates="network",
        foreign_keys="[Asset.network_id]",
    )


# ---------------------------------------------------------------------------
# Asset Reports (externe Audit-Reports z.B. Lynis)
# ---------------------------------------------------------------------------

class AssetReport(Base):
    """Externer Audit-Report, angehängt an ein Asset."""
    __tablename__ = "asset_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    report_type: Mapped[str] = mapped_column(String(50), default="lynis")
    filename: Mapped[Optional[str]] = mapped_column(String(300))
    parsed_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    raw_content: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


# ---------------------------------------------------------------------------
# Asset Snapshots (tägliche Zustandssicherung)
# ---------------------------------------------------------------------------

class AssetSnapshot(Base):
    """Täglicher Snapshot des Asset-Zustands. Max. 30 pro Asset."""
    __tablename__ = "asset_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    snapshot_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Vollständiger Zustand als JSON
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # Diff zum vorherigen Snapshot (None beim ersten)
    diff: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("asset_id", "snapshot_date", name="uq_snapshot_asset_date"),
    )


# ---------------------------------------------------------------------------
# Network Gateways (I-Layer: Übergangspunkte zwischen Segmenten)
# ---------------------------------------------------------------------------

class NetworkGateway(Base):
    """
    Markiert ein Asset (Router/Firewall) als Gateway zwischen zwei Netzwerksegmenten.
    Beispiele:
      - MikroTik hAP:  INTERN → EXTERN  (Hauptrouter)
      - FortiGate:     DMZ → INTERN     (Firewall)
      - CRS-Switch:    VLAN-10 → VLAN-20 (L3-Switch)
    """
    __tablename__ = "network_gateways"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    from_segment: Mapped[str] = mapped_column(String(100), nullable=False)
    # z.B. "INTERN", "192.168.178.0/24", "VLAN-10", "DMZ"
    to_segment: Mapped[str] = mapped_column(String(100), nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="gateways")


# ---------------------------------------------------------------------------
# Conflict Queue
# ---------------------------------------------------------------------------

class ConflictQueueEntry(Base):
    """Eingehende Geräte-Daten die nicht eindeutig zugeordnet werden konnten."""
    __tablename__ = "conflict_queue"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incoming_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(100))
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    matched_on: Mapped[Optional[list]] = mapped_column(ARRAY(String))
    candidate_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending | merged | created | discarded
    resolved_by: Mapped[Optional[str]] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    candidate_asset: Mapped[Optional["Asset"]] = relationship()


# ---------------------------------------------------------------------------
# CVE-Einträge (RAG-Basis)
# ---------------------------------------------------------------------------

class CVEEntry(Base):
    """CVE aus NVD – mit pgvector Embedding für semantische Suche."""
    __tablename__ = "cve_entries"

    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200))
    attack_vector: Mapped[Optional[str]] = mapped_column(String(50))
    # NETWORK, ADJACENT, LOCAL, PHYSICAL
    severity: Mapped[Optional[str]] = mapped_column(String(20))
    # CRITICAL, HIGH, MEDIUM, LOW
    affected_pkgs: Mapped[Optional[dict]] = mapped_column(JSONB)
    # [{"pkg": "openssl", "cpe": "...", "min": "3.0.0", "max": "3.1.4"}]
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    modified_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    embedding = Column(Vector(384))  # all-MiniLM-L6-v2 Dimension
    raw: Mapped[Optional[dict]] = mapped_column(JSONB)
    # CISA Known Exploited Vulnerabilities
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[Optional[str]] = mapped_column(String(20))  # YYYY-MM-DD
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)

    impacts: Mapped[list["CVEImpact"]] = relationship(back_populates="cve")


class CVEImpact(Base):
    """Berechneter CVE-Impact pro Asset (gecacht)."""
    __tablename__ = "cve_impact"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(50), ForeignKey("cve_entries.cve_id"))
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"))
    risk_level: Mapped[Optional[str]] = mapped_column(String(20))  # HIGH, MEDIUM, LOW
    risk_score: Mapped[Optional[float]] = mapped_column(Float)
    reasoning: Mapped[Optional[str]] = mapped_column(Text)  # LLM-Begründung
    affected_pkg: Mapped[Optional[str]] = mapped_column(String(300))
    affected_ver: Mapped[Optional[str]] = mapped_column(String(100))
    computed_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    cve: Mapped["CVEEntry"] = relationship(back_populates="impacts")
    asset: Mapped["Asset"] = relationship(back_populates="cve_impacts")

    __table_args__ = (
        UniqueConstraint("cve_id", "asset_id", name="uq_cve_impact_cve_asset"),
    )


# ---------------------------------------------------------------------------
# Globale Anwendungseinstellungen (Single-Row, id=1)
# ---------------------------------------------------------------------------

class AppSettings(Base):
    """Globale, über die UI änderbare Einstellungen (eine Zeile, id=1)."""
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Microcode-/Firmware-CVEs (intel-microcode, amd64-microcode, ...) auf
    # VMs/VPS als nicht-exploitierbar ausblenden bzw. herabstufen.
    hide_vm_microcode_cves: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# ---------------------------------------------------------------------------
# Audit Sessions (Jumpbox SSH-Session-Aufzeichnung)
# ---------------------------------------------------------------------------

class AuditSession(Base):
    """
    Eine über die Jumpbox aufgezeichnete SSH-Session zu einem Zielhost.

    Zwei Quellen, korreliert über session_uuid:
    - Jumpbox lädt die komplette Terminal-Aufzeichnung (script -t) hoch
    - Zielhost lädt die saubere Kommandoliste hoch (siehe AuditSessionCommand)
    """
    __tablename__ = "audit_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Korrelations-ID, von der Jumpbox erzeugt und per SetEnv an das Ziel gereicht
    session_uuid: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    operator: Mapped[str] = mapped_column(String(120), nullable=False)   # wer auf der Jumpbox eingeloggt war
    jumpbox_host: Mapped[Optional[str]] = mapped_column(String(255))
    target_host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_user: Mapped[Optional[str]] = mapped_column(String(120))      # User auf dem Zielhost

    # Verknüpfung zum Asset (per hostname/IP aufgelöst, optional)
    target_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), index=True, nullable=True
    )

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    duration_sec: Mapped[Optional[int]] = mapped_column(Integer)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer)

    # Aufzeichnung der Jumpbox (script -t): Typescript + Timing
    recording_format: Mapped[str] = mapped_column(String(30), default="script-typescript")
    recording: Mapped[Optional[str]] = mapped_column(Text)        # typescript (Terminal-Stream)
    timing: Mapped[Optional[str]] = mapped_column(Text)           # script --timing (für Replay)
    client_ip: Mapped[Optional[str]] = mapped_column(String(64))  # von wo der Operator kam

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class AuditSessionCommand(Base):
    """Einzelnes, zielseitig protokolliertes Kommando einer Audit-Session."""
    __tablename__ = "audit_session_commands"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("audit_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)         # Reihenfolge innerhalb der Session
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    cwd: Mapped[Optional[str]] = mapped_column(String(500))
    os_user: Mapped[Optional[str]] = mapped_column(String(120))

    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_audit_cmd_session_seq"),
    )
