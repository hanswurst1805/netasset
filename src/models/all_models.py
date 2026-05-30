"""
SQLAlchemy-Modelle für alle OBASHI-Schichten.
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
    """OBASHI B-Layer: Business-Prozesse mit Owner-Verknüpfung."""
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
# A – Application (OBASHI A-Layer)
# Fachliche Anwendungen/Services – KEINE Software-Pakete (die gehören in S)
# ---------------------------------------------------------------------------

class Application(Base):
    """
    OBASHI A-Layer: Fachliche Anwendung oder Service.

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

    # Zugehöriger Prozess
    process_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("business_processes.id", ondelete="CASCADE"), index=True
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


# ---------------------------------------------------------------------------
# H – Hardware (Assets)
# ---------------------------------------------------------------------------

class Asset(Base):
    """
    OBASHI H-Layer: Hardware-Assets.
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

    # I-Layer: Exposure
    exposure_level: Mapped[str] = mapped_column(String(20), default="INTERN")
    # INTERN | DMZ | EXTERN
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

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    # Relations
    sbom_entries: Mapped[list["SBOMEntry"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    process_assets: Mapped[list["ProcessAsset"]] = relationship(back_populates="asset")
    cve_impacts: Mapped[list["CVEImpact"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    port_scans: Mapped[list["PortScan"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    gateways: Mapped[list["NetworkGateway"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


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
