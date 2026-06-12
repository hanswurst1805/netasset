# NetAsset – CMDB & Security Intelligence Platform

## Projektübersicht

NetAsset ist eine CMDB (Configuration Management Database) mit integrierter
Security-Intelligence. Das System sammelt Informationen über IT-Assets aus
verschiedenen Quellen, führt CVE-Impact-Analysen durch und bietet eine
vollständige Web-GUI für Betrieb und Sicherheitsauswertung.

### Kernfunktionen
- Asset-Verwaltung (Server, Switches, Router, Firewalls, Clients) mit Edit/Delete
- SBOM (Software Bill of Materials) pro Asset
- CVE-Impact-Analyse via RAG + pgvector
- OBASHI-Diagramm (O-B-A-S-H-I) mit fachlichen Applications, Owner-Verwaltung
- Exposure-Modell (INTERN / DMZ / EXTERN) + Netzwerk-Zonen (multi-network)
- IP-Netzwerk-Verwaltung mit automatischer Asset-Zuordnung per CIDR
- Netzwerk-Topologie mit Gateway-Konfiguration (Router/Firewall als Segmentgrenzen)
- Discovery-API mit prioritätsbasiertem Source-Merging und Conflict Queue
- Stabile Geräte-Identifikation via UUID + Fingerprinting + min_confidence pro Asset
- JWT-Auth + API-Keys mit Tag-basierter Zugriffskontrolle
- Optionale Zwei-Faktor-Authentifizierung (TOTP) inkl. Backup-Codes
- Tägliche Asset-Snapshots (30 Tage Historie, Diff-Ansicht)
- Lynis-Report Upload + Viewer mit Hardening-Score
- Strukturierte Security-Reports (Security Posture, Network Exposure, SBOM-Vuln, Prozess-Risiko)
- Letztes-Gesehen Timestamp pro Asset

---

## Tech Stack

| Komponente     | Technologie                        |
|----------------|------------------------------------|
| Backend API    | FastAPI (Python 3.12)              |
| Datenbank      | PostgreSQL 16 + pgvector Extension |
| Embeddings     | sentence-transformers (lokal)      |
| LLM            | OpenRouter API (modell-agnostisch) |
| CVE-Quelle     | NVD JSON 2.0 Feed (nvd.nist.gov)   |
| Migrations     | Alembic (async)                    |
| Tests          | pytest + pytest-asyncio            |
| Container      | Podman + Caddy (HTTPS/TLS)         |
| Frontend       | React + Vite + Tailwind CSS        |

---

## Projektstruktur

```
netasset/
├── CLAUDE.md
├── Dockerfile / Caddyfile / docker-compose.prod.yml
├── pyproject.toml
├── alembic.ini
├── migrations/versions/
│   ├── 0001_initial_schema.py       ← Alle OBASHI-Tabellen + pgvector
│   ├── 0002_auth.py                 ← users, api_keys
│   ├── 0003_applications_owners.py  ← applications (OBASHI A-Layer)
│   ├── 0004_conflict_queue.py       ← Conflict Queue
│   ├── 0005_network_gateways.py     ← Netzwerk-Gateways
│   ├── 0006_network_zones.py        ← assets.network_zones
│   ├── 0007_ip_networks.py          ← ip_networks + assets.network_id
│   ├── 0008_last_seen_at.py         ← assets.last_seen_at
│   ├── 0009_asset_snapshots.py      ← Tägliche Snapshots
│   ├── 0010_asset_reports.py        ← Lynis/Audit-Reports
│   └── 0011_min_confidence.py       ← assets.min_confidence
├── src/
│   ├── api/
│   │   ├── assets.py          ← Asset CRUD (mit Tag-Filter, min_confidence)
│   │   ├── sbom.py            ← SBOM Endpunkte
│   │   ├── cve.py             ← CVE-Impact + RAG-Query
│   │   ├── processes.py       ← Business-Prozesse
│   │   ├── discovery.py       ← Discovery-Ingest (Conflict Queue, min_confidence)
│   │   ├── auth.py            ← Login, User-Verwaltung, API-Keys
│   │   ├── conflicts.py       ← Conflict Queue (merge/create/discard)
│   │   ├── gateways.py        ← Network Gateways + Topologie
│   │   ├── networks.py        ← IP-Netzwerke + CIDR-Klassifizierung
│   │   ├── obashi.py          ← OBASHI-Diagramm pro Prozess
│   │   ├── owners.py          ← Owner CRUD (OBASHI O-Layer)
│   │   ├── applications.py    ← Application CRUD (OBASHI A-Layer)
│   │   ├── reporting.py       ← Strukturierte Security-Reports
│   │   ├── reports.py         ← Lynis/Audit-Report Upload
│   │   └── snapshots.py       ← Asset-Snapshots
│   ├── core/
│   │   ├── config.py          ← Settings (pydantic-settings)
│   │   ├── database.py        ← DB-Session, Engine (asyncpg UTC-Modus)
│   │   ├── identity.py        ← Identity Resolver + prioritätsbasiertes Merging
│   │   ├── auth.py            ← JWT + bcrypt + API-Key-Validierung
│   │   ├── llm.py             ← OpenRouter LLM-Client (lazy)
│   │   ├── network_classifier.py ← CIDR-basierte Asset-Zuordnung
│   │   └── snapshots.py       ← Snapshot-Service + Diff-Logik
│   ├── models/
│   │   ├── all_models.py      ← Alle SQLAlchemy-Modelle
│   │   └── auth.py            ← User, APIKey Modelle
│   ├── ingest/
│   │   ├── nvd_importer.py    ← NVD Feed → DB + Embeddings
│   │   ├── lynis_parser.py    ← Lynis Report Parser
│   │   ├── discovery_adapter.py ← Nmap/SNMP/LLDP Adapter
│   │   └── normalizer.py      ← Daten-Normalisierung
│   └── rag/
│       ├── embedder.py        ← sentence-transformers Wrapper
│       ├── vector_search.py   ← pgvector Cosine-Similarity
│       ├── cve_impact.py      ← SBOM-Match + Risk Score + LLM
│       ├── asset_context.py   ← Vollständiger Asset-Kontext für RAG
│       └── query_engine.py    ← Striktes RAG (nur DB-Daten, Anti-Halluzination)
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Assets.tsx / AssetDetail.tsx  ← Edit, Delete, Tabs
│       │   ├── CVEDashboard.tsx
│       │   ├── Chatbot.tsx          ← RAG mit Quellenangaben
│       │   ├── Processes.tsx        ← OBASHI-Diagramm + CVE-Risiko
│       │   ├── NetworkTopology.tsx  ← Gateway-Konfiguration
│       │   ├── Networks.tsx         ← IP-Netzwerke
│       │   ├── ConflictQueue.tsx    ← Manuelle Konfliktauflösung
│       │   ├── Reporting.tsx        ← 4 Security-Reports
│       │   └── UserManagement.tsx   ← User + API-Keys
│       └── components/
│           ├── OBASHIDiagram.tsx    ← SVG OBASHI-Layered-Diagram
│           ├── SnapshotTimeline.tsx ← 30-Tage-History + Diff
│           ├── ReportViewer.tsx     ← Lynis-Report mit Score-Ring
│           ├── LastSeen.tsx         ← "vor X Stunden" Anzeige
│           └── Badge.tsx / Layout.tsx
├── collectors/    ← separates Repo: github.com/hanswurst1805/drucker-collectors
│   ├── netasset_collector.py      ← osquery: Linux/Windows/macOS
│   ├── mikrotik_collector.py      ← MikroTik REST API + SNMP
│   ├── fritzbox_collector.py      ← Fritz!Box TR-064
│   ├── network_discovery_agent.py ← nmap-basierte Netzwerk-Discovery
│   ├── lynis_collector.py         ← Lynis-Report Upload
│   ├── eset_collector.py          ← ESET PROTECT Cloud (ESET Connect API)
│   ├── install_linux.sh / install_macos.sh / install_windows.ps1
│   └── *.conf.example
└── scripts/
    ├── import_cves.py             ← NVD-Import (--days N)
    ├── daily_snapshots.py         ← Tägliche Snapshots (Cron)
    ├── deploy.sh                  ← Podman-Deployment
    └── seed_demo_data.py
```

---

## Datenmodell – Schichten (OBASHI)

```
O – Owners        Person / Team / Abteilung / Rolle  [owners Tabelle]
B – Business      Prozess, Kritikalität (1–5), SLA   [business_processes]
A – Application   Fachliche Anwendung (Webshop, CRM) [applications] ← KEINE Pakete!
S – System        OS+Version, Middleware, key Software [sbom_entries, os_*]
H – Hardware      Asset, Rack, Serial/MAC/UUID         [assets]
I – Infrastructure Netzwerk, Exposure, Ports, VLANs    [ip_networks, gateways]
```

**Wichtig:** A-Layer = fachliche Apps (nginx ist S-Layer, nicht A-Layer!)

---

## Identity Resolver & Source-Merging

**Matching-Priorität:**
1. `internal_uuid` – 1.0
2. Stable Keys: `mac_address`, `serial_number`, `chassis_id` – 0.95
3. 2+ Soft Keys: `hostname`, `ip_address`, `fqdn` – 0.80
4. 1 Soft Key → CONFLICT Queue – 0.40–0.50

**Merge-Strategie** (`src/core/identity.py`):
- `SOURCE_PRIORITY`: osquery(80) > mikrotik(70) > nmap(50) > arp(30)
- Felder werden nur überschrieben wenn neue Quelle höhere Priorität hat
- `open_ports`: Union aus allen Quellen (addiert, nie überschrieben)
- `tags`: immer additiv
- `min_confidence` pro Asset: Matches darunter werden ignoriert (auch für CONFLICT)

**Conflict Queue** (`src/api/conflicts.py`):
- CONFLICT-Ergebnis → `conflict_queue` Tabelle
- Operator-Entscheidung: merge / create / discard
- Sidebar-Badge zeigt offene Konflikte

---

## Auth & Zugriffskontrolle

- **JWT-Login** (8h, via OpenRouter-kompatible Tokens)
- **2FA (TOTP)**: optional pro Account aktivierbar (Google Authenticator/Aegis/
  1Password/Authy-kompatibel), inkl. 10 Backup-Codes; zweistufiger Login
  (`/auth/login` → `mfa_required` → `/auth/2fa/verify`); Self-Service unter
  „Einstellungen" (`/auth/2fa/setup|enable|disable`)
- **API-Keys** (`sk-na-...`, bcrypt-gehasht, nur einmal sichtbar)
- **Rollen**: `admin` (alles), `user` (eingeschränkt auf allowed_tags)
- **Tag-basierter Zugriff**: User sieht nur Assets mit seinen Tags
- **API-Key Tags**: können feiner eingeschränkt werden als User-Tags

---

## Netzwerk & Topologie

- **IP-Netzwerke**: CIDR-Definition → automatische Asset-Zuordnung
- **network_zones**: Asset kann in mehreren Zonen sein (Router/Firewalls)
- **Gateways**: Router/Firewalls als Übergänge zwischen Segmenten
- **Topologie-Diagramm**: SVG, primäre Gateways gold hervorgehoben

---

## Collectors

| Collector | Plattform | Protokoll |
|---|---|---|
| `netasset_collector.py` | Linux/Windows/macOS | osquery |
| `mikrotik_collector.py` | MikroTik Router/Switch | REST API (7.1+) / SNMP |
| `fritzbox_collector.py` | AVM Fritz!Box | TR-064 (fritzconnection) |
| `network_discovery_agent.py` | Netzwerk | nmap |
| `lynis_collector.py` | Linux | Lynis lynis-report.dat |
| `eset_collector.py` | ESET PROTECT Cloud (verwaltete Endpoints) | ESET Connect API (OAuth2) |

**Config-Hierarchie** (alle Collector): CLI-Flag > Env-Variable > Config-Datei > Auto-detect

---

## Security Reports (`/api/v1/reporting/`)

| Report | Inhalt |
|---|---|
| `security-posture` | Gesamtübersicht, kritische Assets, CVE-Counts |
| `network-exposure` | Extern erreichbare Assets + Internet-Ports |
| `sbom-vulnerabilities` | Verwundbare Pakete aus SBOM+CVE-Mapping |
| `process-risk` | CVE-Risiko pro Business-Prozess |

LLM-Summary: `POST /reporting/{type}/summary` — optional, non-blocking, max 200 Tokens.

---

## Asset-Features

- **`last_seen_at`**: Wird bei jedem Collector-Report aktualisiert
- **`min_confidence`**: 0.0–1.0, Matches darunter werden ignoriert
- **`network_id`**: Automatisch per CIDR-Matching gesetzt
- **`network_zones`**: Liste von Netzwerknamen (kein CIDR!)
- **Snapshots**: Täglich, max. 30 pro Asset, Diff-Ansicht im Frontend
- **Reports**: Lynis-Upload, parsed + strukturiert, Hardening-Score

---

## API-Endpunkte (Übersicht)

### Core
- `GET/POST/PUT/DELETE /api/v1/assets`
- `GET/POST /api/v1/sbom/assets/{id}/sbom`
- `GET /api/v1/sbom/search`
- `POST /api/v1/discovery/ingest`

### Security
- `GET /api/v1/cve/{id}/impact`
- `POST /api/v1/cve/query` (RAG)
- `GET /api/v1/reporting/{type}` + `POST .../summary`

### OBASHI
- `GET /api/v1/processes/{id}/obashi`
- `GET/POST/DELETE /api/v1/owners`
- `GET/POST/DELETE /api/v1/applications`
- `GET/POST/DELETE /api/v1/gateways` + `GET .../topology`

### Netzwerk
- `GET/POST/DELETE /api/v1/networks`
- `POST /api/v1/networks/reclassify`
- `GET /api/v1/networks/{id}/assets`

### Auth
- `POST /auth/login`
- `GET/POST/DELETE /auth/users`
- `GET/POST/DELETE /auth/apikeys`

### History & Reports
- `GET/POST /api/v1/snapshots/assets/{id}`
- `POST /api/v1/snapshots/run`
- `POST /api/v1/reports/assets/{id}` (Lynis Upload)
- `GET /api/v1/conflicts` + `POST .../merge|create|discard`

---

## Deployment (Podman + Caddy)

```bash
# Server-Setup (einmalig)
bash scripts/server_setup.sh

# Deployen / Aktualisieren
bash scripts/deploy.sh deploy   # git pull + Build + Restart + Migration

# Tägliche Snapshots (Cron 02:00)
python scripts/daily_snapshots.py

# CVE-Import
python scripts/import_cves.py --days 7
```

---

## Umgebungsvariablen (.env.prod)

```env
DATABASE_URL=postgresql+asyncpg://netasset:PASS@localhost:5432/netasset
OPENROUTER_API_KEY=sk-or-v1-...
LLM_MODEL=anthropic/claude-sonnet-4-5
NVD_API_KEY=                    # Optional, erhöht Rate-Limit
EMBEDDING_MODEL=all-MiniLM-L6-v2
JWT_SECRET=                     # 32+ zufällige Zeichen
INITIAL_ADMIN_PASSWORD=         # Wird beim ersten Start gesetzt
DOMAIN=ocs.kiste.org
LOG_LEVEL=INFO
```

---

## Konventionen

- Python 3.12, `from __future__ import annotations` in allen Dateien
- Async überall (FastAPI + asyncpg), `datetime.utcnow()` für DB-Felder
- Pydantic v2 für alle Schemas, `from_attributes=True` für ORM-Objekte
- Lazy Imports für sentence-transformers und openai (Performance)
- Fehler: HTTPException mit klaren Messages, immer geloggt
- Frontend: TanStack Query für alle API-Calls, optimistic updates
