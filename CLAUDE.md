# NetAsset – CMDB & Security Intelligence Platform

## Projektübersicht

NetAsset ist eine CMDB (Configuration Management Database) mit integrierter
Security-Intelligence. Das System sammelt Informationen über IT-Assets aus
verschiedenen Quellen und ermöglicht CVE-Impact-Analysen über RAG (Retrieval
Augmented Generation).

### Kernfunktionen
- Asset-Verwaltung (Server, Switches, Router, Firewalls, Clients)
- SBOM (Software Bill of Materials) pro Asset
- CVE-Impact-Analyse via RAG + pgvector
- OBASHI-orientierte Business-Prozess-Sicht (O-B-A-S-H-I Schichten)
- Exposure-Modell (INTERN / DMZ / EXTERN) mit Port-Mapping
- Discovery-API für automatische Asset-Erkennung
- Stabile Geräte-Identifikation via UUID + Fingerprinting

---

## Tech Stack

| Komponente     | Technologie                        |
|----------------|------------------------------------|
| Backend API    | FastAPI (Python 3.12)              |
| Datenbank      | PostgreSQL 16 + pgvector Extension |
| Embeddings     | sentence-transformers (lokal)      |
| LLM            | Anthropic Claude API               |
| CVE-Quelle     | NVD JSON 2.0 Feed (nvd.nist.gov)   |
| Migrations     | Alembic                            |
| Tests          | pytest + pytest-asyncio            |
| Linting        | ruff + mypy                        |
| Container      | Docker + docker-compose            |

---

## Projektstruktur

```
netasset/
├── CLAUDE.md                    ← Diese Datei
├── docker-compose.yml           ← PostgreSQL + App
├── pyproject.toml               ← Dependencies + Tools
├── alembic.ini
├── migrations/                  ← Alembic-Migrationen
├── src/
│   ├── api/                     ← FastAPI Router
│   │   ├── assets.py            ← Asset CRUD
│   │   ├── sbom.py              ← SBOM Endpunkte
│   │   ├── cve.py               ← CVE-Impact Endpunkte
│   │   ├── processes.py         ← Business-Prozesse
│   │   └── discovery.py         ← Discovery-Ingest
│   ├── core/
│   │   ├── config.py            ← Settings (pydantic-settings)
│   │   ├── database.py          ← DB-Session, Engine
│   │   └── identity.py          ← Identity Resolver (UUID-Matching)
│   ├── models/
│   │   ├── asset.py             ← SQLAlchemy Asset-Modell
│   │   ├── sbom.py              ← SBOM-Einträge
│   │   ├── cve.py               ← CVE-Entries + Embeddings
│   │   ├── process.py           ← Business-Prozesse (OBASHI)
│   │   └── exposure.py          ← Exposure-Modell
│   ├── ingest/
│   │   ├── nvd_importer.py      ← NVD Feed → DB
│   │   ├── discovery_adapter.py ← Generischer Discovery-Adapter
│   │   └── normalizer.py        ← Daten-Normalisierung
│   └── rag/
│       ├── embedder.py          ← Embedding-Model Wrapper
│       ├── vector_search.py     ← pgvector Queries
│       ├── cve_impact.py        ← Impact-Berechnung
│       └── query_engine.py      ← Freitext-RAG-Query
├── tests/
│   ├── test_identity.py
│   ├── test_cve_impact.py
│   └── test_api.py
└── scripts/
    ├── import_cves.py           ← Cronjob: NVD-Import
    └── seed_demo_data.py        ← Demo-Assets + SBOM
```

---

## Datenmodell – Schichten (OBASHI)

```
O – Owners        Person / Team / Abteilung / Rolle
B – Business      Prozess, Service, Kritikalität (1–5), SLA
A – Application   App/Service, SBOM-Einträge, CVE-Mapping, Ports
S – System        OS+Version, Pakete, Portscan-Ergebnisse
H – Hardware      Asset, Rack-Position, Serial/MAC/UUID, Interfaces
I – Infrastructure Netzwerk-Topologie, Firewall-Policies, VLAN, NAT, Exposure
```

Jede Schicht hat Relations nach oben und unten → Traversal-Queries möglich.

---

## Geräte-Identifikation (Identity Resolver)

**Priorität beim Matching:**
1. `internal_uuid` – unveränderlich, einmal vergeben
2. Stable Keys: `mac_address`, `serial_number`, `chassis_id` (LLDP)
3. Soft Keys: `hostname`, `ip_address`, `fqdn`

**Merge-Logik** (`src/core/identity.py`):
- Match auf Stable Key → automatisch mergen
- Match auf ≥2 Soft Keys → flaggen zur Bestätigung (Conflict Queue)
- Kein Match → neues Asset anlegen

---

## Exposure-Modell

Drei Stufen, bewusst einfach gehalten:
- `INTERN` – nur internes Netz erreichbar
- `DMZ` – aus bestimmten Zonen / Partner-Netzen
- `EXTERN` – aus Internet erreichbar (0.0.0.0/0)

Plus: `open_ports` JSONB pro Asset:
```json
[{"port": 22, "proto": "tcp", "reachable_from": ["internet"]}]
```

---

## CVE-RAG-Flow

```
NVD Feed (täglich) → Embedding → pgvector
                                      ↓
Neue CVE bekannt → SBOM-Match → Exposure-Check → Risk Score → Claude API → Report
                                                                    ↑
                              Business-Prozess-Kontext ────────────┘
```

**Risk Score Formel:**
```python
score = cvss * exposure_factor * port_factor * (0.5 + 0.5 * criticality/5)
# HIGH > 7.0 | MEDIUM > 4.0 | LOW sonst
```

---

## API-Endpunkte (Übersicht)

### Assets
- `GET  /api/v1/assets`                  – Liste mit Filter
- `POST /api/v1/assets`                  – Neu anlegen
- `GET  /api/v1/assets/{id}`             – Detail
- `PUT  /api/v1/assets/{id}`             – Update
- `POST /api/v1/assets/discover`         – Discovery-Ingest (bulk)

### CVE & Security
- `GET  /api/v1/cve/{cve_id}/impact`     – Impact-Report
- `GET  /api/v1/cve/search?q=...`        – Semantische Suche
- `POST /api/v1/cve/query`               – Freitext-RAG-Query
- `GET  /api/v1/assets/{id}/cve-exposure`– Alle CVEs für ein Asset

### Business-Prozesse
- `GET  /api/v1/processes`               – Liste
- `POST /api/v1/processes`               – Neu
- `GET  /api/v1/processes/{id}/assets`   – Alle Assets eines Prozesses
- `GET  /api/v1/processes/{id}/cve-risk` – CVE-Risiko für Prozess

### SBOM
- `GET  /api/v1/assets/{id}/sbom`        – SBOM eines Assets
- `POST /api/v1/assets/{id}/sbom`        – SBOM-Einträge hinzufügen
- `GET  /api/v1/sbom/search?pkg=openssl&version_min=3.0&version_max=3.2`

---

## Konventionen

- Python 3.12, type hints überall, keine `Any` ohne Kommentar
- Async wo möglich (FastAPI + asyncpg)
- Pydantic v2 für alle Schemas
- Alle DB-Queries in Repository-Klassen, kein Raw-SQL in Routers
- Fehler: HTTPException mit klaren Messages, nie 500 ohne Logging
- Umgebungsvariablen via `.env` + `pydantic-settings`
- Tests: Jede neue Funktion bekommt mindestens einen Unit-Test

## Wichtige Befehle

```bash
# Entwicklung starten
docker-compose up -d          # PostgreSQL starten
uvicorn src.main:app --reload # API starten

# Datenbank
alembic upgrade head          # Migrationen anwenden
alembic revision --autogenerate -m "beschreibung"

# CVE-Import
python scripts/import_cves.py --days 7

# Tests
pytest tests/ -v

# Demo-Daten
python scripts/seed_demo_data.py
```

---

## Umgebungsvariablen (.env)

```env
DATABASE_URL=postgresql+asyncpg://netasset:changeme@localhost:5432/netasset
ANTHROPIC_API_KEY=sk-ant-...
NVD_API_KEY=                  # Optional, erhöht Rate-Limit
EMBEDDING_MODEL=all-MiniLM-L6-v2
LOG_LEVEL=INFO
```

---

## Aktuelle Prioritäten (Stand: Projektstart)

1. [ ] DB-Schema + Migrationen (alle 6 OBASHI-Schichten)
2. [ ] Identity Resolver mit Merge-Logik
3. [ ] FastAPI Grundgerüst + Asset-CRUD
4. [ ] NVD-Importer + pgvector-Embeddings
5. [ ] CVE-Impact-Endpunkt (SBOM + Exposure + LLM)
6. [ ] Business-Prozess-Verknüpfung
7. [ ] Discovery-Adapter (generisch)
8. [ ] Web-UI (separates Frontend-Projekt)
