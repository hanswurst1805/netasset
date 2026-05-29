# NetAsset – Initialer Claude Code Prompt

Kopiere diesen Prompt in Claude Code wenn du das Projekt zum ersten Mal öffnest.
Claude Code liest CLAUDE.md automatisch – dieser Prompt gibt den Startauftrag.

---

## Prompt (in Claude Code eingeben)

```
Lies CLAUDE.md vollständig. Das ist unser Projekt-Kontext.

Ich möchte mit Phase 1 beginnen: Datenbankschema + FastAPI-Grundgerüst.

Bitte:

1. Erstelle src/core/database.py mit async SQLAlchemy Session-Setup
   (AsyncSession, get_session Dependency für FastAPI)

2. Erstelle die Alembic-Konfiguration (alembic.ini + migrations/env.py)
   sodass alle Modelle aus src/models/all_models.py migriert werden,
   inklusive pgvector Extension

3. Erstelle die fehlenden API-Router als Stubs:
   - src/api/assets.py   (CRUD: list, get, create, update + /discover endpoint)
   - src/api/sbom.py     (list SBOM per asset, bulk-upsert)
   - src/api/processes.py (CRUD + /assets und /cve-risk endpoints)
   - src/api/discovery.py (POST /ingest mit Identity Resolver)

4. Erstelle src/rag/embedder.py (SentenceTransformer Wrapper, lazy loading)
   und src/rag/vector_search.py (pgvector Suche gegen cve_entries)

5. Schreibe tests/test_identity.py mit pytest-Tests für:
   - Match via MAC-Adresse
   - Match via 2 Soft Keys
   - Conflict bei mehrdeutigem Soft-Key-Match
   - NEW bei keinem Match

Nutze durchgehend async/await, Pydantic v2 Schemas, und type hints.
Alle Schemas als separate Pydantic-Klassen (nicht inline).
```

---

## Nächste Prompts (nach Phase 1)

**Phase 2 – NVD Import:**
```
Implementiere src/ingest/nvd_importer.py vollständig.
NVD JSON 2.0 API, async httpx, Embeddings via src/rag/embedder.py,
bulk-insert in cve_entries mit pgvector.
Schreibe auch scripts/import_cves.py als CLI mit --days Parameter.
```

**Phase 3 – CVE Impact:**
```
Implementiere src/rag/cve_impact.py:
- get_cve_impact(cve_id, session, use_llm=True) → ImpactReport
- SBOM-Match via pkg_name + Versionsbereich
- Risk Score Formel aus CLAUDE.md
- Claude API Call für LLM-Analyse (strukturierter Prompt auf Deutsch)
Verbinde es mit dem bestehenden GET /api/v1/cve/{cve_id}/impact Router.
```

**Phase 4 – Business Prozesse:**
```
Implementiere den vollständigen processes.py Router:
- GET /processes/{id}/assets → alle Assets über process_assets JOIN
- GET /processes/{id}/cve-risk → CVE-Risiko aggregiert über alle Assets des Prozesses
  (höchster Risk Score gewinnt, Liste der betroffenen CVEs)
Nutze die bestehenden Modelle aus all_models.py.
```
