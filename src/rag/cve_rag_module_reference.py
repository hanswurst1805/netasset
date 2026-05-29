"""
CVE RAG Module – NetAsset CMDB
================================
Retrieval Augmented Generation für CVE-Impact-Analyse.

Stack:
  - PostgreSQL + pgvector  (Vektor-Suche)
  - sentence-transformers  (lokale Embeddings, kein API-Key nötig)
  - NVD JSON 2.0 Feed      (CVE-Quelle, kostenlos)
  - Claude API             (Impact-Bewertung)

Setup:
  pip install psycopg2-binary pgvector sentence-transformers httpx anthropic

PostgreSQL:
  CREATE EXTENSION IF NOT EXISTS vector;
"""

import json
import httpx
import asyncio
import anthropic
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from sentence_transformers import SentenceTransformer

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "netasset",
    "user": "netasset",
    "password": "changeme",
}

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"   # lokal, kein API-Key, 384 Dimensionen
VECTOR_DIM = 384
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"

# ---------------------------------------------------------------------------
# Datenbankschema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
-- pgvector Extension
CREATE EXTENSION IF NOT EXISTS vector;

-- CVE-Tabelle mit Embedding
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    cvss_score      FLOAT,
    cvss_vector     TEXT,
    attack_vector   TEXT,   -- NETWORK, ADJACENT, LOCAL, PHYSICAL
    severity        TEXT,   -- CRITICAL, HIGH, MEDIUM, LOW
    affected_pkgs   JSONB,  -- [{"pkg": "openssl", "min": "3.0.0", "max": "3.1.4"}]
    published_at    TIMESTAMP,
    modified_at     TIMESTAMP,
    embedding       vector(384),
    raw             JSONB   -- Original NVD-JSON gecacht
);

CREATE INDEX IF NOT EXISTS idx_cve_severity    ON cve_entries(severity);
CREATE INDEX IF NOT EXISTS idx_cve_published   ON cve_entries(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_embedding   ON cve_entries
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Asset-Tabelle (vereinfacht – wird im Haupt-Schema erweitert)
CREATE TABLE IF NOT EXISTS assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname        TEXT NOT NULL,
    ip_address      TEXT,
    os_name         TEXT,
    os_version      TEXT,
    exposure_level  TEXT DEFAULT 'INTERN',  -- INTERN, DMZ, EXTERN
    open_ports      JSONB DEFAULT '[]',     -- [{"port": 22, "proto": "tcp", "from": ["internet"]}]
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMP DEFAULT NOW()
);

-- SBOM – Software-Komponenten pro Asset
CREATE TABLE IF NOT EXISTS sbom_entries (
    id          SERIAL PRIMARY KEY,
    asset_id    UUID REFERENCES assets(id) ON DELETE CASCADE,
    pkg_name    TEXT NOT NULL,
    pkg_version TEXT NOT NULL,
    pkg_type    TEXT,   -- library, application, os-package
    cpe         TEXT,   -- cpe:2.3:a:openssl:openssl:3.1.2:*
    source      TEXT,   -- dpkg, pip, npm, manual
    scanned_at  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sbom_asset   ON sbom_entries(asset_id);
CREATE INDEX IF NOT EXISTS idx_sbom_pkg     ON sbom_entries(pkg_name, pkg_version);

-- Business-Prozesse
CREATE TABLE IF NOT EXISTS business_processes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    owner_name      TEXT,
    owner_team      TEXT,
    criticality     INT CHECK (criticality BETWEEN 1 AND 5),
    description     TEXT
);

-- Verknüpfung: Prozess → Asset
CREATE TABLE IF NOT EXISTS process_assets (
    process_id  UUID REFERENCES business_processes(id) ON DELETE CASCADE,
    asset_id    UUID REFERENCES assets(id) ON DELETE CASCADE,
    role        TEXT,   -- primary, secondary, dependency
    PRIMARY KEY (process_id, asset_id)
);

-- CVE-Impact-Cache (berechnet, wird regelmäßig neu erstellt)
CREATE TABLE IF NOT EXISTS cve_impact (
    id              SERIAL PRIMARY KEY,
    cve_id          TEXT REFERENCES cve_entries(cve_id),
    asset_id        UUID REFERENCES assets(id),
    risk_level      TEXT,       -- HIGH, MEDIUM, LOW
    risk_score      FLOAT,
    reasoning       TEXT,       -- LLM-Begründung
    affected_pkg    TEXT,
    affected_ver    TEXT,
    computed_at     TIMESTAMP DEFAULT NOW(),
    UNIQUE (cve_id, asset_id)
);
"""

# ---------------------------------------------------------------------------
# Datenbankverbindung
# ---------------------------------------------------------------------------

def get_db():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

def init_schema():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
    print("✓ Schema initialisiert")

# ---------------------------------------------------------------------------
# Embedding-Model (lokal, einmal laden)
# ---------------------------------------------------------------------------

_embedder: Optional[SentenceTransformer] = None

def get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        print(f"Lade Embedding-Model '{EMBEDDING_MODEL}'...")
        _embedder = SentenceTransformer(EMBEDDING_MODEL)
    return _embedder

def embed(text: str) -> list[float]:
    return get_embedder().encode(text, normalize_embeddings=True).tolist()

# ---------------------------------------------------------------------------
# CVE-Text für Embedding aufbereiten
# ---------------------------------------------------------------------------

def cve_to_text(cve_id: str, description: str, affected_pkgs: list, cvss: float, attack_vector: str) -> str:
    """Erzeugt einen einheitlichen Text-Repräsentation einer CVE für das Embedding."""
    pkgs_text = ", ".join(f"{p['pkg']} {p.get('min','?')}–{p.get('max','?')}" for p in affected_pkgs)
    return (
        f"{cve_id}: {description} "
        f"Betroffene Pakete: {pkgs_text}. "
        f"CVSS: {cvss}. Angriffsvektor: {attack_vector}."
    )

# ---------------------------------------------------------------------------
# NVD-Feed Importer
# ---------------------------------------------------------------------------

@dataclass
class NVDImporter:
    days_back: int = 7

    async def fetch_recent(self) -> list[dict]:
        """Holt CVEs der letzten N Tage von NVD."""
        end = datetime.utcnow()
        start = end - timedelta(days=self.days_back)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate":   end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 2000,
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(NVD_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
        return data.get("vulnerabilities", [])

    def parse_cve(self, item: dict) -> Optional[dict]:
        """Normalisiert einen NVD-Eintrag."""
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Beschreibung (englisch bevorzugt)
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        if not desc:
            return None

        # CVSS v3
        metrics = cve.get("metrics", {})
        cvss_data = {}
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                break

        cvss_score   = cvss_data.get("baseScore", 0.0)
        cvss_vector  = cvss_data.get("vectorString", "")
        attack_vec   = cvss_data.get("attackVector", "UNKNOWN")
        severity     = cvss_data.get("baseSeverity", "UNKNOWN")

        # Betroffene Konfigurationen → Paketnamen extrahieren (vereinfacht)
        affected_pkgs = self._extract_affected(cve)

        published = cve.get("published", "")
        modified  = cve.get("lastModified", "")

        return {
            "cve_id":        cve_id,
            "description":   desc,
            "cvss_score":    cvss_score,
            "cvss_vector":   cvss_vector,
            "attack_vector": attack_vec,
            "severity":      severity,
            "affected_pkgs": affected_pkgs,
            "published_at":  published[:19] if published else None,
            "modified_at":   modified[:19]  if modified  else None,
            "raw":           cve,
        }

    def _extract_affected(self, cve: dict) -> list[dict]:
        """Extrahiert Paket-Namen und Versionen aus CPE-Konfigurationen."""
        results = []
        configs = cve.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    cpe = cpe_match.get("criteria", "")
                    # cpe:2.3:a:openssl:openssl:3.1.2:*:*:*:*:*:*:*
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        pkg = parts[4]   # Produkt-Name
                        results.append({
                            "pkg":      pkg,
                            "cpe":      cpe,
                            "min":      cpe_match.get("versionStartIncluding", ""),
                            "max":      cpe_match.get("versionEndIncluding", "") or
                                        cpe_match.get("versionEndExcluding", ""),
                        })
        return results

    async def import_to_db(self):
        """Holt CVEs und schreibt sie mit Embeddings in die DB."""
        print(f"Hole CVEs der letzten {self.days_back} Tage von NVD...")
        items = await self.fetch_recent()
        print(f"  → {len(items)} CVEs gefunden")

        parsed = [self.parse_cve(i) for i in items]
        parsed = [p for p in parsed if p]

        with get_db() as conn:
            with conn.cursor() as cur:
                for cve in parsed:
                    # Embedding erzeugen
                    text = cve_to_text(
                        cve["cve_id"], cve["description"],
                        cve["affected_pkgs"], cve["cvss_score"], cve["attack_vector"]
                    )
                    embedding = embed(text)

                    cur.execute("""
                        INSERT INTO cve_entries
                            (cve_id, description, cvss_score, cvss_vector,
                             attack_vector, severity, affected_pkgs,
                             published_at, modified_at, embedding, raw)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            description   = EXCLUDED.description,
                            cvss_score    = EXCLUDED.cvss_score,
                            severity      = EXCLUDED.severity,
                            affected_pkgs = EXCLUDED.affected_pkgs,
                            modified_at   = EXCLUDED.modified_at,
                            embedding     = EXCLUDED.embedding,
                            raw           = EXCLUDED.raw
                    """, (
                        cve["cve_id"], cve["description"], cve["cvss_score"],
                        cve["cvss_vector"], cve["attack_vector"], cve["severity"],
                        json.dumps(cve["affected_pkgs"]),
                        cve["published_at"], cve["modified_at"],
                        embedding, json.dumps(cve["raw"])
                    ))
            conn.commit()
        print(f"✓ {len(parsed)} CVEs importiert/aktualisiert")

# ---------------------------------------------------------------------------
# RAG – Vektorsuche
# ---------------------------------------------------------------------------

def search_cves(query: str, top_k: int = 10, min_cvss: float = 0.0) -> list[dict]:
    """
    Semantische CVE-Suche per pgvector.
    query: Freitext, z.B. "openssl TLS remote code execution"
    """
    q_embedding = embed(query)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id, description, cvss_score, severity,
                       attack_vector, affected_pkgs,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM cve_entries
                WHERE cvss_score >= %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """, (q_embedding, min_cvss, q_embedding, top_k))
            return [dict(r) for r in cur.fetchall()]

# ---------------------------------------------------------------------------
# SBOM-Abfrage – welche Assets haben ein bestimmtes Paket?
# ---------------------------------------------------------------------------

def get_sbom_context(pkg_names: list[str]) -> list[dict]:
    """Gibt alle Assets zurück, die eines der genannten Pakete installiert haben."""
    if not pkg_names:
        return []
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    a.id, a.hostname, a.ip_address,
                    a.os_name, a.os_version,
                    a.exposure_level, a.open_ports,
                    s.pkg_name, s.pkg_version, s.cpe,
                    COALESCE(
                        array_agg(DISTINCT bp.name) FILTER (WHERE bp.name IS NOT NULL),
                        '{}'
                    ) AS business_processes,
                    COALESCE(
                        MAX(bp.criticality), 0
                    ) AS max_criticality
                FROM assets a
                JOIN sbom_entries s ON s.asset_id = a.id
                LEFT JOIN process_assets pa ON pa.asset_id = a.id
                LEFT JOIN business_processes bp ON bp.id = pa.process_id
                WHERE s.pkg_name = ANY(%s)
                GROUP BY a.id, a.hostname, a.ip_address, a.os_name, a.os_version,
                         a.exposure_level, a.open_ports, s.pkg_name, s.pkg_version, s.cpe
                ORDER BY a.exposure_level DESC, max_criticality DESC
            """, (pkg_names,))
            return [dict(r) for r in cur.fetchall()]

# ---------------------------------------------------------------------------
# Risk Scoring (ohne LLM – deterministisch)
# ---------------------------------------------------------------------------

def calculate_risk(cvss: float, exposure: str, attack_vector: str,
                   open_ports: list, cve_port_relevant: bool, criticality: int) -> tuple[str, float]:
    exposure_factor = {"EXTERN": 1.0, "DMZ": 0.6, "INTERN": 0.3}.get(exposure, 0.3)
    port_factor     = 1.0 if (attack_vector == "NETWORK" and cve_port_relevant) else 0.5
    biz_factor      = 0.5 + 0.5 * (criticality / 5.0)
    score = cvss * exposure_factor * port_factor * biz_factor
    level = "HIGH" if score > 7 else "MEDIUM" if score > 4 else "LOW"
    return level, round(score, 2)

# ---------------------------------------------------------------------------
# LLM Impact-Analyse (Claude)
# ---------------------------------------------------------------------------

def analyze_impact_with_llm(cve: dict, affected_assets: list[dict]) -> str:
    """
    Ruft Claude auf, um den Impact zu bewerten und eine Handlungsempfehlung zu geben.
    Gibt strukturierten Text zurück.
    """
    client = anthropic.Anthropic()

    assets_summary = "\n".join([
        f"- {a['hostname']} ({a['ip_address']}): "
        f"OS={a['os_name']} {a['os_version']}, "
        f"Exposure={a['exposure_level']}, "
        f"Paket={a['pkg_name']} {a['pkg_version']}, "
        f"Prozesse={', '.join(a['business_processes']) or 'keine'}, "
        f"Kritikalität={a['max_criticality']}"
        for a in affected_assets[:20]  # max 20 Assets ans LLM
    ])

    prompt = f"""Du bist ein IT-Security-Analyst. Bewerte den Impact folgender CVE auf die betroffenen Systeme.

CVE: {cve['cve_id']}
Beschreibung: {cve['description']}
CVSS Score: {cve['cvss_score']} ({cve['severity']})
Angriffsvektor: {cve['attack_vector']}

Betroffene Systeme:
{assets_summary}

Antworte auf Deutsch. Gib aus:
1. Eine kurze Zusammenfassung des Risikos (2-3 Sätze)
2. Welche Systeme am dringendsten gepatcht werden müssen (nach Priorität)
3. Eine konkrete Handlungsempfehlung

Sei präzise und praxisorientiert."""

    message = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

# ---------------------------------------------------------------------------
# Haupt-Query: CVE → Impact-Report
# ---------------------------------------------------------------------------

@dataclass
class ImpactReport:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    affected_assets: list[dict]
    llm_analysis: str
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

def get_cve_impact(cve_id: str, use_llm: bool = True) -> Optional[ImpactReport]:
    """
    Vollständiger Impact-Report für eine CVE-ID.
    Kombiniert: CVE-Daten + SBOM-Match + Exposure + Business-Prozesse + LLM
    """
    # 1. CVE aus DB holen
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM cve_entries WHERE cve_id = %s", (cve_id,))
            cve = cur.fetchone()

    if not cve:
        print(f"CVE {cve_id} nicht in lokaler DB – versuche NVD...")
        # Hier könnte man live von NVD holen
        return None

    cve = dict(cve)

    # 2. Betroffene Paketnamen aus CVE extrahieren
    affected_pkgs = cve.get("affected_pkgs") or []
    if isinstance(affected_pkgs, str):
        affected_pkgs = json.loads(affected_pkgs)
    pkg_names = list({p["pkg"] for p in affected_pkgs if p.get("pkg")})

    # Zusätzlich: semantische Suche nach ähnlichen Paketen
    similar_cves = search_cves(cve["description"], top_k=5, min_cvss=0)
    for sc in similar_cves:
        extra_pkgs = sc.get("affected_pkgs") or []
        if isinstance(extra_pkgs, str):
            extra_pkgs = json.loads(extra_pkgs)
        pkg_names += [p["pkg"] for p in extra_pkgs if p.get("pkg")]
    pkg_names = list(set(pkg_names))

    # 3. SBOM-Match: Welche Assets haben diese Pakete?
    assets = get_sbom_context(pkg_names)

    # 4. Risk Score pro Asset berechnen
    for asset in assets:
        open_ports = asset.get("open_ports") or []
        if isinstance(open_ports, str):
            open_ports = json.loads(open_ports)
        level, score = calculate_risk(
            cvss           = cve["cvss_score"] or 0,
            exposure       = asset["exposure_level"],
            attack_vector  = cve["attack_vector"] or "UNKNOWN",
            open_ports     = open_ports,
            cve_port_relevant = True,  # vereinfacht; könnte Port-Matching enthalten
            criticality    = asset["max_criticality"] or 0,
        )
        asset["risk_level"] = level
        asset["risk_score"] = score

    # Nach Risiko sortieren
    assets.sort(key=lambda a: a["risk_score"], reverse=True)

    # 5. LLM-Analyse
    llm_text = ""
    if use_llm and assets:
        llm_text = analyze_impact_with_llm(cve, assets)

    return ImpactReport(
        cve_id          = cve_id,
        description     = cve["description"],
        cvss_score      = cve["cvss_score"],
        severity        = cve["severity"],
        affected_assets = assets,
        llm_analysis    = llm_text,
    )

# ---------------------------------------------------------------------------
# Freitext-Query (RAG-Modus)
# ---------------------------------------------------------------------------

def query_natural(question: str) -> str:
    """
    Beantwortet eine Freitext-Frage über CVEs und Assets.
    Beispiel: "Welche extern erreichbaren Systeme haben kritische OpenSSL CVEs?"
    """
    # 1. Semantisch relevante CVEs finden
    cves = search_cves(question, top_k=8, min_cvss=4.0)

    # 2. SBOM-Kontext für diese CVEs
    all_pkg_names = []
    for cve in cves:
        pkgs = cve.get("affected_pkgs") or []
        if isinstance(pkgs, str):
            pkgs = json.loads(pkgs)
        all_pkg_names += [p["pkg"] for p in pkgs if p.get("pkg")]

    assets = get_sbom_context(list(set(all_pkg_names)))
    assets = [a for a in assets if a["exposure_level"] in ("EXTERN", "DMZ")]

    # 3. LLM mit vollem Kontext befragen
    client = anthropic.Anthropic()

    cve_summary = "\n".join([
        f"- {c['cve_id']} (CVSS {c['cvss_score']}, {c['severity']}): {c['description'][:120]}..."
        for c in cves
    ])
    asset_summary = "\n".join([
        f"- {a['hostname']} [{a['exposure_level']}]: {a['pkg_name']} {a['pkg_version']}, "
        f"Prozesse: {', '.join(a['business_processes']) or 'keine'}"
        for a in assets[:15]
    ])

    prompt = f"""Frage: {question}

Relevante CVEs in unserer Datenbank:
{cve_summary}

Betroffene Assets (extern/DMZ exponiert):
{asset_summary}

Beantworte die Frage präzise auf Deutsch basierend auf diesen Daten.
Wenn keine passenden Daten vorhanden sind, sage das klar."""

    message = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=800,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

# ---------------------------------------------------------------------------
# CLI – schnelle Tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("""
NetAsset CVE RAG Module
=======================
Verwendung:
  python cve_rag_module.py init                      – Schema anlegen
  python cve_rag_module.py import [days]             – CVEs von NVD importieren
  python cve_rag_module.py impact CVE-2024-XXXX      – Impact-Report
  python cve_rag_module.py search "openssl TLS"      – Semantische Suche
  python cve_rag_module.py ask "Frage in Freitext"   – RAG-Query
        """)
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "init":
        init_schema()

    elif cmd == "import":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
        asyncio.run(NVDImporter(days_back=days).import_to_db())

    elif cmd == "impact":
        cve_id = sys.argv[2]
        report = get_cve_impact(cve_id)
        if report:
            print(f"\n{'='*60}")
            print(f"CVE: {report.cve_id}  |  CVSS: {report.cvss_score}  |  {report.severity}")
            print(f"{'='*60}")
            print(f"\nBeschreibung:\n{report.description}\n")
            print(f"Betroffene Assets ({len(report.affected_assets)}):")
            for a in report.affected_assets:
                print(f"  [{a['risk_level']:6}] {a['hostname']:<20} "
                      f"{a['pkg_name']} {a['pkg_version']:<12} "
                      f"Exposure: {a['exposure_level']}")
            if report.llm_analysis:
                print(f"\nLLM-Analyse:\n{report.llm_analysis}")
        else:
            print(f"CVE {cve_id} nicht gefunden")

    elif cmd == "search":
        query = " ".join(sys.argv[2:])
        results = search_cves(query, top_k=10)
        print(f"\nSemantische Suche: '{query}'\n")
        for r in results:
            print(f"  {r['cve_id']:<20} CVSS:{r['cvss_score']:4.1f}  "
                  f"{r['severity']:<8}  Sim:{r['similarity']:.2f}  "
                  f"{r['description'][:80]}...")

    elif cmd == "ask":
        question = " ".join(sys.argv[2:])
        print(f"\nFrage: {question}\n{'='*60}")
        answer = query_natural(question)
        print(answer)
