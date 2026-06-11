# DRUCKER – Benutzer- und Betriebshandbuch

> DRUCKER (Projektname intern: NetAsset) ist eine CMDB (Configuration Management
> Database) mit integrierter Security-Intelligence. Das System sammelt
> Informationen über IT-Assets aus verschiedenen Quellen (Collectors), führt
> CVE-Impact-Analysen durch und bietet eine Web-Oberfläche für Betrieb,
> Inventarisierung und Sicherheitsauswertung.

Dieses Dokument richtet sich an zwei Zielgruppen:

- **Teil A – Benutzerhandbuch**: Anwender:innen, die mit der Web-GUI arbeiten
  (Asset-Verwaltung, Security-Reports, OBASHI/Business-Prozesse, Chatbot).
- **Teil B – Betriebshandbuch**: Administrator:innen, die den Server
  betreiben, deployen und warten (Podman, Caddy, Datenbank, Cron-Jobs,
  Collectors).

---

# Teil A – Benutzerhandbuch

## A.1 Anmeldung (Login)

Die Startseite ist die Login-Seite. Nach erfolgreicher Anmeldung mit
Benutzername und Passwort wird man auf `/assets` weitergeleitet.

- Felder: **Benutzername**, **Passwort**
- Button **„Anmelden"** (deaktiviert solange ein Feld leer ist)
- Bei falschen Zugangsdaten: Fehlermeldung „Benutzername oder Passwort
  falsch"

Das Login erzeugt ein JWT-Token, das 8 Stunden gültig ist. Danach ist eine
erneute Anmeldung nötig.

### Zwei-Faktor-Authentifizierung (2FA)

Hat ein Benutzer 2FA aktiviert (siehe [A.12](#a12-einstellungen-settings)),
erscheint nach Benutzername/Passwort ein zweiter Schritt:

- Eingabe des **6-stelligen Codes** aus einer Authenticator-App
  (z.B. Google Authenticator, Aegis, 1Password, Authy)
- Alternativ kann einer der zuvor generierten **Backup-Codes**
  (Format `xxxx-xxxx`) eingegeben werden – jeder Backup-Code ist nur
  **einmal** gültig
- Button **„Zurück zum Login"** bricht den 2FA-Schritt ab und kehrt zur
  Passwort-Eingabe zurück
- Bei falschem Code: Fehlermeldung „Code ungültig"

Erst nach erfolgreicher 2FA-Prüfung wird das JWT-Token ausgestellt.

Es gibt zwei Rollen:

- **admin**: voller Zugriff auf alle Assets, Einstellungen, Benutzer­verwaltung
- **user**: Zugriff nur auf Assets, deren Tags mit den dem Benutzer
  zugewiesenen `allowed_tags` übereinstimmen

---

## A.2 Assets (`/assets`)

Die zentrale Übersichtsseite über alle erfassten Geräte (Server, Switches,
Router, Firewalls, Clients, …).

### Tabs

- **Aktiv**: alle aktiven, nicht archivierten Assets (Standardansicht)
- **Archiv**: archivierte Assets (siehe `is_archived` in der Asset-Detailseite)

### Filter

- Textsuche (Hostname, IP, FQDN)
- Dropdown **Asset-Typ** (server, switch, router, firewall, client, …)
- Dropdown **Exposure-Level** (INTERN / DMZ / EXTERN)
- Toggle **„Aufmerksamkeit erforderlich"** – zeigt nur Assets, die
  - kritische CVEs haben,
  - ausstehende Updates/Reboot melden, oder
  - länger nicht mehr gesehen wurden (`last_seen_at` veraltet)

### Tabelle

Pro Asset: Hostname/IP, Typ, OS, Exposure-Badge, Tags (farblich kodiert),
„Zuletzt gesehen" (relative Zeitangabe, z.B. „vor 3 Stunden").

### Massenlöschung (nur „Aktiv"-Tab)

Im Bulk-Delete-Panel können Assets gefiltert und gemeinsam gelöscht werden:

- nach Tagen seit letzter Sichtung (> 7 / 30 / 90 / 180 / 365 Tage)
- „Nie gesehen" (kein `last_seen_at`)
- nach Tags (Auswahl + freie Eingabe)

Ablauf: Filter setzen → **Vorschau** der betroffenen Assets → **Bestätigen**
→ Löschen.

### Zeilenaktionen

Pro Asset stehen Icons zum **Archivieren** und **Löschen** zur Verfügung.

---

## A.3 Asset-Detail (`/assets/{id}`)

Detailansicht eines einzelnen Assets. Seitentitel = Hostname oder
IP-Adresse.

### Aktionsleiste

- **„CVE-Scan"** – stößt einen OSV-Scan (Open Source Vulnerabilities) für
  dieses Asset an (`POST /api/v1/cve/osv/scan/asset/{id}`). Kostenlos,
  benötigt keinen API-Key. Vergleicht installierte SBOM-Pakete gegen die
  OSV-Datenbank, legt neue CVE-Einträge an und aktualisiert die
  Risikobewertung. Sinnvoll, um nach einem Software-Update oder nach Ändern
  von Einstellungen wie „Als VM/VPS werten" eine sofortige Neubewertung zu
  erzwingen.
- **„Bearbeiten"** – öffnet das Edit-Modal (siehe unten)
- **„Löschen"** – löscht das Asset endgültig (mit Bestätigungsdialog)

### Edit-Modal („Asset bearbeiten")

| Feld | Beschreibung |
|---|---|
| Hostname, IP-Adresse, FQDN, MAC-Adresse | Basis-Identifikationsdaten |
| Weitere IP-Adressen | Tag-Liste, z.B. WAN-IP, Management-IP |
| OS Name, OS Version, Standort, Asset-Typ | Inventardaten |
| **Exposure Level** | INTERN / DMZ / EXTERN – steuert Risiko-Gewichtung der CVEs |
| **Netzwerk-Zonen** | Tag-Liste, z.B. INTERN, DMZ, Heimnetz, Office-LAN (kein CIDR, nur Bezeichnung) |
| **Tags** | Beliebige Labels, u.a. für Zugriffskontrolle (`allowed_tags`) |
| **Mindest-Konfidenz** | Slider 0.00–1.00. Steuert, ab welcher Match-Konfidenz automatische Updates aus Discovery-Quellen übernommen werden: 0.00 = alle Matches, 0.80 = mind. 2 weiche Schlüssel (Hostname/IP/FQDN), 0.95 = stabiler Schlüssel (MAC/Seriennummer), 1.00 = nur exakter UUID-Match |
| **„Als VM/VPS werten"** (force_vm) | Erzwingt die VM-Erkennung für dieses Asset, unabhängig von Tags/Hersteller. Wirkung: Microcode-/Firmware-CVEs (z.B. `intel-microcode`, `amd64-microcode`, `linux-firmware`) gelten als nicht exploitierbar und werden – sofern die globale Einstellung „Microcode-Updates für VMs/VPS ausblenden" aktiv ist (siehe [A.10](#a10-einstellungen-settings)) – komplett aus den CVE-Listen entfernt |
| **„Archivieren"** (is_archived) | Asset aus aktiven Listen, Reports und Diagrammen ausblenden, ohne es zu löschen. Wird unter dem Archiv-Tab weiter angezeigt |

### Tabs

1. **Details**
   - Info-Grid: Typ, OS, IP-Adressen, MAC-Adresse
   - Netzwerk-Zonen als farbige Badges (EXTERN rot, DMZ gelb, INTERN blau)
   - **CVE-Scan-Ergebnis**: Anzahl geprüfter Pakete, gefundene
     Schwachstellen, neue CVEs – mit aufklappbaren Paket- und CVE-Listen
   - **CVE-Risiken**: Top-CVEs, getrennt nach „Software/Pakete" (SBOM-Treffer)
     und „Netzwerk/System" (Port-bezogen), inkl. Risk-Level, KEV-Flag und
     betroffenem Paket
   - **Offene Ports**: Tabelle mit Port, Protokoll, „Erreichbar von"
     (internet/intern/…)
   - **SBOM**: aufklappbare, durchsuchbare Paketliste (Paket, Version, Typ,
     Quelle)
2. **Verlauf** – Snapshot-Timeline mit täglichen Änderungen (max. 30 Tage),
   Diff-Ansicht zwischen zwei Zeitpunkten
3. **Reports** – hochgeladene Lynis-/Audit-Reports für dieses Asset
4. **Karteikarte** – Vorschau der Export-„Karteikarte" (siehe
   [A.9 Karteikarten](#a9-karteikarten-cards)) mit Template-Auswahl
   (Vollständig, Security, Inventar, Netzwerk, Minimal) und
   Markdown-Download

---

## A.4 CVE Dashboard (`/cve`)

Zentrale Sicht auf alle bekannten CVEs.

- **Filter-Suche**: CVE-ID oder Stichwort
- **Semantische Suche**: Freitext über RAG/Embeddings (z.B. „openssl buffer
  overflow")
- **Tabs**: „Betroffene Assets" (nur CVEs mit aktivem Treffer) / „Alle CVEs"
- Pro CVE: CVE-ID, Severity-Badge, CVSS-Score, KEV-Kennzeichnung, Anzahl und
  Liste betroffener Hostnamen
- **Impact-Panel** (rechts): nach Auswahl einer CVE werden betroffene Assets
  (Hostname, Exposure, Paket+Version, Risk-Level/Score) sowie eine optionale
  KI-Analyse angezeigt

> Hinweis: Microcode-/Firmware-CVEs auf Assets, die als VM/VPS gelten, werden
> hier – sofern in den Einstellungen aktiviert – nicht mehr aufgeführt, da sie
> vom Hypervisor-Host und nicht vom Gast-System verwaltet werden.

---

## A.5 Reports (`/reporting`)

Vier strukturierte Security-Reports als Tabs, jeweils mit Aktualisieren- und
„KI-Zusammenfassung generieren"-Button (Sparkles-Icon, max. 200 Token,
optional/non-blocking).

### Globale Aktionen (oben rechts)

- **„OSV-Scan"** – scannt alle aktiven Assets mit SBOM gegen OSV
  (`POST /api/v1/cve/osv/scan/all`)
- **„CISA KEV"** – importiert die CISA Known-Exploited-Vulnerabilities-Liste
- **„KEV-Datei"** – manueller Upload des KEV-Katalogs als JSON
  (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Tab 1 – Security Posture

Gesamtübersicht: Anzahl Assets, HIGH/MEDIUM CVEs, „Stale"-Assets
(> 24h nicht gesehen), Verteilung nach Exposure-Level und Asset-Typ,
kritische extern erreichbare Assets mit HIGH-CVEs (klickbar →
Asset-Detail), Top-10-Risiko-Assets.

### Tab 2 – Network Exposure

Anzahl EXTERN-/DMZ-Assets, Internet-erreichbare Ports, häufigste
Internet-Ports, Liste exponierter Assets nach Risiko sortiert (Zone,
Internet-Ports, HIGH-CVEs, Risk-Score).

### Tab 3 – SBOM Vulnerabilities

Anzahl geprüfter Pakete, verwundbare Pakete, kritische Funde; Tabelle der
verwundbaren Pakete mit CVE, CVSS, Schweregrad und betroffenen Assets.

### Tab 4 – Process Risk

CVE-Risiko pro Business-Prozess: Risiko-Badge, Kritikalität (1–5-Balken),
Anzahl betroffener Assets, Verteilung HIGH/MEDIUM/LOW, Top-CVE.

---

## A.6 Netzwerke (`/networks`)

Verwaltung von IP-Netzwerken (CIDR) und deren automatischer
Asset-Zuordnung.

- Statistik: Anzahl definierter Netze, zugeordnete Assets, leere Netze
- **„Netzwerk hinzufügen"**: Name, CIDR, Exposure-Level, Farbe,
  optionaler Gateway-Router, Beschreibung
- Pro Netz: Farbpunkt, Name + CIDR, Gateway (falls gesetzt),
  Exposure-Badge, Asset-Anzahl (aufklappbar → Liste der zugeordneten Assets,
  klickbar zur Detailseite), Bearbeiten-/Löschen-Icons
- **„Reclassify"**: ordnet alle Assets erneut anhand ihrer IP-Adresse den
  passenden CIDR-Netzen zu (`POST /api/v1/networks/reclassify`)

---

## A.7 Netzwerk-Topologie (`/topology`)

Visuelle Darstellung der Netzwerksegmente und ihrer Übergänge
(Router/Firewalls als Gateways).

- **„Auto-Erkennen"**: erkennt automatisch Router/Firewalls, die mehrere
  Netzwerk-Zonen verbinden, und schlägt Gateways vor
- **„Gateway hinzufügen"**: Gerät (Router/Firewall/Switch), Name,
  Von-/Zu-Segment, Option „Primärer Gateway" (wird im Diagramm gold
  hervorgehoben)
- Diagramm: Segmente farbcodiert (EXTERN rot, DMZ gelb, INTERN blau,
  MGMT grün, GUEST lila) mit Verbindungslinien
- Übersicht: Anzahl verbundener Gateways, Anzahl isolierter Segmente
- Gateway-Liste mit Von→Zu-Segment, Name, IP/Hostname,
  Primär-Kennzeichnung (★), Löschen-Button

---

## A.8 Business-Prozesse & OBASHI (`/processes`, `/basis`)

DRUCKER bildet die OBASHI-Schichten ab:

```
O – Owners        Person/Team/Abteilung/Rolle
B – Business      Prozess, Kritikalität (1–5), RTO/RPO
A – Application   Fachliche Anwendung (z.B. Webshop, CRM)
S – System        OS, Middleware, SBOM-Software
H – Hardware      Asset (Server, Switch, …)
I – Infrastructure Netzwerk, Exposure, Ports
```

### Business-Prozesse (`/processes`)

- **„Owner verwalten"**: Owner anlegen (Name, E-Mail, Team, Abteilung,
  Rolle) und löschen
- Pro Prozess (aufklappbar): Name, Owner-Badge, Kritikalitäts-Balken
  (1–5), RTO in Stunden
- **Sub-Tabs je Prozess**:
  - **BASIS** – OBASHI-Diagramm des Prozesses
  - **Anwendungen** – Liste der zugeordneten Applications mit Icon (🌐 web,
    ⚡ api, ⚙ batch, 🔗 integration, 🔧 service, 🖥 desktop, 📱 mobile,
    📦 other), „Neue App"-Button, Löschen pro App
  - **CVE-Risiko** – HIGH/MEDIUM/LOW-Verteilung, Top-CVEs, zugehörige Assets
    mit Exposure-Level
  - Inline Owner-Auswahl per Dropdown

### BASIS-Editor (`/basis`)

Detaillierter, dreispaltiger Editor:

- **Links**: Baum aus Owners (O), Business-Prozessen (B) mit zugeordneten
  Applications (A) – jeweils mit Hinzufügen-/Löschen-Aktionen
- **Mitte**: Editor je nach Auswahl
  - Prozess: Name, Beschreibung, Kritikalität, RTO/RPO, Owner
  - Anwendung: Name, App-Typ, Version, URL, Owner, Kritikalität,
    Verknüpfung mit Assets (Suchfeld + Checkboxen), SBOM-Vorschau des
    verknüpften Assets
  - Owner: Name, Team, Abteilung, Rolle
- **Rechts**: BASIS-Layer-Vorschau der ausgewählten Anwendung – zeigt
  Application (Name/Version), System (OS + Top-5-Pakete aus SBOM),
  Hardware (Hostname, Typ je verknüpftem Asset) und Infrastructure
  (Exposure-Level, Top-Ports/Protokoll)

---

## A.9 Karteikarten (`/cards`)

Batch-Export von Asset-Daten als „Karteikarten" – aufbereitete
Markdown-/JSON-/Text-Dateien, z.B. für RAG-Systeme oder LLM-Training.

- **Template-Auswahl** (Radio-Buttons), z.B. Vollständig, Security-fokussiert,
  Inventar – jedes Template definiert enthaltene Sektionen (Basis-Infos,
  Netzwerk, Ports, SBOM, CVE-Risiken, Business-Kontext, Lynis-Audit,
  Metadaten)
- **Format**: Markdown (für RAG), JSON+JSONL (für LLM-Training), Plaintext
- **Filter** (optional): Asset-Typ, Exposure-Level, Tag
- **„Als ZIP exportieren"**: erzeugt einen Download mit einer Datei pro Asset

Eine Einzelvorschau pro Asset findet sich im Tab „Karteikarte" der
Asset-Detailseite ([A.3](#a3-asset-detail-assetsid)).

---

## A.10 Konflikte (`/conflicts`)

Manuelle Auflösung von Identitäts-Konflikten, die beim automatischen
Daten-Merging aus mehreren Quellen entstehen (z.B. ein neues Discovery-Event
lässt sich nicht eindeutig einem bestehenden Asset zuordnen).

- **Status-Filter**: Offen / Zusammengeführt / Neu angelegt / Verworfen
- Nur Admins: **„Alle löschen"**
- Pro Konflikt (aufklappbar):
  - Header: Hostname/IP/MAC, Quelle, Konfidenz in %, Match-Felder
  - Aufgeklappt: Side-by-side-Vergleich „Eingehende Daten (neu)" vs.
    „Möglicher Kandidat (bestehend)"
  - **Aktionen**:
    - **„Zusammenführen"**: Eingabe der Ziel-Asset-ID
    - **„Als neues Asset anlegen"**
    - **„Verwerfen"**

Ein Badge in der Sidebar zeigt die Anzahl offener Konflikte.

---

## A.11 Chatbot (`/chat`)

RAG-basierter Chat über die echten CMDB-Daten („striktes RAG" – das LLM
antwortet ausschließlich auf Basis der in der Datenbank vorhandenen
Asset- und CVE-Daten, keine Halluzinationen).

- Info-Banner: „Alle Antworten basieren auf echten Asset-Daten deiner CMDB"
- Vorgeschlagene Beispiel-Fragen, u.a.:
  - „Welche Systeme sind von außen erreichbar und haben bekannte
    Schwachstellen?"
  - „Welche Softwareversionen sind auf den Webservern installiert?"
  - „Auf welchen Systemen läuft OpenSSL und in welcher Version?"
- Antworten zeigen Quellenangaben (verwendete Assets, durchsuchte CVEs,
  Größe des Kontexts) zur Nachvollziehbarkeit

---

## A.12 Einstellungen (`/settings`)

### Allgemein (nur Admin)

- **Toggle „Microcode-Updates für VMs/VPS ausblenden"**
  (`hide_vm_microcode_cves`, Standard: aktiv)

  Wenn aktiviert, werden CVEs zu `intel-microcode`, `amd64-microcode`,
  `linux-firmware`, `iucode-tool` sowie Pakete mit dem Präfix `firmware-`
  für Assets, die als VM/VPS erkannt werden, **vollständig aus allen
  CVE-Listen entfernt** (nicht nur herabgestuft) – Begründung: Microcode wird
  vom Hypervisor-Host geladen, nicht vom Gast-Betriebssystem, daher ist die
  CVE auf der Gast-Ebene nicht relevant. Die Filterung wirkt sofort
  (live), ohne dass ein erneuter CVE-Scan nötig ist.

  Ob ein Asset als VM/VPS gilt, wird automatisch anhand von Tags
  (`vm`, `virtual`, `kvm`, `vmware`, `docker`, …) und
  Hersteller-/Modellfeldern erkannt – oder lässt sich pro Asset über den
  Schalter **„Als VM/VPS werten"** im Edit-Modal erzwingen
  (siehe [A.3](#a3-asset-detail-assetsid)).

### Benutzer (nur Admin)

- **„Neuer User"**: Benutzername, Passwort, Rolle (`user`/`admin`),
  erlaubte Tags (leer = Zugriff auf alle Assets)
- Tabelle aller Benutzer: Username (+E-Mail), Rollen-Badge, Tags,
  Löschen-Button

### Zwei-Faktor-Authentifizierung – 2FA (alle Benutzer)

Jeder Benutzer kann für seinen eigenen Account 2FA per TOTP
(Time-based One-Time Password) aktivieren – kompatibel mit gängigen
Authenticator-Apps (Google Authenticator, Aegis, 1Password, Authy, …).

**Aktivieren:**

1. Button **„2FA einrichten"** klicken
2. QR-Code mit der Authenticator-App scannen (alternativ das angezeigte
   Secret manuell in der App eintragen)
3. Den von der App generierten 6-stelligen Code eingeben und mit
   **„Aktivieren"** bestätigen
4. Es werden **10 Backup-Codes** angezeigt (Format `xxxx-xxxx`) – diese
   an einem sicheren Ort aufbewahren! Sie werden nur **einmalig**
   angezeigt und ermöglichen den Login, falls die Authenticator-App
   nicht verfügbar ist (jeder Code ist nur einmal gültig)

Nach der Aktivierung wird beim Login zusätzlich zu Benutzername/Passwort
ein 2FA-Code abgefragt (siehe [A.1](#a1-anmeldung-login)).

**Deaktivieren:**

- Im Bereich „Zwei-Faktor-Authentifizierung" einen aktuellen TOTP-Code
  oder einen Backup-Code eingeben und auf **„2FA deaktivieren"** klicken
- Danach ist beim Login wieder nur Benutzername/Passwort erforderlich

### API-Keys (alle Benutzer)

- Eingabe eines Namens (z.B. `linux-server`) und **„Key erstellen"**
- Der vollständige Schlüssel (`sk-na-...`) wird **nur einmal** angezeigt –
  unbedingt kopieren und in der Collector-Konfiguration
  (`netasset_collector.conf` → `api_key = ...`) hinterlegen
- Tabelle aktiver Keys: Name, Präfix, erlaubte Tags (oder „alle"),
  zuletzt benutzt, Status (aktiv/inaktiv), Löschen-Button

API-Key-Tags können enger gefasst sein als die Tags des erstellenden
Benutzers, um den Zugriff einzelner Collectors granular einzuschränken.

---

# Teil B – Betriebshandbuch

## B.1 Architektur-Überblick

| Komponente     | Technologie                        |
|----------------|-------------------------------------|
| Backend API    | FastAPI (Python 3.12)               |
| Datenbank      | PostgreSQL 16 + pgvector Extension  |
| Embeddings     | sentence-transformers (lokal)       |
| LLM            | OpenRouter API (modell-agnostisch)  |
| CVE-Quelle     | NVD JSON 2.0 Feed + OSV + CISA KEV   |
| Migrationen    | Alembic (async)                     |
| Container      | Podman + Caddy (HTTPS/TLS)          |
| Frontend       | React + Vite + Tailwind CSS         |

Die Container laufen als Podman-Pod (`netasset`) mit drei Diensten:

- **db** – `pgvector/pgvector:pg16`, persistiertes Volume `pgdata`,
  Healthcheck via `pg_isready`
- **api** – das FastAPI-Backend (Image `localhost/netasset-api:latest`),
  startet erst wenn `db` „healthy" ist
- **caddy** – Reverse Proxy mit automatischem HTTPS (Ports 80/443 + 443/udp
  für HTTP/3), Volumes `caddy_data`/`caddy_config`, liest die
  `Caddyfile`

---

## B.2 Server-Setup (Erstinstallation)

```bash
bash scripts/server_setup.sh
```

Richtet die Grundvoraussetzungen auf dem Server ein (Podman, Verzeichnisse
unter `/opt/netasset`, `.env.prod`-Vorlage, etc.).

Anschließend Erststart aller Container, Volumes und initialer Migrationen:

```bash
bash scripts/deploy.sh start
```

`cmd_start` erstellt den Pod, die Volumes, startet `db`/`api`/`caddy` und
führt `alembic upgrade head` aus.

---

## B.3 Deployment & Updates

```bash
bash scripts/deploy.sh {start|deploy|stop|status}
```

| Befehl | Wirkung |
|---|---|
| `start` | Initiales Setup: Pod, Volumes, alle Container, Migrationen |
| `deploy` | Update: `git pull`, Frontend-Build (`npm ci && npm run build`, falls npm verfügbar), `podman build -t localhost/netasset-api:latest .`, API-Container neu starten, `alembic upgrade head` (über temporären Container), `podman image prune -f` |
| `stop` | Stoppt alle Container des Pods |
| `status` | Zeigt Status von Pod und Containern |

Konstanten in `scripts/deploy.sh`:

- `INSTALL_DIR=/opt/netasset`
- `ENV_FILE=$INSTALL_DIR/.env.prod`
- `POD_NAME=netasset`
- `API_IMAGE=localhost/netasset-api:latest`

**Standard-Update-Workflow** auf dem Server:

```bash
cd /opt/netasset
bash scripts/deploy.sh deploy
```

> Wichtig: Neue Datenbankänderungen müssen immer als **neue**
> Alembic-Migration mit eigener Revision-ID angelegt werden (nächste freie
> Nummer in `migrations/versions/`). Eine bereits angewendete
> Migrationsdatei nachträglich zu ändern, bewirkt **keine** erneute
> Ausführung – `alembic upgrade head` führt nur Migrationen aus, deren
> Revision noch nicht in der `alembic_version`-Tabelle vermerkt ist.

---

## B.4 Umgebungsvariablen (`.env.prod`)

Liegt unter `/opt/netasset/.env.prod` und wird von `docker-compose.prod.yml`
in den `api`-Container injiziert:

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

`INITIAL_ADMIN_PASSWORD` wird nur beim allerersten Start verwendet, um den
`admin`-Benutzer anzulegen. Danach sollte das Passwort über die GUI
(„Einstellungen → Benutzer") geändert werden.

---

## B.5 Datenbank & Migrationen

- Alembic-Migrationskette unter `migrations/versions/` (aktuell 0001–0018)
- Manuell ausführen (z.B. zur Fehlersuche):

```bash
podman exec -it netasset-api alembic upgrade head
podman exec -it netasset-api alembic current
podman exec -it netasset-api alembic history
```

- `alembic upgrade head` wird automatisch bei `deploy.sh deploy` und
  `deploy.sh start` ausgeführt.

---

## B.6 Geplante Aufgaben (Cron)

### Tägliche Asset-Snapshots (für die Verlaufs-/Diff-Ansicht)

```bash
python scripts/daily_snapshots.py
```

Empfohlen: Cron-Job um 02:00 Uhr. Erstellt für jedes aktive Asset einen
Snapshot des aktuellen Zustands (max. 30 pro Asset, älteste werden
rotiert).

### CVE-Import (NVD-Feed)

```bash
python scripts/import_cves.py --days 7
```

Importiert neue/aktualisierte CVEs der letzten N Tage aus dem NVD JSON
2.0 Feed inkl. Embeddings für die semantische Suche. Mit `NVD_API_KEY`
deutlich höheres Rate-Limit.

### KEV-Import

Kann manuell über die GUI angestoßen werden („Reports → CISA KEV"), oder per
API (`POST /api/v1/cve/kev/import`). Kein API-Key erforderlich.

### OSV-Scan aller Assets

GUI-Button „Reports → OSV-Scan" bzw. `POST /api/v1/cve/osv/scan/all` –
prüft alle aktiven Assets mit SBOM gegen die OSV-Datenbank. Kann ebenfalls
periodisch per Cron über die API getriggert werden, falls gewünscht.

---

## B.7 Collectors

Separates Repository: `github.com/hanswurst1805/drucker-collectors`.

| Collector | Plattform | Protokoll |
|---|---|---|
| `netasset_collector.py` | Linux/Windows/macOS | osquery |
| `mikrotik_collector.py` | MikroTik Router/Switch | REST API (7.1+) / SNMP |
| `fritzbox_collector.py` | AVM Fritz!Box | TR-064 (fritzconnection) |
| `network_discovery_agent.py` | Netzwerk | nmap |
| `lynis_collector.py` | Linux | Lynis lynis-report.dat |

Installation über `install_linux.sh`, `install_macos.sh` bzw.
`install_windows.ps1`. Konfiguration über `*.conf`-Dateien
(Vorlagen: `*.conf.example`).

**Konfigurations-Hierarchie** (für alle Collectors, in absteigender
Priorität):

1. CLI-Flag
2. Umgebungsvariable
3. Konfigurationsdatei
4. Auto-Detect

Jeder Collector benötigt einen API-Key (`sk-na-...`), der unter
„Einstellungen → API-Keys" erstellt wird (siehe [A.12](#a12-einstellungen-settings)).
Über die API-Key-Tags lässt sich steuern, welche Assets ein Collector sehen
bzw. aktualisieren darf.

---

## B.8 Identity Resolver & Source-Merging (Hintergrund)

Beim Discovery-Ingest (`POST /api/v1/discovery/ingest`) versucht das System,
eingehende Daten einem bestehenden Asset zuzuordnen:

**Matching-Priorität:**

1. `internal_uuid` – Konfidenz 1.0
2. Stabile Schlüssel (`mac_address`, `serial_number`, `chassis_id`) – 0.95
3. 2+ weiche Schlüssel (`hostname`, `ip_address`, `fqdn`) – 0.80
4. 1 weicher Schlüssel → landet in der Conflict Queue – 0.40–0.50

**Merge-Strategie:**

- `SOURCE_PRIORITY`: osquery (80) > mikrotik (70) > nmap (50) > arp (30)
- Felder werden nur überschrieben, wenn die neue Quelle eine höhere Priorität
  hat als die zuletzt setzende Quelle
- `open_ports`: Vereinigung aller Quellen (wird addiert, nie überschrieben)
- `tags`: immer additiv
- `min_confidence` pro Asset (siehe [A.3](#a3-asset-detail-assetsid)):
  Matches mit niedrigerer Konfidenz werden komplett ignoriert (auch für die
  Conflict Queue)

Treffer mit Konfidenz < `min_confidence` und ≥ 0.40 landen in der
**Conflict Queue** (`/conflicts`, siehe [A.10](#a10-konflikte-conflicts))
zur manuellen Entscheidung (zusammenführen / neu anlegen / verwerfen).
