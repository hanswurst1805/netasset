# Docker/Podman-Integration → Menü „Container"

Wie Container-Informationen (Docker **und** Podman) in DRUCKER gelangen und im
Menüpunkt **Container** sowie am Host (Asset-Detail → „Dienste") sichtbar werden.

## Was die Integration leistet

- Erfasst **alle lauschenden Dienste** eines Hosts – auch `127.0.0.1`/`::1`
  (z. B. Container hinter einem Reverse-Proxy).
- Bestimmt je Listener die **Erreichbarkeit** (`bind_scope`): `localhost`,
  `lan`, `all` (0.0.0.0/::).
- Ordnet jedem Port den **Prozess** und – aufgelöst – das **SBOM-Paket** zu.
- Erkennt **Docker- und Podman-Container** und hängt **Name + Image** an den
  passenden Host-Port.

Damit entsteht die Brücke vom I-Layer (Port) zum C/S-Layer (Software/Paket):
`Port → Dienst (Prozess) → SBOM-Paket` bzw. `Port → Container-Image`.

## Datenfluss

```
Collector (osquery + docker/podman CLI)
   → services[]  ──POST /api/v1/discovery/ingest──▶  services-Tabelle
                                                      (je Quelle ersetzt)
                                                          │
                          GET /api/v1/assets/{id}/services│  GET /api/v1/services
                                                          ▼
                         Asset-Detail „Dienste"      Menü „Container" (alle Hosts)
```

## 1. Erfassung im Collector

`netasset_collector.py` (osquery-basiert):

- **Listener**: `listening_ports` ⋈ `processes` – ohne localhost-Filter, mit
  `address` (Bind) und `path` (Prozesspfad).
- **Container**: per CLI – erst `docker ps`, sonst `podman ps`
  (`{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}`). Aus dem Ports-Feld wird der
  **Host-Port** geparst und an den Dienst gemappt. Bewusst CLI statt osquery
  `docker_*`-Tabellen, da letztere **nur Docker** abdecken.

Voraussetzungen auf dem Host:
- `screen`/osquery wie beim regulären Collector,
- `docker` **oder** `podman` im `PATH`,
- ausreichende Rechte auf den Engine-Socket. **Rootful**: Collector als root
  sieht alle Container. **Rootless Podman**: nur Container des Users, unter dem
  der Collector läuft (ggf. Collector als diesen User ausführen).
- Ist keine Engine erreichbar, bleibt der Dienst trotzdem als Port + Prozess
  erfasst – nur ohne Container-Bezug (best effort).

## 2. Speicherung (services-Tabelle, Migration 0023)

Pro Listener eine Zeile: `asset_id, port, proto, bind_address, bind_scope,
process_name, process_path, sbom_pkg, container_name, container_image, source`.
Beim Ingest werden die Dienste **je Quelle ersetzt** (`source`, z. B. `osquery`),
und `process_name`/`path`/`container_image` werden gegen die SBOM des Assets auf
ein Paket aufgelöst (Alias-Tabelle wie `dockerd/docker-proxy → docker`,
`sshd → openssh-server`, …; siehe `src/core/services.py`).

## 3. Anzeige

- **Menü „Container"** (`/containers`, API `GET /api/v1/services`): Dienste über
  alle Hosts. Standardmäßig nur container-gebunden (Toggle „nur Container" für
  alle Dienste). Spalten: Host (Link → Asset), Port, Erreichbarkeit, Prozess,
  SBOM-Paket, Container-Image. Tag-gefiltert nach Benutzerrechten.
- **Asset-Detail → „Dienste"** (`GET /api/v1/assets/{id}/services`): dieselben
  Daten je Host, inkl. localhost-Binds.

## Grenzen / Hinweise

- Die Container-Auflösung mappt über den **Host-Port**; Container ganz ohne
  veröffentlichte Ports (nur internes Netz) erscheinen nicht als Listener.
- `sbom_pkg` bleibt leer, wenn kein passendes Paket in der SBOM gefunden wird
  (z. B. Software nur im Container-Image, nicht im Host-SBOM) – das Image dient
  dann als fachlicher Bezug.
- Für die Zuordnung zu Fachanwendungen siehe die Komponenten-Schicht
  (BASIS / `application_components`).
