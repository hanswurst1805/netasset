#!/usr/bin/env bash
# Manuelles Deployment mit reinem Podman (kein compose).
#
# Einmaliger Erststart:  bash scripts/deploy.sh start
# Update deployen:       bash scripts/deploy.sh deploy
# Status anzeigen:       bash scripts/deploy.sh status
# Alles stoppen:         bash scripts/deploy.sh stop
#
# Voraussetzung: /opt/netasset/.env.prod ist befüllt.
set -euo pipefail

INSTALL_DIR="/opt/netasset"
ENV_FILE="$INSTALL_DIR/.env.prod"
POD_NAME="netasset"
API_IMAGE="localhost/netasset-api:latest"

# .env.prod laden
if [ ! -f "$ENV_FILE" ]; then
    echo "FEHLER: $ENV_FILE nicht gefunden. Bitte .env.prod.example kopieren und ausfüllen."
    exit 1
fi
set -a; source "$ENV_FILE"; set +a

# ---------------------------------------------------------------------------
cmd_start() {
    echo "==> [0/5] Image bauen..."
    podman build -t "$API_IMAGE" "$INSTALL_DIR"

    echo "==> Pod anlegen..."
    podman pod create \
        --name "$POD_NAME" \
        --publish 80:80 \
        --publish 443:443 \
        --publish 443:443/udp \
        2>/dev/null || echo "    (Pod existiert bereits)"

    echo "==> Volumes anlegen..."
    podman volume create netasset-pgdata   2>/dev/null || true
    podman volume create netasset-caddy-data   2>/dev/null || true
    podman volume create netasset-caddy-config 2>/dev/null || true

    echo "==> Datenbank starten..."
    podman run -d \
        --replace \
        --pod "$POD_NAME" \
        --name netasset-db \
        --restart unless-stopped \
        -e POSTGRES_DB=netasset \
        -e POSTGRES_USER=netasset \
        -e "POSTGRES_PASSWORD=${DB_PASSWORD}" \
        -v netasset-pgdata:/var/lib/postgresql/data \
        --health-cmd "pg_isready -U netasset" \
        --health-interval 10s \
        --health-retries 5 \
        docker.io/pgvector/pgvector:pg16

    echo "==> Warte auf Datenbank..."
    for i in $(seq 1 30); do
        podman exec netasset-db pg_isready -U netasset &>/dev/null && break
        sleep 2
    done

    _start_api

    echo "==> Caddy starten..."
    podman run -d \
        --replace \
        --pod "$POD_NAME" \
        --name netasset-caddy \
        --restart unless-stopped \
        -v "$INSTALL_DIR/Caddyfile:/etc/caddy/Caddyfile:ro" \
        -v netasset-caddy-data:/data \
        -v netasset-caddy-config:/config \
        docker.io/caddy:2-alpine

    echo ""
    echo "==> Migrationen..."
    podman run --rm \
        --pod "$POD_NAME" \
        --env-file "$ENV_FILE" \
        -e DATABASE_URL="postgresql+asyncpg://netasset:${DB_PASSWORD}@localhost:5432/netasset" \
        "$API_IMAGE" \
        alembic upgrade head

    echo ""
    echo "✓ Gestartet."
    cmd_status
}

_start_api() {
    echo "==> API starten..."
    podman run -d \
        --replace \
        --pod "$POD_NAME" \
        --name netasset-api \
        --restart unless-stopped \
        --env-file "$ENV_FILE" \
        -e DATABASE_URL="postgresql+asyncpg://netasset:${DB_PASSWORD}@localhost:5432/netasset" \
        "$API_IMAGE"
}

cmd_deploy() {
    cd "$INSTALL_DIR"

    echo "==> [1/4] Git pull..."
    git pull

    echo "==> [2/4] Image bauen..."
    podman build -t "$API_IMAGE" .

    echo "==> [3/4] API neu starten..."
    podman stop netasset-api 2>/dev/null || true
    podman rm   netasset-api 2>/dev/null || true
    _start_api

    echo "==> [4/4] Migrationen..."
    podman run --rm \
        --pod "$POD_NAME" \
        --env-file "$ENV_FILE" \
        -e DATABASE_URL="postgresql+asyncpg://netasset:${DB_PASSWORD}@localhost:5432/netasset" \
        "$API_IMAGE" \
        alembic upgrade head

    # Alte Images aufräumen
    podman image prune -f

    echo ""
    echo "✓ Deploy abgeschlossen."
    cmd_status
}

cmd_stop() {
    echo "==> Stoppe alle Container..."
    podman pod stop "$POD_NAME"
    echo "✓ Gestoppt."
}

cmd_status() {
    echo ""
    echo "Container:"
    podman pod ps --filter name="$POD_NAME" 2>/dev/null || true
    podman ps --filter pod="$POD_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

# ---------------------------------------------------------------------------
case "${1:-}" in
    start)  cmd_start  ;;
    deploy) cmd_deploy ;;
    stop)   cmd_stop   ;;
    status) cmd_status ;;
    *)
        echo "Verwendung: $0 {start|deploy|stop|status}"
        echo ""
        echo "  start   Erststart: Pod, Volumes, alle Container + Migrationen"
        echo "  deploy  Update: git pull, Image bauen, API neu starten"
        echo "  stop    Alle Container stoppen"
        echo "  status  Status anzeigen"
        exit 1
        ;;
esac
