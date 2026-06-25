#!/usr/bin/env bash
# NetAsset – Start/Deploy mit Docker (Compose).
#
# Entspricht scripts/deploy.sh (Podman), aber für Docker:
#   db (pgvector) + api (FastAPI) + caddy (HTTPS/TLS, Reverse-Proxy + SPA)
#
# Aufruf:
#   bash scripts/docker_start.sh up       # Frontend bauen, Image bauen, Migration, Start  (Default)
#   bash scripts/docker_start.sh down     # Stack stoppen
#   bash scripts/docker_start.sh migrate  # nur Alembic-Migration
#   bash scripts/docker_start.sh logs     # Logs folgen
#   bash scripts/docker_start.sh status   # Status
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ENV_FILE=".env.prod"
COMPOSE_FILE="docker-compose.prod.yml"

# docker compose (v2) bevorzugt, sonst docker-compose (v1)
if docker compose version >/dev/null 2>&1; then
    DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    DC=(docker-compose)
else
    echo "FEHLER: weder 'docker compose' noch 'docker-compose' gefunden." >&2
    exit 1
fi
COMPOSE=("${DC[@]}" -f "$COMPOSE_FILE" --env-file "$ENV_FILE")

require_env() {
    if [ ! -f "$ENV_FILE" ]; then
        echo "FEHLER: $ENV_FILE fehlt. Vorlage kopieren und anpassen:" >&2
        echo "  cp .env.prod.example $ENV_FILE && \$EDITOR $ENV_FILE" >&2
        echo "  Mindestens DOMAIN, DB_PASSWORD, JWT_SECRET, INITIAL_ADMIN_PASSWORD setzen." >&2
        exit 1
    fi
}

build_frontend() {
    if command -v npm >/dev/null 2>&1; then
        echo "==> Frontend bauen (npm)…"
        (cd dashboard && npm ci --silent && npm run build)
    elif [ ! -d dashboard/dist ]; then
        echo "WARN: npm fehlt und dashboard/dist nicht vorhanden – Caddy hat kein Frontend zum Ausliefern." >&2
    fi
}

migrate() {
    echo "==> Datenbank-Migration (alembic upgrade head)…"
    "${COMPOSE[@]}" run --rm api alembic upgrade head
}

cmd="${1:-up}"
case "$cmd" in
    up)
        require_env
        build_frontend
        echo "==> Image bauen…"
        "${COMPOSE[@]}" build api
        echo "==> Datenbank starten…"
        "${COMPOSE[@]}" up -d db
        migrate
        echo "==> API + Caddy starten…"
        "${COMPOSE[@]}" up -d
        echo ""
        echo "✓ Gestartet. Erreichbar unter https://\${DOMAIN} (aus $ENV_FILE)."
        "${COMPOSE[@]}" ps
        ;;
    down)
        require_env
        "${COMPOSE[@]}" down
        ;;
    migrate)
        require_env
        migrate
        ;;
    logs)
        require_env
        "${COMPOSE[@]}" logs -f --tail 100
        ;;
    status)
        require_env
        "${COMPOSE[@]}" ps
        ;;
    *)
        echo "Verwendung: $0 {up|down|migrate|logs|status}"
        exit 1
        ;;
esac
