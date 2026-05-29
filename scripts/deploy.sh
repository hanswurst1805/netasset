#!/usr/bin/env bash
# Manuelles Deployment auf dem VPS.
#
# Aufruf lokal:
#   ssh user@vps 'bash /opt/netasset/scripts/deploy.sh'
#
# Oder direkt auf dem VPS:
#   bash /opt/netasset/scripts/deploy.sh
set -euo pipefail

INSTALL_DIR="/opt/netasset"
COMPOSE="podman compose -f $INSTALL_DIR/docker-compose.prod.yml"

cd "$INSTALL_DIR"

echo "==> [1/4] Git pull..."
git pull

echo "==> [2/4] Image bauen..."
$COMPOSE build api

echo "==> [3/4] App neu starten..."
$COMPOSE up -d --no-deps api

echo "==> [4/4] Migrationen..."
$COMPOSE run --rm api alembic upgrade head

echo ""
echo "✓ Deploy abgeschlossen."
$COMPOSE ps
