#!/usr/bin/env bash
# Einmaliges Server-Setup auf dem VPS.
# Voraussetzung: Ubuntu 22.04/24.04 oder Debian, Podman ist bereits installiert.
#
# Ausführen als normaler User (nicht root), der sudo-Rechte hat:
#   bash scripts/server_setup.sh
set -euo pipefail

INSTALL_DIR="/opt/netasset"
SERVICE_USER="${SUDO_USER:-$USER}"

echo "==> NetAsset Server Setup"
echo "    Install-Dir : $INSTALL_DIR"
echo "    User        : $SERVICE_USER"
echo ""

# 1. podman-compose installieren (falls noch nicht vorhanden)
if ! command -v podman-compose &>/dev/null && ! podman compose version &>/dev/null 2>&1; then
    echo "==> Installiere podman-compose..."
    sudo apt-get install -y podman-compose || pip3 install podman-compose
fi

# 2. Deployment-Verzeichnis anlegen
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# 3. Benötigte Dateien kopieren (lokal ausführen: rsync zum Server statt cp)
cp docker-compose.prod.yml "$INSTALL_DIR/"
cp Caddyfile "$INSTALL_DIR/"

# 4. .env.prod anlegen wenn noch nicht vorhanden
if [ ! -f "$INSTALL_DIR/.env.prod" ]; then
    cp .env.prod.example "$INSTALL_DIR/.env.prod"
    echo ""
    echo "  WICHTIG: $INSTALL_DIR/.env.prod bearbeiten!"
    echo "  Mindestens: DOMAIN, DB_PASSWORD, ANTHROPIC_API_KEY, GITHUB_REPO"
    echo ""
fi

# 5. Rootless Podman: Ports 80/443 erlauben
# (nur nötig wenn < 1024 als unprivileged user)
if [ "$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null)" != "80" ]; then
    echo "==> Erlaube unprivileged ports ab 80..."
    echo "net.ipv4.ip_unprivileged_port_start=80" | sudo tee /etc/sysctl.d/99-podman-ports.conf
    sudo sysctl -p /etc/sysctl.d/99-podman-ports.conf
fi

# 6. systemd Lingering aktivieren (Container laufen nach Logout weiter)
sudo loginctl enable-linger "$SERVICE_USER"

# 7. Systemd-User-Service für automatischen Start
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/netasset.service << 'EOF'
[Unit]
Description=NetAsset CMDB
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/netasset
EnvironmentFile=/opt/netasset/.env.prod
ExecStart=/usr/bin/podman compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/podman compose -f docker-compose.prod.yml down
TimeoutStartSec=300

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable netasset.service

echo ""
echo "==> Setup abgeschlossen!"
echo ""
echo "Nächste Schritte:"
echo "  1. $INSTALL_DIR/.env.prod ausfüllen"
echo "  2. DNS: A-Record DOMAIN → $(curl -s ifconfig.me 2>/dev/null || echo 'VPS-IP')"
echo "  3. Erststart: cd $INSTALL_DIR && podman compose -f docker-compose.prod.yml up -d"
echo "  4. Migrationen: podman compose -f docker-compose.prod.yml run --rm api alembic upgrade head"
echo "  5. Demo-Daten: podman compose -f docker-compose.prod.yml run --rm api python scripts/seed_demo_data.py"
