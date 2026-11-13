#!/usr/bin/env bash
# Restaura un backup generado por scripts/backup.sh.
# Uso: sudo bash scripts/restore.sh /var/backups/wazuh-waha/20260101T000000Z [--with-wazuh] [--with-waha-volume] [--yes]
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecutar con sudo/root." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
APP_OWNER="${APP_OWNER:-$(stat -c '%U' "$APP_DIR" 2>/dev/null || echo root)}"
APP_GROUP="${APP_GROUP:-$(id -gn "$APP_OWNER" 2>/dev/null || echo root)}"
BACKUP_DIR="${1:-}"
[ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ] || { echo "Uso: $0 <backup_dir> [--with-wazuh] [--with-waha-volume] [--yes]"; exit 1; }
shift || true
WITH_WAZUH=0
WITH_VOLUME=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --with-wazuh) WITH_WAZUH=1 ;;
    --with-waha-volume) WITH_VOLUME=1 ;;
    --yes) ASSUME_YES=1 ;;
  esac
done

if [ "$ASSUME_YES" -ne 1 ]; then
  echo "Se restaurará desde: $BACKUP_DIR"
  echo "Destino: $APP_DIR y /etc"
  read -r -p "¿Continuar? [y/N] " ans
  [[ "$ans" =~ ^[yY]$ ]] || exit 1
fi

echo "=== Restaurando wazuh-waha ==="
systemctl stop wazuh-waha.service 2>/dev/null || true

[ -f "$BACKUP_DIR/env/.env" ] && install -m 600 -o "$APP_OWNER" -g "$APP_GROUP" "$BACKUP_DIR/env/.env" "$APP_DIR/.env" && echo "  .env restaurado"
if [ -d "$BACKUP_DIR/etc/wazuh-waha" ]; then
  cp -a "$BACKUP_DIR/etc/wazuh-waha/." /etc/wazuh-waha/
  chmod 640 /etc/wazuh-waha/relay.env 2>/dev/null || true
  echo "  /etc/wazuh-waha restaurado"
fi
[ -f "$BACKUP_DIR/etc/Caddyfile" ] && cp -a "$BACKUP_DIR/etc/Caddyfile" /etc/caddy/Caddyfile && echo "  Caddyfile restaurado"
if [ -d "$BACKUP_DIR/systemd" ]; then
  find "$BACKUP_DIR/systemd" -maxdepth 1 -type f -exec cp -a {} /etc/systemd/system/ \; 2>/dev/null || true
  if [ -d "$BACKUP_DIR/systemd/dropins" ]; then
    install -d -m 0755 /etc/systemd/system/wazuh-waha.service.d
    cp -a "$BACKUP_DIR/systemd/dropins/." /etc/systemd/system/wazuh-waha.service.d/ 2>/dev/null || true
  fi
  [ -f "$BACKUP_DIR/systemd/sudoers-wazuh-waha" ] && install -m 440 -o root -g root "$BACKUP_DIR/systemd/sudoers-wazuh-waha" /etc/sudoers.d/wazuh-waha
  systemctl daemon-reload
  echo "  units systemd restauradas"
fi
[ -d "$BACKUP_DIR/state" ] && cp -a "$BACKUP_DIR/state/." /var/lib/wazuh-waha/ 2>/dev/null || true

if [ -d "$BACKUP_DIR/project" ]; then
  [ -f "$BACKUP_DIR/project/docker-compose.yml" ] && cp -a "$BACKUP_DIR/project/docker-compose.yml" "$APP_DIR/docker-compose.yml" && echo "  docker-compose.yml restaurado"
  [ -f "$BACKUP_DIR/project/docker-compose.prod.yml" ] && cp -a "$BACKUP_DIR/project/docker-compose.prod.yml" "$APP_DIR/deploy/production/docker-compose.prod.yml" && echo "  docker-compose.prod.yml restaurado"
fi

if [ "$WITH_WAZUH" -eq 1 ]; then
  [ -f "$BACKUP_DIR/wazuh/agent.conf" ] && install -m 640 -o root -g wazuh "$BACKUP_DIR/wazuh/agent.conf" /var/ossec/etc/shared/default/agent.conf 2>/dev/null && echo "  agent.conf restaurado"
  [ -f "$BACKUP_DIR/wazuh/ossec.conf" ] && install -m 640 -o root -g wazuh "$BACKUP_DIR/wazuh/ossec.conf" /var/ossec/etc/ossec.conf 2>/dev/null && echo "  ossec.conf restaurado"
  [ -f "$BACKUP_DIR/wazuh/wsl-relay.conf" ] && install -m 640 -o root -g wazuh "$BACKUP_DIR/wazuh/wsl-relay.conf" /var/ossec/etc/wsl-relay.conf 2>/dev/null && echo "  wsl-relay.conf restaurado"
  [ -f "$BACKUP_DIR/wazuh/integrations/whatsapp_alert.py" ] && install -m 750 -o root -g wazuh "$BACKUP_DIR/wazuh/integrations/whatsapp_alert.py" /var/ossec/integrations/custom/whatsapp_alert.py 2>/dev/null && echo "  integracion whatsapp restaurada"
fi

if [ "$WITH_VOLUME" -eq 1 ] && [ -f "$BACKUP_DIR/waha_sessions.tar.gz" ]; then
  docker run --rm \
    -v wazuh_waha_sessions:/data \
    -v "$BACKUP_DIR":/backup:ro \
    alpine:3.20 sh -c 'cd /data && tar -xzf /backup/waha_sessions.tar.gz' \
    && echo "  volumen WAHA restaurado"
fi

bash "$APP_DIR/scripts/sync_relay_env.sh" apply >/dev/null || true
systemctl start wazuh-waha.service 2>/dev/null || true
systemctl reload caddy 2>/dev/null || true
echo "Restauración completada. Ejecutar: bash $APP_DIR/scripts/healthcheck.sh"
