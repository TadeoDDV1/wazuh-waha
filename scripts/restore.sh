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

[ -f "$BACKUP_DIR/env/.env" ] && install -m 600 -o root -g "$(id -gn wazuh-waha 2>/dev/null || echo root)" "$BACKUP_DIR/env/.env" "$APP_DIR/.env" && echo "  .env restaurado"
if [ -d "$BACKUP_DIR/etc/wazuh-waha" ]; then
  cp -a "$BACKUP_DIR/etc/wazuh-waha/." /etc/wazuh-waha/
  chmod 640 /etc/wazuh-waha/relay.env 2>/dev/null || true
  echo "  /etc/wazuh-waha restaurado"
fi
[ -f "$BACKUP_DIR/etc/Caddyfile" ] && cp -a "$BACKUP_DIR/etc/Caddyfile" /etc/caddy/Caddyfile && echo "  Caddyfile restaurado"
[ -f "$BACKUP_DIR/systemd/wazuh-waha.service" ] && cp -a "$BACKUP_DIR/systemd/wazuh-waha.service" /etc/systemd/system/wazuh-waha.service && systemctl daemon-reload && echo "  unit systemd restaurada"
[ -d "$BACKUP_DIR/state" ] && cp -a "$BACKUP_DIR/state/." /var/lib/wazuh-waha/ 2>/dev/null || true

if [ "$WITH_WAZUH" -eq 1 ]; then
  [ -f "$BACKUP_DIR/wazuh/agent.conf" ] && install -m 640 -o root -g wazuh "$BACKUP_DIR/wazuh/agent.conf" /var/ossec/etc/shared/default/agent.conf 2>/dev/null && echo "  agent.conf restaurado"
  [ -f "$BACKUP_DIR/wazuh/ossec.conf" ] && install -m 640 -o root -g wazuh "$BACKUP_DIR/wazuh/ossec.conf" /var/ossec/etc/ossec.conf 2>/dev/null && echo "  ossec.conf restaurado"
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
