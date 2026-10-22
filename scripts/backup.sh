#!/usr/bin/env bash
# Backup de configuración y estado de wazuh-waha.
# Uso: sudo bash scripts/backup.sh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
ENV_FILE="$APP_DIR/.env"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/wazuh-waha}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_ROOT/$STAMP"

getenv() {
  [ -f "$ENV_FILE" ] || return 1
  grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' | sed -E "s/^'(.*)'$/\1/"
}

mkdir -p "$DEST"
chmod 700 "$DEST"
echo "=== Backup wazuh-waha -> $DEST ==="

copy() {
  local src="$1" dst="$2"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$DEST/$dst")"
    cp -a "$src" "$DEST/$dst" 2>/dev/null || true
    echo "  + $src"
  fi
}

copy "$ENV_FILE" "env/.env"
copy "/etc/wazuh-waha" "etc/wazuh-waha"
copy "/etc/caddy/Caddyfile" "etc/Caddyfile"
copy "/etc/systemd/system/wazuh-waha.service" "systemd/wazuh-waha.service"
copy "/var/ossec/etc/shared/default/agent.conf" "wazuh/agent.conf"
copy "/var/ossec/etc/ossec.conf" "wazuh/ossec.conf"
copy "/var/lib/wazuh-waha/dedup_state.json" "state/dedup_state.json"
copy "/var/lib/wazuh-waha/config_overrides.json" "state/config_overrides.json"
copy "/var/lib/wazuh-waha/audit.jsonl" "state/audit.jsonl"
copy "/var/lib/wazuh-waha/manager_ip_state" "state/manager_ip_state"

# Últimos backups de alertas (JSONL)
if [ -d "$APP_DIR/backups" ]; then
  mkdir -p "$DEST/alerts"
  find "$APP_DIR/backups" -maxdepth 1 -type f -name 'alerts-*.jsonl' -mtime -7 \
    -exec cp -a {} "$DEST/alerts/" \; 2>/dev/null || true
fi

# Volumen de sesión de WAHA (evita reescanear QR al restaurar)
if command -v docker >/dev/null 2>&1; then
  if docker volume inspect wazuh_waha_sessions >/dev/null 2>&1; then
    echo "  + volumen Docker wazuh_waha_sessions"
    docker run --rm \
      -v wazuh_waha_sessions:/data:ro \
      -v "$DEST":/backup \
      alpine:3.20 tar -czf /backup/waha_sessions.tar.gz -C /data . \
      >/dev/null 2>&1 || echo "  [WARN] No se pudo respaldar el volumen WAHA"
  fi
fi

chmod -R go-rwx "$DEST"

# Retención
if [ "$RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +"$RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true
fi

echo "Backup completado: $DEST"
