#!/usr/bin/env bash
# Rollback de configuración/estado al backup más reciente.
# Uso: sudo bash scripts/rollback.sh [backup_dir]
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/wazuh-waha}"

BACKUP_DIR="${1:-}"
if [ -z "$BACKUP_DIR" ]; then
  BACKUP_DIR="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -1 || true)"
fi
[ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ] || {
  echo "No hay backups en $BACKUP_ROOT"
  exit 1
}

echo "=== Rollback de wazuh-waha ==="
echo "Backup seleccionado: $BACKUP_DIR"
echo "Últimos commits del proyecto:"
git -C "$APP_DIR" log --oneline -5 2>/dev/null | sed 's/^/  /' || true
echo
echo "Se restaurarán .env, relay.env, Caddyfile y unit systemd."
echo "Para restaurar también Wazuh: bash scripts/restore.sh $BACKUP_DIR --with-wazuh"
APP_DIR="$APP_DIR" bash "$APP_DIR/scripts/restore.sh" "$BACKUP_DIR"
