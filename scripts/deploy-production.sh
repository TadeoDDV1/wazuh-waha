#!/usr/bin/env bash
# Despliegue/actualización de wazuh-waha en producción.
# Uso: sudo bash scripts/deploy-production.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecutar con sudo/root." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
APP_USER="${APP_USER:-wazuh-waha}"

ok()   { echo "  [OK]   $*"; }
info() { echo "  [INFO] $*"; }
warn() { echo "  [WARN] $*"; }
fail() { echo "  [FAIL] $*" >&2; exit 1; }

echo "=== Despliegue de wazuh-waha ==="
[ -f "$APP_DIR/.env" ] || fail "No existe $APP_DIR/.env. Ejecutar install-production.sh"
id -u "$APP_USER" >/dev/null 2>&1 || fail "No existe el usuario $APP_USER"

info "Backup previo..."
if [ -x "$APP_DIR/scripts/backup.sh" ]; then
  APP_DIR="$APP_DIR" bash "$APP_DIR/scripts/backup.sh" >/dev/null 2>&1 || warn "Backup previo falló (continuando)"
else
  warn "backup.sh no encontrado"
fi

info "Sincronizando variables de entorno..."
bash "$APP_DIR/scripts/sync_relay_env.sh" apply >/dev/null
chown root:"$(id -gn "$APP_USER")" /etc/wazuh-waha/relay.env
chmod 640 /etc/wazuh-waha/relay.env
ok "relay.env actualizado"

info "Actualizando dependencias Python..."
"$APP_DIR/relay/.venv/bin/pip" install -e "$APP_DIR/relay" -q
ok "Dependencias Python listas"

info "Construyendo y levantando contenedores..."
(cd "$APP_DIR" && docker compose -f deploy/production/docker-compose.prod.yml up -d --build --remove-orphans)
ok "WAHA y dashboard arriba"

info "Reiniciando relay y watchdog..."
systemctl daemon-reload
systemctl enable wazuh-waha.service wazuh-waha-watchdog.timer >/dev/null 2>&1 || true
systemctl restart wazuh-waha.service
systemctl start wazuh-waha-watchdog.timer >/dev/null 2>&1 || true
if command -v caddy >/dev/null 2>&1; then
  caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 && systemctl reload caddy >/dev/null 2>&1 || warn "Caddy no recargó; revisar /etc/caddy/Caddyfile"
fi
ok "Servicios reiniciados"

info "Ejecutando healthcheck..."
if APP_DIR="$APP_DIR" bash "$APP_DIR/scripts/healthcheck.sh"; then
  echo
  ok "Despliegue completado correctamente"
else
  echo
  warn "Healthcheck con fallos. Logs del relay:"
  journalctl -u wazuh-waha -n 30 --no-pager -q | sed 's/^/    /' || true
  echo
  echo "Rollback disponible con: sudo bash $APP_DIR/scripts/rollback.sh"
  exit 1
fi
