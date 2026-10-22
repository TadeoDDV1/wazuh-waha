#!/usr/bin/env bash
# Healthcheck del stack wazuh-waha.
# Uso: bash scripts/healthcheck.sh
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/.env}"
FAIL=0
WARN=0

getenv() {
  [ -f "$ENV_FILE" ] || return 1
  grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' | sed -E "s/^'(.*)'$/\1/"
}

RELAY_PORT="$(getenv RELAY_PORT || true)"; RELAY_PORT="${RELAY_PORT:-8765}"
DASHBOARD_PORT="$(getenv DASHBOARD_PUBLIC_PORT || true)"; DASHBOARD_PORT="${DASHBOARD_PORT:-8001}"
WAHA_PORT="$(getenv WAHA_PUBLIC_PORT || true)"; WAHA_PORT="${WAHA_PORT:-3001}"
WAHA_API_KEY="$(getenv WAHA_API_KEY || true)"
DOMAIN="$(getenv DOMAIN || true)"

ok()   { echo "  [OK]   $*"; }
warn() { echo "  [WARN] $*"; WARN=$((WARN+1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

echo "=== Healthcheck wazuh-waha ==="

if curl -fsS -m 5 "http://127.0.0.1:${RELAY_PORT}/health" | grep -q '"status":"ok"'; then
  ok "Relay http://127.0.0.1:${RELAY_PORT}/health"
else
  fail "Relay no responde en :${RELAY_PORT}"
fi

if curl -fsS -m 5 "http://127.0.0.1:${DASHBOARD_PORT}/" >/dev/null; then
  ok "Dashboard http://127.0.0.1:${DASHBOARD_PORT}/"
else
  fail "Dashboard no responde en :${DASHBOARD_PORT}"
fi

if [ -n "$WAHA_API_KEY" ] && curl -fsS -m 8 -H "X-Api-Key: $WAHA_API_KEY" \
    "http://127.0.0.1:${WAHA_PORT}/api/server/version" >/dev/null; then
  ok "WAHA http://127.0.0.1:${WAHA_PORT}"
else
  fail "WAHA no responde o API key inválida en :${WAHA_PORT}"
fi

if systemctl is-active --quiet wazuh-waha; then
  ok "systemd wazuh-waha activo"
else
  fail "systemd wazuh-waha inactivo"
fi

MANAGER_HOST="$(getenv WAZUH_MANAGER_HOST || true)"
[ -z "$MANAGER_HOST" ] && MANAGER_HOST="$(getenv WAZUH_SERVER_IP || true)"
API_PORT="$(getenv WAZUH_MANAGER_API_PORT || true)"; API_PORT="${API_PORT:-55000}"
if [ -n "$MANAGER_HOST" ]; then
  if timeout 3 bash -c "exec 3<>/dev/tcp/${MANAGER_HOST}/${API_PORT}" 2>/dev/null; then
    ok "Wazuh API ${MANAGER_HOST}:${API_PORT}"
  else
    warn "Wazuh API ${MANAGER_HOST}:${API_PORT} no responde"
  fi
fi

if [ -n "$DOMAIN" ]; then
  if curl -fsS -m 8 "https://${DOMAIN}/health" | grep -q '"status":"ok"'; then
    ok "HTTPS https://${DOMAIN}/health"
  else
    warn "No responde HTTPS para $DOMAIN (DNS/TLS/firewall)"
  fi
else
  warn "DOMAIN vacío: sin verificación HTTPS"
fi

echo
if [ "$FAIL" -gt 0 ]; then
  echo "Healthcheck con $FAIL fallo(s) y $WARN advertencia(s)."
  exit 1
fi
echo "Healthcheck OK ($WARN advertencia(s))."
