#!/bin/bash
# Arregla el relay wazuh-waha si está zombie (puerto abierto pero no responde HTTP).
# NO hace nada si está respondiendo bien.
#
# Requiere sudo para el restart. Si el sandbox bloquea sudo, correr
# manualmente en una terminal con TTY:
#   sudo systemctl restart wazuh-waha

set +e
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }

RELAY_HOST="${RELAY_HOST:-http://127.0.0.1:8765}"

echo "=== Test actual del relay ==="
HTTP_CODE=$(curl -sS -m 3 -o /tmp/wazuh-waha_health.json -w "%{http_code}" "$RELAY_HOST/health" 2>/dev/null)
echo "HTTP code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  ok "relay responde 200 OK, no hay que tocar nada"
  cat /tmp/wazuh-waha_health.json
  echo
  exit 0
fi

warn "relay NO responde 200 (code=$HTTP_CODE). Reiniciando..."
echo
echo "=== Estado antes ==="
systemctl status wazuh-waha --no-pager 2>&1 | head -10
echo
echo "=== Ultimos 30 logs ==="
journalctl -u wazuh-waha -n 30 --no-pager 2>&1
echo
echo "=== Restart ==="
sudo systemctl restart wazuh-waha
sleep 3
echo
echo "=== Estado despues ==="
systemctl status wazuh-waha --no-pager 2>&1 | head -10
echo
echo "=== Re-test ==="
HTTP_CODE=$(curl -sS -m 3 -o /tmp/wazuh-waha_health.json -w "%{http_code}" "$RELAY_HOST/health" 2>/dev/null)
echo "HTTP code: $HTTP_CODE"
cat /tmp/wazuh-waha_health.json
echo
if [ "$HTTP_CODE" = "200" ]; then
  ok "relay RESPONDE OK despues del restart"
else
  fail "sigue sin responder. Logs recientes:"
  journalctl -u wazuh-waha -n 50 --no-pager 2>&1
fi
