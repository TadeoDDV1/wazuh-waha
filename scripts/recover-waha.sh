#!/bin/bash
# recover-waha.sh - Recupera una sesion WAHA pegada en STARTING/STOPPED.
# Secuencia validada: STOP -> wait -> START -> poll hasta WORKING.
# NO destruye la sesion persistida (no usa docker compose down -v).
#
# Lee WAHA_API_KEY y WAHA_HOST del .env del proyecto.

set +e
GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/Desktop/wazuh-waha}"
ENV_FILE="$PROJECT_ROOT/.env"
WAHA_HOST="${WAHA_HOST:-http://localhost:3000}"
SESSION="${WAHA_SESSION:-default}"

if [ -f "$ENV_FILE" ]; then
  set -a; source "$ENV_FILE"; set +a
fi

if [ -z "$WAHA_API_KEY" ]; then
  fail "WAHA_API_KEY no esta en $ENV_FILE"
  exit 1
fi

echo "WAHA_HOST=$WAHA_HOST SESSION=$SESSION key_len=${#WAHA_API_KEY}"

# 1. Stop limpio
echo "=== 1. Stop ==="
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST "$WAHA_HOST/api/sessions/$SESSION/stop" 2>&1
echo

# Espera 5 segundos (secreto del fix: dejar a WAHA matar el Chromium anterior)
sleep 5

# 2. Confirmar STOPPED
echo "=== 2. Check STOPPED ==="
STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
  "$WAHA_HOST/api/sessions/$SESSION" | jq -r .status 2>/dev/null)
echo "  status: $STATUS"
if [ "$STATUS" != "STOPPED" ]; then
  warn "estado actual: $STATUS (esperado STOPPED). Esperando 5s mas..."
  sleep 5
  STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$SESSION" | jq -r .status 2>/dev/null)
  echo "  status: $STATUS"
fi

# 3. Start
echo "=== 3. Start ==="
curl -sS -m 10 -H "X-Api-Key: $WAHA_API_KEY" \
  -X POST "$WAHA_HOST/api/sessions/$SESSION/start" 2>&1
echo

# 4. Poll hasta WORKING (max 60s)
echo "=== 4. Poll hasta WORKING (max 60s) ==="
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  sleep 5
  STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$SESSION" | jq -r .status 2>/dev/null)
  echo "  intento $i (${i}*5s): $STATUS"
  [ "$STATUS" = "WORKING" ] && break
done

if [ "$STATUS" = "WORKING" ]; then
  ok "Sesion WORKING. Resumen:"
  curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$SESSION" | jq '{status, presence, me}'
else
  fail "Sesion no llego a WORKING en 60s. Probar:"
  echo "  docker logs wazuh-waha --tail 30"
  echo "  Si persiste: docker compose down -v (BORRA la sesion, hay que re-escanear QR)"
fi
