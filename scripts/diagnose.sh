#!/bin/bash
# Diagnostico read-only de la integracion Wazuh -> WAHA.
# NO modifica nada. Solo lee.
#
# Variables opcionales (de .env o exportadas):
#   WAZUH_SERVER_IP       IP del manager Wazuh. FUENTE DE VERDAD (default 172.44.30.5).
#                         Si no esta, cae a WAZUH_MANAGER_HOST o WAZUH_VM_SSH_HOST
#                         (aliases deprecated, mantendidos por compat).
#   WAZUH_VM_SSH_USER     Usuario SSH (default tadeou7)
#   WAZUH_VM_SSH_PORT     Puerto SSH (default 22)
#   WAZUH_VM_SSH_PASS     Pass SSH. Si no esta seteada, se skipea el ssh test.
#   WAHA_HOST             URL base de WAHA (default http://172.44.30.8:3000)
#   RELAY_HOST            URL base del relay (default http://172.44.30.8:8765)
#   OLLAMA_HOST           URL base de Ollama (default http://172.44.30.8:11434)
#   WAZUH_MANAGER_API_USER (default wazuh)
#   WAZUH_MANAGER_API_PASS Si no esta seteada, se skipea el test de la API.

set +e

# Resolver IP del manager: prioridad WAZUH_SERVER_IP > WAZUH_MANAGER_HOST > WAZUH_VM_SSH_HOST
WAZUH_SERVER_IP_RESOLVED="${WAZUH_SERVER_IP:-${WAZUH_MANAGER_HOST:-${WAZUH_VM_SSH_HOST:-172.44.30.5}}}"

# Defaults (aliases deprecated se mantienen por compat pero usan la IP resuelta)
WAZUH_VM_SSH_HOST="${WAZUH_VM_SSH_HOST:-${WAZUH_SERVER_IP_RESOLVED}}"
WAZUH_VM_SSH_USER="${WAZUH_VM_SSH_USER:-tadeou7}"
WAZUH_VM_SSH_PORT="${WAZUH_VM_SSH_PORT:-22}"
WAHA_HOST="${WAHA_HOST:-http://172.44.30.8:3000}"
RELAY_HOST="${RELAY_HOST:-http://172.44.30.8:8765}"
OLLAMA_HOST="${OLLAMA_HOST:-http://172.44.30.8:11434}"
WAZUH_MANAGER_API_HOST="${WAZUH_MANAGER_API_HOST:-${WAZUH_SERVER_IP_RESOLVED}}"
WAZUH_MANAGER_API_USER="${WAZUH_MANAGER_API_USER:-wazuh}"

GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }
sep()  { echo -e "\n${YEL}========== $1 ==========${NC}"; }

# Cargar .env si existe en el cwd o ~/Desktop/wazuh-waha/.env
# (PROJECT_ROOT se mantiene como ~/Desktop/wazuh-waha aunque el codigo
#  viva en ~/Desktop/wazuh-waha/relay/, por compat con instalacion previa)
if [ -f .env ]; then
  set -a; source .env; set +a
elif [ -f ~/Desktop/wazuh-waha/.env ]; then
  set -a; source ~/Desktop/wazuh-waha/.env; set +a
fi

sep "1. WAHA (docker)"
docker ps --filter "name=wazuh-waha" --format "  {{.Names}}  {{.Status}}  {{.Ports}}" 2>&1
if docker ps --filter "name=wazuh-waha" --format "{{.Names}}" 2>/dev/null | grep -q waha; then
  ok "WAHA container running"
else
  fail "WAHA container NOT running"
fi

sep "2. WAHA session (pide API key desde .env)"
if [ -z "$WAHA_API_KEY" ]; then
  fail "no pude leer WAHA_API_KEY del .env"
else
  echo "  key len: ${#WAHA_API_KEY}"
  curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" "$WAHA_HOST/api/sessions/default" 2>&1 | head -c 600
  echo
fi

sep "3. Puerto 8765 (relay)"
if ss -tln 2>/dev/null | grep -q ":8765"; then
  ok "relay escucha en :8765"
else
  fail "nada escucha en :8765"
fi

sep "4. Relay health endpoint"
curl -sS -m 5 "$RELAY_HOST/health" 2>&1
echo

sep "5. Relay systemd unit"
systemctl is-active wazuh-waha 2>&1
systemctl is-enabled wazuh-waha 2>&1
systemctl status wazuh-waha --no-pager 2>&1 | head -15

sep "6. Ollama"
curl -sS -m 5 "$OLLAMA_HOST/api/tags" 2>&1 | head -c 400
echo

sep "7. Wazuh Manager API ($WAZUH_MANAGER_API_HOST:55000)"
if [ -z "$WAZUH_MANAGER_API_PASS" ]; then
  warn "WAZUH_MANAGER_API_PASS no seteada, saltando"
else
  curl -sS -m 5 -k -u "$WAZUH_MANAGER_API_USER:$WAZUH_MANAGER_API_PASS" \
    "https://$WAZUH_MANAGER_API_HOST:55000/" 2>&1 | head -c 300
  echo
fi

sep "8. Wazuh Manager status"
if [ -z "$WAZUH_MANAGER_API_PASS" ]; then
  warn "WAZUH_MANAGER_API_PASS no seteada, saltando"
else
  curl -sS -m 5 -k -u "$WAZUH_MANAGER_API_USER:$WAZUH_MANAGER_API_PASS" \
    "https://$WAZUH_MANAGER_API_HOST:55000/manager/status" 2>&1 | head -c 400
  echo
fi

sep "9. Agente Wazuh LOCAL"
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
  ok "wazuh-agent activo"
elif [ -x /var/ossec/bin/wazuh-control ]; then
  /var/ossec/bin/wazuh-control status 2>&1 | head -10
else
  warn "no encontre wazuh-agent local"
fi

sep "10. Ping a la VM manager"
ping -c 2 -W 2 "$WAZUH_VM_SSH_HOST" 2>&1 | tail -5

sep "10b. SSH port abierto?"
nc -zvw3 "$WAZUH_VM_SSH_HOST" "$WAZUH_VM_SSH_PORT" 2>&1 || echo "puerto $WAZUH_VM_SSH_PORT cerrado/timed out"

sep "11. SSH a la VM (solo check de pass, no hace nada)"
if [ -z "$WAZUH_VM_SSH_PASS" ]; then
  warn "WAZUH_VM_SSH_PASS no seteada, saltando ssh test"
elif ! command -v sshpass >/dev/null; then
  warn "sshpass no instalado, saltando ssh test"
else
  sshpass -p "$WAZUH_VM_SSH_PASS" ssh \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -p "$WAZUH_VM_SSH_PORT" \
    "$WAZUH_VM_SSH_USER@$WAZUH_VM_SSH_HOST" \
    'echo SSH_OK; ls /var/ossec/etc/ossec.conf 2>&1; sudo -n true 2>&1 && echo SUDO_OK || echo SUDO_needs_tty' \
    2>&1 | head -10
fi

sep "12. Estructura del repo"
ls -la ~/Desktop/wazuh-waha/ 2>&1 | head -15
ls -la ~/Desktop/wazuh-waha/relay/ 2>&1 | head -10

echo
echo -e "${GRN}========== FIN DIAGNOSTICO ==========${NC}"
echo "Pegame toda esta salida en el chat."
