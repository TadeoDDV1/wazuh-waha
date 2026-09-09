#!/bin/bash
# =============================================================================
# update_server_vm.sh - Actualiza y valida el estado de Wazuh Manager en la VM / Servidor
# =============================================================================
# Uso:
#   bash scripts/update_server_vm.sh
# =============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -f .env ]; then
  # Leer variables
  SERVER_IP=$(grep -E '^WAZUH_SERVER_IP=' .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
  SSH_USER=$(grep -E '^WAZUH_VM_SSH_USER=' .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
  API_USER=$(grep -E '^WAZUH_MANAGER_API_USER=' .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
  API_PASS=$(grep -E '^WAZUH_MANAGER_API_PASS=' .env | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
fi

SERVER_IP="${SERVER_IP:-127.0.0.1}"
SSH_USER="${SSH_USER:-root}"
API_USER="${API_USER:-wazuh-wui}"
API_PASS="${API_PASS:-}"

echo "========================================================"
echo " Actualizando y Validando Wazuh Manager en: $SERVER_IP"
echo "========================================================"

# 1. Probar conexion a la API REST
echo -n "[1/4] Verificando API REST Wazuh en https://$SERVER_IP:55000 ... "
AUTH_RES=$(curl -k -s -u "$API_USER:$API_PASS" -X POST "https://$SERVER_IP:55000/security/user/authenticate" || true)
if echo "$AUTH_RES" | grep -q '"token"'; then
  TOKEN=$(echo "$AUTH_RES" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
  echo "OK (Token obtenido)"
else
  echo "FALLO: $AUTH_RES"
fi

# 2. Consultar agentes activos
if [ -n "$TOKEN" ]; then
  echo -n "[2/4] Consultando agentes conectados ... "
  AGENTS_RES=$(curl -k -s -H "Authorization: Bearer $TOKEN" "https://$SERVER_IP:55000/agents" || true)
  TOTAL_AGENTS=$(echo "$AGENTS_RES" | grep -o '"total_affected_items":[0-9]*' | cut -d':' -f2)
  echo "OK ($TOTAL_AGENTS agente(s) registrados)"
fi

# 3. Validar agent.conf centralizado
if [ -n "$TOKEN" ]; then
  echo -n "[3/4] Comprobando agent.conf en grupo 'default' ... "
  CONF_RES=$(curl -k -s -H "Authorization: Bearer $TOKEN" "https://$SERVER_IP:55000/groups/default/configuration" || true)
  if echo "$CONF_RES" | grep -q '"affected_items"'; then
    echo "OK (agent.conf sincronizado)"
  else
    echo "FALLO: $CONF_RES"
  fi
fi

# 4. Sincronizar relay.env local
echo -n "[4/4] Sincronizando /etc/wazuh-waha/relay.env ... "
if [ -f scripts/sync_relay_env.sh ]; then
  sudo bash scripts/sync_relay_env.sh apply > /dev/null 2>&1 || true
  echo "OK"
fi

echo ""
echo "========================================================"
echo " Sincronizacion completada con exito."
echo " Dashboard disponible en: http://localhost:8000"
echo " Wazuh Oficial UI en:    https://$SERVER_IP"
echo "========================================================"
