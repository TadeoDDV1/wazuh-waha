#!/bin/bash
# =============================================================================
# diagnose.sh - Diagnóstico del Stack Wazuh -> WAHA en Servidor Local
# =============================================================================
# Diagnóstico read-only. No modifica nada.
# - Lee .env del proyecto de forma segura (sin fallar ante espacios ni comillas).
# - Comprueba contenedores Docker (WAHA, Dashboard).
# - Comprueba sesión de WAHA y API Key.
# - Comprueba servicio systemd y salud HTTP del Relay (:8765).
# - Comprueba estado de Wazuh Manager local e integración custom-whatsapp.
# =============================================================================

set +e

GRN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GRN}[ OK ]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YEL}[WARN]${NC} $1"; }
sep()  { echo -e "\n${CYN}========== $1 ==========${NC}"; }

# 1. Resolver ruta del proyecto
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

# 2. Cargar .env de forma segura con Python
if [ -f "$ENV_FILE" ]; then
    PARSED_ENV=$(python3 - <<EOF 2>/dev/null
import sys

data = {}
try:
    with open("$ENV_FILE", 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            k = k.strip()
            v = v.strip()
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1]
            data[k] = v
except Exception:
    pass

for k, v in data.items():
    escaped = v.replace('\\\\', '\\\\\\\\').replace('"', '\\"')
    print(f'{k}="{escaped}"')
EOF
)
    eval "$PARSED_ENV"
fi

# Variables resueltas con defaults para servidor local
RELAY_HOST="${RELAY_HOST:-http://127.0.0.1:8765}"
WAHA_HOST="${WAHA_HOST:-http://127.0.0.1:3001}"
OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}"
WAZUH_SERVER_IP="${WAZUH_SERVER_IP:-127.0.0.1}"
WAZUH_MANAGER_API_HOST="${WAZUH_MANAGER_API_HOST:-$WAZUH_SERVER_IP}"
WAZUH_MANAGER_API_USER="${WAZUH_MANAGER_API_USER:-wazuh}"
WAZUH_MANAGER_API_PORT="${WAZUH_MANAGER_API_PORT:-55000}"

sep "1. WAHA y Dashboard (Docker)"
if command -v docker &>/dev/null; then
  docker ps --filter "name=wazuh-waha" --format "  {{.Names}}  {{.Status}}  {{.Ports}}" 2>&1
  if docker ps --filter "name=wazuh-waha" --format "{{.Names}}" 2>/dev/null | grep -q waha; then
    ok "WAHA container corriendo"
  else
    fail "WAHA container NO esta corriendo"
  fi
else
  warn "Docker no encontrado o no ejecutable sin sudo"
fi

sep "2. WAHA sesión y API Key"
if [ -z "$WAHA_API_KEY" ]; then
  fail "no pude leer WAHA_API_KEY del .env ($ENV_FILE)"
else
  echo "  Longitud de clave WAHA_API_KEY: ${#WAHA_API_KEY} caracteres"
  WAHA_RESP=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" "$WAHA_HOST/api/sessions/default" 2>&1 || true)
  echo "  Respuesta WAHA: ${WAHA_RESP:0:200}"
  if echo "$WAHA_RESP" | grep -q '"status":"WORKING"'; then
    ok "Sesión WAHA operativa (WORKING)"
  elif echo "$WAHA_RESP" | grep -q '"status":"SCAN_QR_CODE"'; then
    warn "Sesión WAHA requiere escanear código QR"
  fi
fi

sep "3. Puerto 8765 (Relay Wazuh-WAHA)"
if ss -tln 2>/dev/null | grep -q ":8765"; then
  ok "Relay escuchando en :8765"
else
  fail "Nada escucha en el puerto :8765"
fi

sep "4. Endpoint de Salud del Relay ($RELAY_HOST/health)"
RELAY_HEALTH=$(curl -sS -m 5 "$RELAY_HOST/health" 2>&1 || true)
echo "  $RELAY_HEALTH"
if echo "$RELAY_HEALTH" | grep -q '"status":"ok"'; then
  ok "Relay responde 200 OK con salud intacta"
else
  fail "Relay no responde o devolvió error"
fi

sep "5. Servicio Systemd del Relay (wazuh-waha)"
systemctl is-active wazuh-waha 2>&1
systemctl is-enabled wazuh-waha 2>&1
systemctl status wazuh-waha --no-pager 2>&1 | head -12

sep "6. Integración en Wazuh Manager Local (/var/ossec)"
if [ -d "/var/ossec" ]; then
  ok "Directorio /var/ossec existe"
  
  # Script custom
  if [ -x "/var/ossec/integrations/custom/whatsapp_alert.py" ]; then
    ok "whatsapp_alert.py instalado con permisos de ejecución"
  else
    fail "whatsapp_alert.py no existe o no tiene permisos de ejecución"
  fi

  # Config relay
  if [ -f "/var/ossec/etc/wsl-relay.conf" ]; then
    ok "/var/ossec/etc/wsl-relay.conf existe"
    grep -v "API_KEY" /var/ossec/etc/wsl-relay.conf 2>/dev/null | sed 's/^/    /'
  else
    fail "/var/ossec/etc/wsl-relay.conf no existe"
  fi

  # Inyección en ossec.conf
  if grep -q "custom-whatsapp" /var/ossec/etc/ossec.conf 2>/dev/null; then
    ok "Bloque <integration> custom-whatsapp presente en ossec.conf"
  else
    fail "Bloque <integration> custom-whatsapp NO encontrado en ossec.conf"
  fi
else
  warn "/var/ossec no encontrado en este host (Wazuh Manager)"
fi

sep "7. Estado de Wazuh Manager"
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
  ok "wazuh-manager activo (systemd)"
elif [ -x /var/ossec/bin/wazuh-control ]; then
  /var/ossec/bin/wazuh-control status 2>&1 | head -8
else
  warn "wazuh-manager local no detectado"
fi

sep "8. Wazuh Manager API ($WAZUH_MANAGER_API_HOST:$WAZUH_MANAGER_API_PORT)"
if [ -z "$WAZUH_MANAGER_API_PASS" ]; then
  warn "WAZUH_MANAGER_API_PASS no seteada en .env, saltando prueba de API"
else
  API_AUTH=$(curl -sS -m 5 -k -u "$WAZUH_MANAGER_API_USER:$WAZUH_MANAGER_API_PASS" \
    "https://$WAZUH_MANAGER_API_HOST:$WAZUH_MANAGER_API_PORT/security/user/authenticate" 2>&1 || true)
  if echo "$API_AUTH" | grep -q '"token"'; then
    ok "Autenticación exitosa en Wazuh API (Token JWT obtenido)"
  else
    fail "Fallo al autenticar en Wazuh API: ${API_AUTH:0:200}"
  fi
fi

sep "9. Dashboard Web (Puerto 8001)"
DASH_HTTP=$(curl -s -m 3 -o /dev/null -w "%{http_code}" "http://127.0.0.1:8001/" 2>/dev/null || true)
if [ "$DASH_HTTP" = "200" ]; then
  ok "Dashboard Web disponible en http://localhost:8001 (HTTP 200)"
else
  warn "Dashboard Web respondió con HTTP $DASH_HTTP en puerto 8001"
fi

echo
echo -e "${GRN}========== FIN DIAGNÓSTICO ==========${NC}"
echo "Estado general del stack verificado."
