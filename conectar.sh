#!/usr/bin/env bash
# ==============================================================================
# conectar.sh - Asistente 1-Clic de Conexión, Credenciales y Sincronización
# Proyecto: wazuh-waha
# ==============================================================================
# Este script:
#   1. Valida o genera nuevas credenciales seguras (RELAY_API_KEY, WAHA_API_KEY)
#   2. Configura ADMIN_PHONE y verifica IPs de red
#   3. Actualiza .env de forma limpia
#   4. Recrea el contenedor WAHA en Docker con las nuevas variables
#   5. Sincroniza /etc/wazuh-waha/relay.env para Systemd
#   6. Reinicia el Relay y todos los servicios
#   7. Valida la conexión y muestra el código QR de WhatsApp si hace falta
#   8. Genera la configuración lista para el Wazuh Manager (/var/ossec/etc/wsl-relay.conf)
# ==============================================================================

set -e

ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[1;33m'
AZUL='\033[0;34m'
CYAN='\033[0;36m'
BLANCO='\033[1;37m'
GRIS='\033[0;90m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

separador() {
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
}

titulo() {
    separador
    echo -e "${BLANCO}  $1${NC}"
    separador
}

ok()   { echo -e "  ${VERDE}[✓]${NC} $1"; }
fail() { echo -e "  ${ROJO}[✗]${NC} $1"; }
warn() { echo -e "  ${AMARILLO}[!]${NC} $1"; }
info() { echo -e "  ${CYAN}[i]${NC} $1"; }

# 1. Verificar sudo al inicio si se requiere
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

titulo "ASISTENTE DE CONFIGURACIÓN, CREDENCIALES Y CONEXIÓN WAZUH-WAHA"

# 2. Asegurar existencia de .env
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        info "Creando .env a partir de .env.example..."
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        ok ".env creado."
    else
        fail "No se encontró .env ni .env.example en $SCRIPT_DIR"
        exit 1
    fi
fi

# Detectar IP local de este servidor
LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' || hostname -I | awk '{print $1}')
LOCAL_IP="${LOCAL_IP:-127.0.0.1}"

# Leer valores actuales de .env
get_env_val() {
    local k="$1"
    grep -E "^${k}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

set_env_val() {
    local k="$1"
    local v="$2"
    if grep -qE "^${k}=" "$ENV_FILE"; then
        local escaped_val=$(printf '%s\n' "$v" | sed -e 's/[\/&]/\\&/g')
        sed -i "s/^${k}=.*/${k}=${escaped_val}/" "$ENV_FILE"
    else
        echo "${k}=${v}" >> "$ENV_FILE"
    fi
}

CURRENT_RELAY_KEY=$(get_env_val "RELAY_API_KEY")
CURRENT_WAHA_KEY=$(get_env_val "WAHA_API_KEY")
CURRENT_PHONE=$(get_env_val "ADMIN_PHONE")
CURRENT_MGR_IP=$(get_env_val "WAZUH_SERVER_IP")
CURRENT_WAHA_HOST=$(get_env_val "WAHA_HOST")
CURRENT_WAHA_HOST="${CURRENT_WAHA_HOST:-http://localhost:3001}"

echo -e "  ${BLANCO}Datos actuales detectados:${NC}"
echo -e "    • IP local de este host (Relay):   ${VERDE}${LOCAL_IP}${NC}"
echo -e "    • IP del Wazuh Manager:           ${CYAN}${CURRENT_MGR_IP:-no definida}${NC}"
echo -e "    • Teléfono destino WhatsApp:      ${CYAN}${CURRENT_PHONE:-no configurado}${NC}"
echo -e "    • Host de WAHA:                   ${CYAN}${CURRENT_WAHA_HOST}${NC}"
echo ""

# Preguntar si se desean regenerar claves
REGEN="n"
if [ -z "$CURRENT_RELAY_KEY" ] || [ "$CURRENT_RELAY_KEY" = "***" ] || [ "$CURRENT_RELAY_KEY" = "changeme" ] || [ -z "$CURRENT_WAHA_KEY" ]; then
    info "Se detectaron claves vacías o de ejemplo. Se generarán nuevas claves automáticamente."
    REGEN="s"
else
    echo -e "  ¿Deseas ${AMARILLO}REGENERAR nuevas API Keys${NC} para solucionar problemas de autenticación? (s/N): "
    read -rp "  > " resp_regen
    if [[ "$resp_regen" =~ ^[sSyY]$ ]]; then
        REGEN="s"
    fi
fi

if [ "$REGEN" = "s" ]; then
    info "Generando nuevas claves seguras con openssl..."
    NEW_RELAY_KEY=$(openssl rand -hex 24)
    NEW_WAHA_KEY=$(openssl rand -hex 24)
    set_env_val "RELAY_API_KEY" "$NEW_RELAY_KEY"
    set_env_val "WAHA_API_KEY" "$NEW_WAHA_KEY"
    ok "Nuevas claves generadas e insertadas en .env."
    RELAY_KEY="$NEW_RELAY_KEY"
    WAHA_KEY="$NEW_WAHA_KEY"
else
    RELAY_KEY="$CURRENT_RELAY_KEY"
    WAHA_KEY="$CURRENT_WAHA_KEY"
fi

# Preguntar / confirmar teléfono de WhatsApp
echo ""
echo -e "  Número de WhatsApp para recibir alertas (formato país + número, ej. 5219991234567)"
read -rp "  [Enter para conservar '${CURRENT_PHONE:-sin número}']: " input_phone
if [ -n "$input_phone" ]; then
    set_env_val "ADMIN_PHONE" "$input_phone"
    ok "Teléfono actualizado a: $input_phone"
fi

# Preguntar / confirmar IP del Manager si está vacía
if [ -z "$CURRENT_MGR_IP" ]; then
    read -rp "  IP del Wazuh Manager: " input_mgr_ip
    if [ -n "$input_mgr_ip" ]; then
        set_env_val "WAZUH_SERVER_IP" "$input_mgr_ip"
        CURRENT_MGR_IP="$input_mgr_ip"
    fi
fi

# Asegurar WAHA_HOST correcto a puerto 3001
set_env_val "WAHA_HOST" "http://localhost:3001"

echo ""
titulo "1. APLICANDO CONFIGURACIÓN A DOCKER (WAHA)"

# Arreglar contexto de Docker por si estaba apuntando a socket inexistente
if command -v docker &>/dev/null; then
    docker context use default >/dev/null 2>&1 || true
    info "Reiniciando contenedor de WAHA con la nueva API Key..."
    docker compose down 2>/dev/null || true
    docker compose up -d --force-recreate
    ok "Contenedor WAHA recreado correctamente."
else
    fail "Docker no está instalado o no es accesible."
fi

echo ""
titulo "2. SINCRONIZANDO CONFIGURACIÓN CON SYSTEMD"

# Sincronizar a /etc/wazuh-waha/relay.env
if [ -f "$SCRIPT_DIR/scripts/sync_relay_env.sh" ]; then
    info "Sincronizando /etc/wazuh-waha/relay.env..."
    $SUDO bash "$SCRIPT_DIR/scripts/sync_relay_env.sh" apply >/dev/null 2>&1 || {
        $SUDO mkdir -p /etc/wazuh-waha
        $SUDO cp "$ENV_FILE" /etc/wazuh-waha/relay.env
        $SUDO chmod 600 /etc/wazuh-waha/relay.env
    }
    ok "Archivo /etc/wazuh-waha/relay.env actualizado."
fi

echo ""
titulo "3. REINICIANDO SERVICIOS SYSTEMD"

info "Reiniciando servicio wazuh-waha..."
$SUDO systemctl daemon-reload
$SUDO systemctl restart wazuh-waha
$SUDO systemctl restart wazuh-waha-watchdog.service 2>/dev/null || true
$SUDO systemctl restart watch_manager_ip.service 2>/dev/null || true
ok "Servicios reiniciados."

echo ""
titulo "4. VALIDANDO CONECTIVIDAD DEL STACK"

# Esperar unos segundos a que levanten uvicorn y WAHA
sleep 3

# Test Relay
echo -n "  • Comprobando Relay (:8765/health) ... "
RELAY_STATUS=$(curl -s -m 5 http://localhost:8765/health || echo "fail")
if echo "$RELAY_STATUS" | grep -q '"status":"ok"'; then
    echo -e "${VERDE}[CONECTADO Y RESPONDIENDO]${NC}"
else
    echo -e "${ROJO}[ERROR AL CONECTAR: $RELAY_STATUS]${NC}"
fi

# Test WAHA API
echo -n "  • Comprobando WAHA API (:3001/api/sessions/default) ... "
WAHA_RESP=$(curl -s -m 5 -H "X-Api-Key: $WAHA_KEY" http://localhost:3001/api/sessions/default || echo "fail")
if echo "$WAHA_RESP" | grep -q '"status"'; then
    SES_STATE=$(echo "$WAHA_RESP" | grep -o '"status":"[^"]*' | cut -d'"' -f4)
    if [ "$SES_STATE" = "WORKING" ]; then
        echo -e "${VERDE}[SESIÓN ACTIVA: WORKING]${NC}"
    elif [ "$SES_STATE" = "SCAN_QR_CODE" ]; then
        echo -e "${AMARILLO}[PENDIENTE: ESCANEAR CÓDIGO QR]${NC}"
    else
        echo -e "${AMARILLO}[ESTADO: $SES_STATE]${NC}"
    fi
else
    echo -e "${ROJO}[ERROR DE AUTENTICACIÓN / CONEXIÓN: $WAHA_RESP]${NC}"
fi

# Generar archivo de configuración para el Manager
MGR_CONF_FILE="$SCRIPT_DIR/manager-side/wsl-relay.conf"
mkdir -p "$SCRIPT_DIR/manager-side"
cat <<EOF > "$MGR_CONF_FILE"
# Configuración del script whatsapp_alert.py en Wazuh Manager
# Generado automáticamente por conectar.sh el $(date '+%Y-%m-%d %H:%M:%S')
WAZUH_RELAY_URL=http://${LOCAL_IP}:8765/alerts
WAZUH_RELAY_API_KEY=${RELAY_KEY}
WAZUH_RELAY_TIMEOUT=5
EOF
chmod 644 "$MGR_CONF_FILE"
ok "Archivo generado: manager-side/wsl-relay.conf"

echo ""
titulo "5. ACCIONES EN EL WAZUH MANAGER"
echo -e "${BLANCO}Para que el Wazuh Manager conecte con este Relay, debe tener la misma clave:${NC}"
echo ""
echo -e "  ${AMARILLO}Paso A) Copiar archivo de configuración al Manager:${NC}"
echo -e "  Ejecuta esto para subir el archivo generado:"
echo -e "  ${CYAN}scp manager-side/wsl-relay.conf root@${CURRENT_MGR_IP:-<IP_MANAGER>}:/var/ossec/etc/wsl-relay.conf${NC}"
echo -e "  (O crea el archivo ${BLANCO}/var/ossec/etc/wsl-relay.conf${NC} en el Manager con este contenido):"
echo -e "  --------------------------------------------------"
cat "$MGR_CONF_FILE" | sed 's/^/  /'
echo -e "  --------------------------------------------------"
echo -e "  ${GRIS}Permisos en el Manager: sudo chown root:wazuh /var/ossec/etc/wsl-relay.conf && sudo chmod 640 /var/ossec/etc/wsl-relay.conf${NC}"
echo ""
echo -e "  ${AMARILLO}Paso B) Asegurar que el script existe en el Manager:${NC}"
echo -e "  ${CYAN}scp manager-side/custom/whatsapp_alert.py root@${CURRENT_MGR_IP:-<IP_MANAGER>}:/var/ossec/integrations/custom/${NC}"
echo -e "  ${GRIS}Permisos: sudo chmod 750 /var/ossec/integrations/custom/whatsapp_alert.py && sudo chown root:wazuh /var/ossec/integrations/custom/whatsapp_alert.py${NC}"
echo ""
echo -e "  ${AMARILLO}Paso C) Reiniciar Wazuh Manager:${NC}"
echo -e "  ${CYAN}sudo systemctl restart wazuh-manager${NC}"

# Si la sesión de WAHA necesita QR, ofrecer mostrarlo
if echo "$WAHA_RESP" | grep -q 'SCAN_QR_CODE'; then
    echo ""
    separador
    echo -e "${AMARILLO}  [!] WHATSAPP AÚN NO ESTÁ VINCULADO${NC}"
    echo -e "  Puedes escanear el QR directamente abriendo en tu navegador:"
    echo -e "  👉 ${BLANCO}http://localhost:3001/dashboard${NC} (API Key: ${CYAN}${WAHA_KEY}${NC})"
    echo ""
    read -rp "  ¿Deseas intentar renderizar el código QR en la terminal ahora? (s/N): " show_qr
    if [[ "$show_qr" =~ ^[sSyY]$ ]]; then
        QR_RAW=$(curl -s -m 5 -H "X-Api-Key: $WAHA_KEY" http://localhost:3001/api/default/auth/qr 2>/dev/null | grep -o '"raw":"[^"]*' | cut -d'"' -f4 || true)
        if [ -n "$QR_RAW" ]; then
            if command -v qrencode &>/dev/null; then
                echo ""
                qrencode -t ANSI256 "$QR_RAW"
                echo ""
            else
                echo -e "  Código QR raw: $QR_RAW"
                warn "Instala 'qrencode' para renderizarlo en texto gráfico: sudo pacman -S qrencode (o apt install qrencode)"
            fi
        else
            info "WAHA está preparando el código QR. Puedes abrir http://localhost:3001/dashboard en el navegador."
        fi
    fi
fi

echo ""
separador
echo -e "${VERDE}  ¡PROCESO COMPLETADO SATISFACTORIAMENTE!${NC}"
echo -e "  Puedes ejecutar ${BLANCO}./admin.sh${NC} en cualquier momento para monitorear el sistema."
separador
