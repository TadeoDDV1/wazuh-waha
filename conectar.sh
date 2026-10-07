#!/usr/bin/env bash
# ==============================================================================
# conectar.sh - Asistente de Conexión, Credenciales y Sincronización
# Proyecto: wazuh-waha
# ==============================================================================
# Este script:
#   1. Valida credenciales existentes o genera nuevas (RELAY_API_KEY, WAHA_API_KEY)
#   2. Configura ADMIN_PHONE y verifica IPs de red
#   3. Actualiza .env de forma limpia
#   4. Recrea el contenedor WAHA en Docker
#   5. Sincroniza /etc/wazuh-waha/relay.env para Systemd
#   6. Reinicia el Relay y todos los servicios
#   7. Despliega la config al Wazuh Manager vía SSH (si hay acceso)
#   8. Valida la conexión end-to-end
#
# Uso:
#   ./conectar.sh                  # Modo interactivo (default)
#   ./conectar.sh --auto           # Todo automático, sin preguntas
#   ./conectar.sh --fix-connection # Solo sincronizar y verificar conexión
#   ./conectar.sh --force-keys     # Forzar regeneración de API keys
# ==============================================================================

set -e

# ── Colores ──────────────────────────────────────────────────────────────────
ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[1;33m'
AZUL='\033[0;34m'
CYAN='\033[0;36m'
BLANCO='\033[1;37m'
GRIS='\033[0;90m'
NC='\033[0m'

# ── Flags ────────────────────────────────────────────────────────────────────
AUTO_MODE=false
FIX_CONNECTION=false
FORCE_KEYS=false

for arg in "$@"; do
    case "$arg" in
        --auto)           AUTO_MODE=true ;;
        --fix-connection) FIX_CONNECTION=true ;;
        --force-keys)     FORCE_KEYS=true ;;
        --help|-h)
            echo "Uso: $0 [--auto] [--fix-connection] [--force-keys]"
            echo ""
            echo "  --auto            Todo automático, sin preguntas"
            echo "  --fix-connection  Solo sincronizar config y verificar conexión"
            echo "  --force-keys      Forzar regeneración de API keys"
            exit 0
            ;;
    esac
done

# ── Funciones auxiliares ─────────────────────────────────────────────────────
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

# Verificar sudo
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
else
    SUDO=""
fi

# ── Validar que key hex es válida (48 chars hex) ─────────────────────────────
is_valid_hex_key() {
    local key="$1"
    [[ "$key" =~ ^[0-9a-fA-F]{48}$ ]]
}

# ── Leer/escribir .env ───────────────────────────────────────────────────────
get_env_val() {
    local k="$1"
    # 1) Variable de entorno en runtime tiene prioridad (ej:
    #    WAZUH_VM_SSH_PASS=xxx ./conectar.sh --fix-connection)
    if [ -n "${!k:-}" ]; then
        printf '%s\n' "${!k}"
        return
    fi
    # 2) Fallback: leer del .env
    grep -E "^${k}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

set_env_val() {
    local k="$1"
    local v="$2"
    if grep -qE "^${k}=" "$ENV_FILE"; then
        local escaped_val
        escaped_val=$(printf '%s\n' "$v" | sed -e 's/[\/&]/\\&/g')
        sed -i "s/^${k}=.*/${k}=${escaped_val}/" "$ENV_FILE"
    else
        echo "${k}=${v}" >> "$ENV_FILE"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# INICIO
# ══════════════════════════════════════════════════════════════════════════════

titulo "ASISTENTE DE CONEXIÓN WAZUH-WAHA"

if [ "$AUTO_MODE" = true ]; then
    info "Modo automático: sin preguntas, usando valores existentes."
fi
if [ "$FIX_CONNECTION" = true ]; then
    info "Modo fix-connection: solo sincronizar y verificar."
fi

# ── 0. Asegurar existencia de .env ───────────────────────────────────────────
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

# ── 1. Leer valores actuales ─────────────────────────────────────────────────
LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' || hostname -I | awk '{print $1}')
LOCAL_IP="${LOCAL_IP:-127.0.0.1}"

CURRENT_RELAY_KEY=$(get_env_val "RELAY_API_KEY")
CURRENT_WAHA_KEY=$(get_env_val "WAHA_API_KEY")
CURRENT_PHONE=$(get_env_val "ADMIN_PHONE")
CURRENT_MGR_IP=$(get_env_val "WAZUH_SERVER_IP")
CURRENT_WAHA_HOST=$(get_env_val "WAHA_HOST")
CURRENT_WAHA_HOST="${CURRENT_WAHA_HOST:-http://localhost:3001}"
CURRENT_SSH_USER=$(get_env_val "WAZUH_VM_SSH_USER")
CURRENT_SSH_USER="${CURRENT_SSH_USER:-tadeou7}"
CURRENT_SSH_PORT=$(get_env_val "WAZUH_VM_SSH_PORT")
CURRENT_SSH_PORT="${CURRENT_SSH_PORT:-22}"

# ── 2. Auto-detectar IP del Wazuh Manager si no está definida ────────────────
detect_wazuh_manager_ip() {
    local detected_ip=""

    # Método 1: Verificar si el Manager corre en esta máquina
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        info "Wazuh Manager detectado localmente en esta máquina."
        detected_ip="$LOCAL_IP"
        echo "$detected_ip"
        return 0
    fi

    # Método 2: Leer del ossec.conf del agente local
    local agent_conf="/var/ossec/etc/ossec.conf"
    if [ -f "$agent_conf" ]; then
        detected_ip=$(grep -oE '<address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</address>' "$agent_conf" 2>/dev/null \
            | head -1 | sed 's|</\?address>||g' | tr -d ' ')
        if [ -n "$detected_ip" ] && [ "$detected_ip" != "0.0.0.0" ]; then
            info "IP del Manager detectada desde $agent_conf: $detected_ip"
            echo "$detected_ip"
            return 0
        fi
    fi

    # Método 3: Escanear la red local buscando puertos 55000 (API) o 1514 (Agentes)
    info "Escaneando red local para encontrar Wazuh Manager..."
    local iface
    iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$iface" ]; then
        return 1
    fi

    local subnet
    subnet=$(ip -o -f inet addr show "$iface" 2>/dev/null | awk '{print $4}' | head -n1)
    if [ -z "$subnet" ]; then
        return 1
    fi

    local base_ip
    base_ip=$(echo "$subnet" | cut -d/ -f1 | cut -d. -f1-3)

    # Escaneo rápido: probar IPs comunes en la subred
    for i in $(seq 1 50); do
        local test_ip="${base_ip}.${i}"
        [ "$test_ip" = "$LOCAL_IP" ] && continue
        # Probar puerto 55000 (API) o 1514 (Agentes)
        if timeout 1 bash -c "echo >/dev/tcp/$test_ip/55000" 2>/dev/null || \
           timeout 1 bash -c "echo >/dev/tcp/$test_ip/1514" 2>/dev/null; then
            # Verificar que es Wazuh
            if curl -s -k -m 2 "https://$test_ip:55000/" 2>/dev/null | grep -qi "wazuh\|title"; then
                info "Wazuh Manager encontrado en: $test_ip"
                echo "$test_ip"
                return 0
            fi
        fi
    done

    return 1
}

# Auto-detectar si no está definida la IP del Manager
DETECTED_MGR_IP=""
if [ -z "$CURRENT_MGR_IP" ] || [ "$CURRENT_MGR_IP" = "0.0.0.0" ]; then
    info "WAZUH_SERVER_IP no definida. Intentando auto-detección..."
    DETECTED_MGR_IP=$(detect_wazuh_manager_ip) || true

    if [ -n "$DETECTED_MGR_IP" ]; then
        ok "IP del Manager detectada: $DETECTED_MGR_IP"
        set_env_val "WAZUH_SERVER_IP" "$DETECTED_MGR_IP"
        CURRENT_MGR_IP="$DETECTED_MGR_IP"
    elif [ "$AUTO_MODE" = true ]; then
        fail "No se pudo detectar el Wazuh Manager automáticamente."
        fail "Define WAZUH_SERVER_IP en .env o ejecuta sin --auto para ingresarla manualmente."
        exit 1
    fi
else
    # Verificar que la IP configurada sigue siendo válida
    info "Verificando Wazuh Manager en $CURRENT_MGR_IP..."
    if timeout 2 bash -c "echo >/dev/tcp/$CURRENT_MGR_IP/55000" 2>/dev/null || \
       timeout 2 bash -c "echo >/dev/tcp/$CURRENT_MGR_IP/1514" 2>/dev/null; then
        ok "Wazuh Manager accesible en $CURRENT_MGR_IP"
    else
        warn "Wazuh Manager NO responde en $CURRENT_MGR_IP"
        if [ "$AUTO_MODE" = false ]; then
            info "Intentando buscar el Manager en la red..."
            DETECTED_MGR_IP=$(detect_wazuh_manager_ip) || true
            if [ -n "$DETECTED_MGR_IP" ] && [ "$DETECTED_MGR_IP" != "$CURRENT_MGR_IP" ]; then
                echo -e "  ${AMARILLO}Se encontró el Manager en otra IP: $DETECTED_MGR_IP${NC}"
                read -rp "  ¿Actualizar WAZUH_SERVER_IP a $DETECTED_MGR_IP? (S/n): " update_ip
                if [[ ! "$update_ip" =~ ^[nN]$ ]]; then
                    set_env_val "WAZUH_SERVER_IP" "$DETECTED_MGR_IP"
                    CURRENT_MGR_IP="$DETECTED_MGR_IP"
                    ok "IP actualizada a $DETECTED_MGR_IP"
                fi
            fi
        fi
    fi
fi

echo -e "  ${BLANCO}Datos actuales detectados:${NC}"
echo -e "    • IP local de este host (Relay):   ${VERDE}${LOCAL_IP}${NC}"
echo -e "    • IP del Wazuh Manager:           ${CYAN}${CURRENT_MGR_IP:-no definida}${NC}"
echo -e "    • Teléfono destino WhatsApp:      ${CYAN}${CURRENT_PHONE:-no configurado}${NC}"
echo -e "    • Host de WAHA:                   ${CYAN}${CURRENT_WAHA_HOST}${NC}"
echo -e "    • Relay API Key:                  ${CYAN}$(if is_valid_hex_key "$CURRENT_RELAY_KEY"; then echo "válida (${#CURRENT_RELAY_KEY} chars)"; else echo "INVÁLIDA o vacía"; fi)${NC}"
echo -e "    • WAHA API Key:                   ${CYAN}$(if is_valid_hex_key "$CURRENT_WAHA_KEY"; then echo "válida (${#CURRENT_WAHA_KEY} chars)"; else echo "INVÁLIDA o vacía"; fi)${NC}"
echo ""

# ── 3. Decidir sobre regeneración de keys ────────────────────────────────────
REGEN="n"

# Determinar si las keys actuales son válidas
RELAY_KEY_VALID=false
WAHA_KEY_VALID=false
is_valid_hex_key "$CURRENT_RELAY_KEY" && RELAY_KEY_VALID=true
is_valid_hex_key "$CURRENT_WAHA_KEY" && WAHA_KEY_VALID=true

if [ "$FORCE_KEYS" = true ]; then
    info "Forzando regeneración de API keys (--force-keys)."
    REGEN="s"
elif [ "$RELAY_KEY_VALID" = false ] || [ "$WAHA_KEY_VALID" = false ]; then
    info "Se detectaron claves inválidas o de ejemplo. Se generarán nuevas claves automáticamente."
    REGEN="s"
elif [ "$AUTO_MODE" = true ]; then
    info "Keys válidas detectadas. Conservando keys existentes (modo --auto)."
    REGEN="n"
else
    if [ "$FIX_CONNECTION" = false ]; then
        echo -e "  ¿Las API Keys actuales son correctas? (las keys actuales tienen 48 caracteres hex)"
        read -rp "  ¿Deseas REGENERAR nuevas API Keys? (s/N): " resp_regen
        if [[ "$resp_regen" =~ ^[sSyY]$ ]]; then
            REGEN="s"
        fi
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
    info "Conservando keys existentes."
fi

# ── 4. Configurar teléfono ───────────────────────────────────────────────────
if [ "$FIX_CONNECTION" = false ]; then
    if [ "$AUTO_MODE" = false ]; then
        echo ""
        echo -e "  Número de WhatsApp para recibir alertas (formato país + número, ej. 5219991234567)"
        read -rp "  [Enter para conservar '${CURRENT_PHONE:-sin número}']: " input_phone
        if [ -n "$input_phone" ]; then
            set_env_val "ADMIN_PHONE" "$input_phone"
            ok "Teléfono actualizado a: $input_phone"
        fi
    fi

    if [ -z "$CURRENT_MGR_IP" ]; then
        if [ "$AUTO_MODE" = true ]; then
            fail "WAZUH_SERVER_IP no está definido en .env y no se pudo detectar automáticamente."
            exit 1
        fi
        read -rp "  IP del Wazuh Manager: " input_mgr_ip
        if [ -n "$input_mgr_ip" ]; then
            set_env_val "WAZUH_SERVER_IP" "$input_mgr_ip"
            CURRENT_MGR_IP="$input_mgr_ip"
        fi
    fi
fi

# Asegurar WAHA_HOST correcto
set_env_val "WAHA_HOST" "http://localhost:3001"

# ══════════════════════════════════════════════════════════════════════════════
# PASO 1: DOCKER (WAHA)
# ══════════════════════════════════════════════════════════════════════════════

if [ "$FIX_CONNECTION" = false ]; then
    echo ""
    titulo "2. APLICANDO CONFIGURACIÓN A DOCKER (WAHA)"

    if command -v docker &>/dev/null; then
        docker context use default >/dev/null 2>&1 || true
        info "Reiniciando contenedor de WAHA con la nueva API Key..."
        docker compose down 2>/dev/null || true
        docker compose up -d --force-recreate
        ok "Contenedor WAHA recreado correctamente."
    else
        fail "Docker no está instalado o no es accesible."
        fail "Sin Docker, WAHA no puede correr. Abortando."
        exit 1
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# PASO 2: SINCRONIZAR .env → /etc/wazuh-waha/relay.env
# ══════════════════════════════════════════════════════════════════════════════

echo ""
titulo "3. SINCRONIZANDO CONFIGURACIÓN CON SYSTEMD"

if [ -f "$SCRIPT_DIR/scripts/sync_relay_env.sh" ]; then
    info "Sincronizando /etc/wazuh-waha/relay.env..."
    $SUDO bash "$SCRIPT_DIR/scripts/sync_relay_env.sh" apply >/dev/null 2>&1 || {
        $SUDO mkdir -p /etc/wazuh-waha
        $SUDO cp "$ENV_FILE" /etc/wazuh-waha/relay.env
        $SUDO chmod 600 /etc/wazuh-waha/relay.env
    }
    ok "Archivo /etc/wazuh-waha/relay.env actualizado."
else
    warn "sync_relay_env.sh no encontrado. Copiando .env directamente..."
    $SUDO mkdir -p /etc/wazuh-waha
    $SUDO cp "$ENV_FILE" /etc/wazuh-waha/relay.env
    $SUDO chmod 600 /etc/wazuh-waha/relay.env
    ok "Archivo /etc/wazuh-waha/relay.env actualizado (copia directa)."
fi

# ══════════════════════════════════════════════════════════════════════════════
# PASO 3: REINICIAR SERVICIOS
# ══════════════════════════════════════════════════════════════════════════════

echo ""
titulo "4. REINICIANDO SERVICIOS SYSTEMD"

info "Reiniciando servicios..."
$SUDO systemctl daemon-reload
$SUDO systemctl restart wazuh-waha
$SUDO systemctl restart wazuh-waha-watchdog.service 2>/dev/null || true
$SUDO systemctl restart watch_manager_ip.service 2>/dev/null || true
ok "Servicios reiniciados."

# ══════════════════════════════════════════════════════════════════════════════
# PASO 4: DESPLEGAR CONFIG AL WAZUH MANAGER
# ══════════════════════════════════════════════════════════════════════════════

echo ""
titulo "5. DESPLEGANDO CONFIGURACIÓN AL WAZUH MANAGER"

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

DEPLOY_OK=false
MANAGER_LOCAL=false

# Detectar si el Manager está en la misma máquina
if [ -n "$CURRENT_MGR_IP" ]; then
    # Comparar con todas las IPs locales
    for local_addr in $(hostname -I 2>/dev/null); do
        if [ "$local_addr" = "$CURRENT_MGR_IP" ]; then
            MANAGER_LOCAL=true
            break
        fi
    done
fi

if [ "$MANAGER_LOCAL" = true ]; then
    # ── Manager local: copia directa con sudo ────────────────────────────────
    info "Manager detectado en la misma máquina ($CURRENT_MGR_IP). Copiando directamente..."

    # Backup del archivo anterior
    $SUDO cp /var/ossec/etc/wsl-relay.conf \
        /var/ossec/etc/wsl-relay.conf.bak.$(date +%s) 2>/dev/null && \
        ok "Backup del archivo anterior creado." || \
        warn "No se pudo crear backup (puede no existir el archivo aún)."

    # Copiar archivo de configuración
    $SUDO mkdir -p /var/ossec/etc
    $SUDO cp "$MGR_CONF_FILE" /var/ossec/etc/wsl-relay.conf
    $SUDO chown root:wazuh /var/ossec/etc/wsl-relay.conf
    $SUDO chmod 640 /var/ossec/etc/wsl-relay.conf
    ok "Configuración copiada a /var/ossec/etc/wsl-relay.conf"
    DEPLOY_OK=true

    # Verificar que whatsapp_alert.py existe
    if [ -f "$SCRIPT_DIR/manager-side/custom/whatsapp_alert.py" ]; then
        $SUDO cp "$SCRIPT_DIR/manager-side/custom/whatsapp_alert.py" \
            /var/ossec/integrations/custom/whatsapp_alert.py 2>/dev/null
        $SUDO chown root:wazuh /var/ossec/integrations/custom/whatsapp_alert.py 2>/dev/null
        $SUDO chmod 750 /var/ossec/integrations/custom/whatsapp_alert.py 2>/dev/null
        ok "whatsapp_alert.py copiado a /var/ossec/integrations/custom/"
    else
        warn "manager-side/custom/whatsapp_alert.py no encontrado. Asegúrate de que exista en el Manager."
    fi

    # Reiniciar Manager si se pidió
    if [ "$FIX_CONNECTION" = false ]; then
        info "Reiniciando Wazuh Manager..."
        $SUDO systemctl restart wazuh-manager 2>/dev/null && \
            ok "Wazuh Manager reiniciado." || \
            warn "No se pudo reiniciar wazuh-manager (puede requerir sudo sin password)."
    fi

elif [ -n "$CURRENT_MGR_IP" ]; then
    # ── Manager remoto: intentar SSH ─────────────────────────────────────────
    # Pass en runtime (WAZUH_VM_SSH_PASS=... ./conectar.sh --fix-connection),
    # nunca guardada en .env. Si no hay pass, se intenta clave SSH (BatchMode).
    SSH_PASS=$(get_env_val "WAZUH_VM_SSH_PASS")

    if [ -n "$SSH_PASS" ] && command -v sshpass &>/dev/null; then
        SSHX=(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -p "$CURRENT_SSH_PORT")
        SCPX=(sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -P "$CURRENT_SSH_PORT")
        # sudo en la VM pide contraseña: se pasa por stdin (-S)
        REMOTE_SUDO="echo $SSH_PASS | sudo -S"
    else
        [ -z "$SSH_PASS" ] && info "Sin WAZUH_VM_SSH_PASS en runtime: intentando clave SSH (${CURRENT_SSH_USER}@${CURRENT_MGR_IP})."
        SSHX=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -p "$CURRENT_SSH_PORT")
        SCPX=(scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -P "$CURRENT_SSH_PORT")
        # -n: falla rápido si sudo necesita pass (sin cuelgue); se muestran
        # los comandos manuales al final.
        REMOTE_SUDO="sudo -n"
    fi

    info "Desplegando configuración al Manager remoto (${CURRENT_SSH_USER}@${CURRENT_MGR_IP})..."

    # Backup
    "${SSHX[@]}" \
        "${CURRENT_SSH_USER}@${CURRENT_MGR_IP}" \
        "$REMOTE_SUDO cp /var/ossec/etc/wsl-relay.conf /var/ossec/etc/wsl-relay.conf.bak.\$(date +%s) 2>/dev/null || true" \
        2>/dev/null && ok "Backup creado en el Manager." || \
        warn "No se pudo crear backup (puede no existir aún)."

    # Copiar
    "${SCPX[@]}" \
        "$MGR_CONF_FILE" \
        "${CURRENT_SSH_USER}@${CURRENT_MGR_IP}:/tmp/wsl-relay.conf" 2>/dev/null

    if [ $? -eq 0 ]; then
        "${SSHX[@]}" \
            "${CURRENT_SSH_USER}@${CURRENT_MGR_IP}" \
            "$REMOTE_SUDO cp /tmp/wsl-relay.conf /var/ossec/etc/wsl-relay.conf && \
             $REMOTE_SUDO chown root:wazuh /var/ossec/etc/wsl-relay.conf && \
             $REMOTE_SUDO chmod 640 /var/ossec/etc/wsl-relay.conf && \
             rm -f /tmp/wsl-relay.conf" 2>/dev/null

        if [ $? -eq 0 ]; then
            ok "Configuración desplegada exitosamente al Manager."
            DEPLOY_OK=true
            if [ "$FIX_CONNECTION" = false ]; then
                info "Reiniciando Wazuh Manager en el host remoto..."
                if "${SSHX[@]}" "${CURRENT_SSH_USER}@${CURRENT_MGR_IP}" "$REMOTE_SUDO systemctl restart wazuh-manager" 2>/dev/null; then
                    ok "Wazuh Manager reiniciado en el host remoto."
                else
                    warn "No se pudo reiniciar wazuh-manager en el Manager remoto (puede requerir sudo sin password)."
                fi
            fi
        else
            fail "Error al mover el archivo en el Manager."
        fi
    else
        fail "Error al copiar archivo al Manager."
    fi
else
    warn "WAZUH_SERVER_IP no definido. No se puede desplegar al Manager."
fi

# Mostrar comandos manuales si el despliegue automático no funcionó
if [ "$DEPLOY_OK" = false ]; then
    echo ""
    echo -e "  ${AMARILLO}Despliegue manual requerido:${NC}"
    echo ""
    if [ "$MANAGER_LOCAL" = true ]; then
        echo -e "  ${AMARILLO}Copiar configuración:${NC}"
        echo -e "  ${CYAN}sudo cp manager-side/wsl-relay.conf /var/ossec/etc/wsl-relay.conf${NC}"
        echo -e "  ${CYAN}sudo chown root:wazuh /var/ossec/etc/wsl-relay.conf && sudo chmod 640 /var/ossec/etc/wsl-relay.conf${NC}"
    else
        echo -e "  ${AMARILLO}Paso A) Copiar configuración al Manager:${NC}"
        echo -e "  ${CYAN}scp manager-side/wsl-relay.conf ${CURRENT_SSH_USER}@${CURRENT_MGR_IP:-<IP_MANAGER>}:/var/ossec/etc/wsl-relay.conf${NC}"
        echo -e "  ${GRIS}Permisos: sudo chown root:wazuh /var/ossec/etc/wsl-relay.conf && sudo chmod 640 /var/ossec/etc/wsl-relay.conf${NC}"
    fi
    echo ""
    echo -e "  ${AMARILLO}Reiniciar Wazuh Manager:${NC}"
    echo -e "  ${CYAN}sudo systemctl restart wazuh-manager${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# PASO 5: VALIDACIÓN END-TO-END
# ══════════════════════════════════════════════════════════════════════════════

echo ""
titulo "6. VALIDANDO CONECTIVIDAD DEL STACK"

sleep 3

# Test Relay Health
echo -n "  • Comprobando Relay (:8765/health) ... "
RELAY_STATUS=$(curl -s -m 5 http://localhost:8765/health || echo "fail")
if echo "$RELAY_STATUS" | grep -q '"status":"ok"'; then
    echo -e "${VERDE}[CONECTADO Y RESPONDIENDO]${NC}"
else
    echo -e "${ROJO}[ERROR: $RELAY_STATUS]${NC}"
    info "Reintentando relay..."
    $SUDO systemctl restart wazuh-waha 2>/dev/null || true
    sleep 3
    RELAY_STATUS=$(curl -s -m 5 http://localhost:8765/health || echo "fail")
    if echo "$RELAY_STATUS" | grep -q '"status":"ok"'; then
        echo -n "  • Reintentando Relay (:8765/health) ... "
        echo -e "${VERDE}[RECUPERADO]${NC}"
    else
        echo -e "    ${ROJO}[SIN RESPUESTA tras reinicio]${NC}"
    fi
fi

# Test WAHA API
echo -n "  • Comprobando WAHA API (:3001) ... "
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

# Test autenticación del Relay con RELAY_API_KEY
echo -n "  • Verificando auth del Relay (POST test) ... "
AUTH_TEST=$(curl -s -m 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -H "X-Api-Key: $RELAY_KEY" \
    -d '{"test":true}' \
    http://localhost:8765/alerts 2>/dev/null || echo "000")
if [ "$AUTH_TEST" = "401" ]; then
    echo -e "${ROJO}[KEY RECHAZADA - la key del .env no coincide con el relay]${NC}"
    warn "El relay puede estar usando una key diferente. Verificar /etc/wazuh-waha/relay.env"
elif [ "$AUTH_TEST" = "400" ] || [ "$AUTH_TEST" = "200" ]; then
    echo -e "${VERDE}[KEY ACEPTADA - auth OK (HTTP $AUTH_TEST)]${NC}"
elif [ "$AUTH_TEST" = "000" ]; then
    echo -e "${ROJO}[SIN RESPUESTA]${NC}"
else
    echo -e "${AMARILLO}[RESPUESTA: HTTP $AUTH_TEST]${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# PASO 6: WHATSAPP QR (si necesario)
# ══════════════════════════════════════════════════════════════════════════════

if echo "$WAHA_RESP" | grep -q 'SCAN_QR_CODE'; then
    echo ""
    separador
    echo -e "${AMARILLO}  [!] WHATSAPP AÚN NO ESTÁ VINCULADO${NC}"
    echo -e "  Puedes escanear el QR directamente abriendo en tu navegador:"
    echo -e "  👉 ${BLANCO}http://localhost:3001/dashboard${NC} (API Key: ${CYAN}${WAHA_KEY}${NC})"

    if [ "$AUTO_MODE" = false ]; then
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
fi

# ══════════════════════════════════════════════════════════════════════════════
# RESUMEN FINAL
# ══════════════════════════════════════════════════════════════════════════════

echo ""
separador
echo -e "${VERDE}  ¡PROCESO COMPLETADO SATISFACTORIAMENTE!${NC}"
echo ""
if [ "$REGEN" = "s" ]; then
    echo -e "  ${AMARILLO}NOTA: Se generaron nuevas API Keys.${NC}"
    echo -e "  Asegúrate de que el Wazuh Manager tenga la misma RELAY_API_KEY."
    if [ "$DEPLOY_OK" = true ]; then
        echo -e "  ${VERDE}La config fue desplegada automáticamente al Manager.${NC}"
    else
        echo -e "  ${AMARILLO}La config NO se pudo desplegar automáticamente. Revisa los comandos de arriba.${NC}"
    fi
fi
echo ""
echo -e "  Puedes ejecutar ${BLANCO}./admin.sh${NC} en cualquier momento para monitorear el sistema."
separador
