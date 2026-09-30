#!/bin/bash
# ==============================================================================
# Script Unificado de Administración - Wazuh WAHA
# Proyecto: Wazuh-WAHA SOC Integration
# ==============================================================================
# Menú interactivo integral para la terminal:
#   1) Estado e información del sistema (CPU, RAM, Disco)
#   2) Estado de todos los servicios (Wazuh, Docker, Relay, Timers)
#   3) Diagnóstico completo del stack
#   4) Visor de logs en tiempo real (Docker, Relay, Wazuh, Alertas)
#   5) Gestión y Despliegue de Agentes Wazuh (Multiplataforma)
#   6) Control de Módulos de Seguridad Wazuh (SCA, Malware, FIM, Vulns)
#   7) WhatsApp (WAHA) y Notificaciones por Correo (QR, Tests)
#   8) Respaldos automatizados en carpeta 'backups/'
#   9) Listar y explorar respaldos existentes
#  10) Limpieza y mantenimiento del servidor
#  11) Gestión de servicios (iniciar/detener/reiniciar)
#  12) Auto-detección y reconciliación de IP del Manager
#  13) Verificación de seguridad (SSH, Firewall, accesos fallidos)
#  14) Instalar / actualizar herramientas del sistema
#  15) Ver registro de auditoría (admin-wazuh-waha.log)
#  16) Ejecutar mantenimiento y diagnóstico completo
#  17) Ver credenciales de acceso a Wazuh (API + SSH, con confirmación)
#  18) Salir
# ==============================================================================

# ── Colores ANSI ─────────────────────────────────────────────────────────────
ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[1;33m'
AZUL='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BLANCO='\033[1;37m'
GRIS='\033[0;90m'
NC='\033[0m'

# ── Rutas y Variables del Proyecto ───────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"

# Auto-detección de ruta raíz si el script se llama desde otra parte
if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    if [ -f "$HOME/wazuh-waha/docker-compose.yml" ]; then
        PROJECT_ROOT="$HOME/wazuh-waha"
    elif [ -f "$HOME/Desktop/wazuh-waha/docker-compose.yml" ]; then
        PROJECT_ROOT="$HOME/Desktop/wazuh-waha"
    fi
fi

BACKUP_DIR="$PROJECT_ROOT/backups"
LOG_DIR="$PROJECT_ROOT/logs"
ADMIN_LOG="$HOME/admin-wazuh-waha.log"
ENV_FILE="$PROJECT_ROOT/.env"

# Asegurar que el directorio de backups existe
mkdir -p "$BACKUP_DIR"

# Cargar variables del .env si existe
if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE" 2>/dev/null
    set +a
fi

WAHA_HOST="${WAHA_HOST:-http://localhost:3001}"
RELAY_HOST="${RELAY_HOST:-http://localhost:8765}"
WAZUH_SERVER_IP="${WAZUH_SERVER_IP:-192.168.122.142}"
WAZUH_MANAGER_API_PORT="${WAZUH_MANAGER_API_PORT:-55000}"
WAZUH_MANAGER_API_USER="${WAZUH_MANAGER_API_USER:-wazuh}"
WAZUH_MANAGER_API_PASS="${WAZUH_MANAGER_API_PASS:-}"
RELAY_API_KEY="${RELAY_API_KEY:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"

# ── Funciones Auxiliares ─────────────────────────────────────────────────────
limpiar() {
    if [ -t 1 ]; then
        clear 2>/dev/null || true
    fi
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ADMIN_LOG" 2>/dev/null || true
}

pausar() {
    echo ""
    read -rp "  Presione [Enter] para continuar..."
}

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

check_servicio() {
    local nombre="$1"
    local unidad="$2"
    local estado
    estado=$(systemctl is-active "$unidad" 2>/dev/null)
    printf "  %-40s" "• $nombre"
    if [ "$estado" = "active" ]; then
        echo -e "${VERDE}[ACTIVO]${NC}"
    else
        echo -e "${ROJO}[INACTIVO: ${estado:-no encontrado}]${NC}"
    fi
}

check_docker_container() {
    local nombre="$1"
    local container="$2"
    local estado
    estado=$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)
    printf "  %-40s" "• $nombre"
    if [ "$estado" = "true" ]; then
        echo -e "${VERDE}[CORRIENDO]${NC}"
    else
        echo -e "${ROJO}[DETENIDO]${NC}"
    fi
}

# ── Contexto Docker ──────────────────────────────────────────────────────────
# Los contenedores pueden vivir en el contexto 'default' cuando Docker Desktop
# (u otro daemon) es el activo; sin esta detección el script los ve "detenidos".
# Se inyecta --context automáticamente en cada llamada a docker.
DOCKER_CTX_ARGS=()
docker() {
    command docker "${DOCKER_CTX_ARGS[@]}" "$@"
}
detectar_docker_contexto() {
    DOCKER_CTX_ARGS=()
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-waha'; then
        return 0
    fi
    if docker --context default ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-waha'; then
        DOCKER_CTX_ARGS=(--context default)
    fi
    return 0
}
detectar_docker_contexto

# ── Servicios Wazuh: existen local o en la VM (manager remoto) ───────────────
unidad_local() {
    systemctl list-unit-files --no-legend "$1" 2>/dev/null | grep -q "^$1"
}

# vm_ssh [-t] "comando remoto" — clave (BatchMode) → sshpass (.env) → interactivo
vm_ssh() {
    local con_tty=0
    if [ "$1" = "-t" ]; then con_tty=1; shift; fi
    local cmd="$1"
    local destino="${WAZUH_VM_SSH_USER:-root}@${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP}"
    local puerto="${WAZUH_VM_SSH_PORT:-22}"
    local base=(-o ConnectTimeout=5 -p "$puerto")
    if [ -n "${WAZUH_VM_SSH_KEY_PATH:-}" ]; then
        base+=(-i "$WAZUH_VM_SSH_KEY_PATH")
    fi

    # 1) Clave SSH sin prompts
    if ssh -o BatchMode=yes "${base[@]}" "$destino" "$cmd" 2>/dev/null; then
        return 0
    fi
    # 2) Contraseña desde .env (requiere sshpass)
    if [ -n "${WAZUH_VM_SSH_PASS:-}" ] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$WAZUH_VM_SSH_PASS" ssh -o BatchMode=yes "${base[@]}" "$destino" "$cmd"
        return $?
    fi
    # 3) Interactivo con TTY (puede pedir password de SSH y/o sudo remoto)
    if [ "$con_tty" = 1 ] && [ -t 0 ] && [ -t 1 ]; then
        ssh -tt "${base[@]}" -o NumberOfPasswordPrompts=1 "$destino" "$cmd"
        return $?
    fi
    return 1
}

# wazuh_svc restart|status <unidad> <nombre> [--batch]
#   Si la unidad existe localmente, actúa acá; si no, en la VM del Manager.
#   --batch = sin TTY (para recorridos como "reinicio maestro").
wazuh_svc() {
    local accion="$1" unidad="$2" nombre="${3:-$2}" modo="${4:-}"
    if unidad_local "$unidad"; then
        if [ "$accion" = "restart" ]; then
            info "Reiniciando $nombre (local)..."
            sudo systemctl restart "$unidad" || { fail "No se pudo reiniciar $nombre"; return 1; }
            sleep 2
        fi
        check_servicio "$nombre" "$unidad"
        return 0
    fi
    local vm_desc="${WAZUH_VM_SSH_USER:-root}@${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP}"
    if [ "$accion" = "restart" ]; then
        local remoto="sudo -n systemctl restart $unidad 2>/dev/null || sudo systemctl restart $unidad"
        if [ "$modo" = "--batch" ]; then
            if vm_ssh "$remoto" >/dev/null 2>&1; then
                sleep 2
                ok "$nombre reiniciado en la VM ($vm_desc)"
            else
                warn "$nombre: la VM no acepta SSH sin interacción (clave o WAZUH_VM_SSH_PASS). Opciones 3-5 del menú 11 para reinicio interactivo."
            fi
        else
            info "$nombre no está en local → reiniciando en la VM ($vm_desc)..."
            if vm_ssh -t "$remoto" >/dev/null 2>&1; then
                sleep 2
                if vm_ssh "systemctl is-active --quiet $unidad" 2>/dev/null; then
                    ok "$nombre reiniciado y ACTIVO en la VM"
                else
                    fail "$nombre: reinicio enviado pero no quedó activo (revisar en la VM)"
                fi
            else
                fail "Sin acceso SSH a la VM. Instalá una clave (ssh-copy-id) o pasá WAZUH_VM_SSH_PASS en runtime (variable de entorno, no en .env)."
            fi
        fi
    else
        if vm_ssh "systemctl is-active $unidad" 2>/dev/null; then
            printf "  %-40s" "• $nombre (VM)"
            echo -e "${VERDE}[ACTIVO]${NC}"
        else
            printf "  %-40s" "• $nombre (VM)"
            echo -e "${GRIS}[SIN ACCESO]${NC}"
        fi
    fi
}

# Caché de estado de unidades en la VM (una sola conexión SSH por llamada)
declare -A WAZUH_VM_ST=()
cargar_estado_vm() {
    WAZUH_VM_ST=()
    local pendientes=() u
    for u in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
        unidad_local "$u.service" || pendientes+=("$u")
    done
    [ ${#pendientes[@]} -eq 0 ] && return 0
    local out
    out=$(vm_ssh "for u in ${pendientes[*]}; do printf '%s=%s\n' \"\$u\" \"\$(systemctl is-active \"\$u\" 2>/dev/null)\"; done") || return 1
    local par
    while IFS='=' read -r u par; do
        [ -n "$u" ] && WAZUH_VM_ST[$u]="$par"
    done <<< "$out"
    return 0
}

# check_servicio_wazuh <nombre> <unidad> — local si existe, si no desde la VM
check_servicio_wazuh() {
    local nombre="$1" unidad="${2%.service}" est
    if unidad_local "$unidad.service"; then
        check_servicio "$nombre" "$unidad.service"
        return 0
    fi
    est="${WAZUH_VM_ST[$unidad]:-}"
    printf "  %-40s" "• $nombre (VM)"
    case "$est" in
        active)                echo -e "${VERDE}[ACTIVO]${NC}" ;;
        failed)                echo -e "${ROJO}[FALLIDO]${NC}" ;;
        "" )                   echo -e "${GRIS}[VM SIN ACCESO]${NC}" ;;
        *)                     echo -e "${AMARILLO}[${est^^}]${NC}" ;;
    esac
}

# Obtener Token JWT de la API de Wazuh
obtener_wazuh_token() {
    if [ -z "$WAZUH_MANAGER_API_PASS" ]; then
        echo ""
        return 1
    fi
    local auth_res
    auth_res=$(curl -k -s -m 5 -u "${WAZUH_MANAGER_API_USER:-wazuh}:$WAZUH_MANAGER_API_PASS" \
        -X POST "https://${WAZUH_SERVER_IP}:${WAZUH_MANAGER_API_PORT}/security/user/authenticate" 2>/dev/null || true)
    if echo "$auth_res" | grep -q '"token"'; then
        echo "$auth_res" | grep -o '"token":"[^"]*' | cut -d'"' -f4
    else
        echo ""
    fi
}

# ==============================================================================
# 1. INFORMACIÓN Y ESTADO DEL SISTEMA
# ==============================================================================
info_sistema() {
    limpiar
    titulo "ESTADO E INFORMACIÓN DEL SISTEMA"

    local OS_NAME
    OS_NAME=$(grep -oP 'PRETTY_NAME="\K[^"]+' /etc/os-release 2>/dev/null || uname -s)
    local IP_LOCAL
    IP_LOCAL=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -3 | paste -sd ', ' -)
    local UPTIME_STR
    UPTIME_STR=$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}')

    echo -e "  ${AMARILLO}Hostname:${NC}            $(hostname)"
    echo -e "  ${AMARILLO}Sistema Operativo:${NC}   $OS_NAME"
    echo -e "  ${AMARILLO}Kernel:${NC}              $(uname -r)"
    echo -e "  ${AMARILLO}Arquitectura:${NC}        $(uname -m)"
    echo -e "  ${AMARILLO}Tiempo Activo:${NC}       $UPTIME_STR"
    echo -e "  ${AMARILLO}Direcciones IP:${NC}      ${IP_LOCAL:-127.0.0.1}"
    echo -e "  ${AMARILLO}Usuario Actual:${NC}      $(whoami) (UID: $(id -u))"

    echo -e "\n  ${BLANCO}[ Memoria RAM / Swap ]${NC}"
    free -h 2>/dev/null | sed 's/^/  /' || echo "  No disponible"

    echo -e "\n  ${BLANCO}[ Espacio en Disco ]${NC}"
    df -h -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | sed 's/^/  /'

    echo -e "\n  ${BLANCO}[ Carga del Procesador ]${NC}"
    awk '{printf "    1 min: %s | 5 min: %s | 15 min: %s\n", $1, $2, $3}' /proc/loadavg 2>/dev/null || uptime

    echo -e "\n  ${BLANCO}[ Top 5 procesos por consumo de recursos ]${NC}"
    ps aux --sort=-%cpu 2>/dev/null | head -6 | awk 'NR==1{printf "  %-10s %-6s %-6s %s\n","USER","CPU%","MEM%","COMMAND"} NR>1{printf "  %-10s %-6s %-6s %s\n",$1,$3,$4,$11}'

    separador
    log "INFO: Se consultó el estado del sistema."
}

# ==============================================================================
# 2. ESTADO DE SERVICIOS
# ==============================================================================
estado_servicios() {
    limpiar
    titulo "ESTADO DE TODOS LOS SERVICIOS DEL STACK"

    echo -e "\n  ${BLANCO}── Servicios Wazuh (local o VM ${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP}) ──${NC}"
    if ! cargar_estado_vm 2>/dev/null; then
        info "VM ${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP}: sin acceso SSH (falta clave o WAZUH_VM_SSH_PASS en runtime)."
    fi
    check_servicio_wazuh "Wazuh Manager"              "wazuh-manager"
    check_servicio_wazuh "Wazuh Indexer"              "wazuh-indexer"
    check_servicio_wazuh "Wazuh Dashboard"            "wazuh-dashboard"
    check_servicio "Wazuh Agent"                      "wazuh-agent.service"
    check_servicio_wazuh "Filebeat"                   "filebeat"

    echo -e "\n  ${BLANCO}── Servicios WAHA / Relay (systemd) ──${NC}"
    check_servicio "Relay Wazuh-WAHA"            "wazuh-waha.service"
    check_servicio "Watchdog Sesión WAHA"        "wazuh-waha-watchdog.timer"
    check_servicio "Monitor IP Manager"          "watch_manager_ip.timer"
    check_servicio "Boot Notify"                 "wazuh-waha-boot-notify.timer"
    check_servicio "Health-Check Agente"         "wazuh-agent-health.timer"

    echo -e "\n  ${BLANCO}── Contenedores Docker ──${NC}"
    if [ ${#DOCKER_CTX_ARGS[@]} -gt 0 ]; then
        info "Contexto Docker en uso: ${DOCKER_CTX_ARGS[*]}"
    fi
    check_docker_container "WAHA (WhatsApp API)"     "wazuh-waha"
    check_docker_container "Dashboard Web (Nginx)"   "wazuh-waha-dashboard"

    echo -e "\n  ${BLANCO}── Conectividad y Puertos de Red ──${NC}"
    # Relay HTTP
    printf "  %-40s" "• Relay HTTP (:8765)"
    if curl -sS -m 3 "$RELAY_HOST/health" >/dev/null 2>&1; then
        echo -e "${VERDE}[RESPONDIENDO]${NC}"
    else
        echo -e "${ROJO}[SIN RESPUESTA]${NC}"
    fi

    # WAHA API
    printf "  %-40s" "• WAHA API (:3001)"
    if curl -sS -m 3 -H "X-Api-Key: ${WAHA_API_KEY:-nokey}" "$WAHA_HOST/api/server/version" >/dev/null 2>&1; then
        echo -e "${VERDE}[RESPONDIENDO]${NC}"
    else
        echo -e "${ROJO}[SIN RESPUESTA]${NC}"
    fi

    # Dashboard Web HTTP :8001
    printf "  %-40s" "• Dashboard Web (:8001)"
    if curl -sS -m 3 "http://localhost:8001/" >/dev/null 2>&1; then
        echo -e "${VERDE}[DISPONIBLE]${NC}"
    else
        echo -e "${ROJO}[SIN RESPUESTA]${NC}"
    fi

    # Wazuh API :55000
    printf "  %-40s" "• Wazuh API (:${WAZUH_MANAGER_API_PORT})"
    if timeout 2 bash -c "exec 3<>/dev/tcp/$WAZUH_SERVER_IP/$WAZUH_MANAGER_API_PORT" 2>/dev/null; then
        echo -e "${VERDE}[PUERTO ABIERTO]${NC}"
    else
        echo -e "${ROJO}[PUERTO CERRADO]${NC}"
    fi

    # Manager Agentes TCP :1514
    printf "  %-40s" "• Manager Agentes TCP (:1514)"
    if timeout 2 bash -c "exec 3<>/dev/tcp/$WAZUH_SERVER_IP/1514" 2>/dev/null; then
        echo -e "${VERDE}[PUERTO ABIERTO]${NC}"
    else
        echo -e "${ROJO}[PUERTO CERRADO]${NC}"
    fi

    separador
    log "INFO: Se verificó el estado de los servicios."
}

# ==============================================================================
# 3. DIAGNÓSTICO COMPLETO DEL STACK
# ==============================================================================
diagnostico() {
    limpiar
    titulo "DIAGNÓSTICO COMPLETO DEL STACK WAZUH-WAHA"
    echo -e "  ${GRIS}Ejecutando pruebas de conectividad y salud...${NC}\n"

    # 1. WAHA Docker
    echo -e "  ${AMARILLO}▸ 1/8 Contenedor WAHA en Docker${NC}"
    if docker ps --filter "name=wazuh-waha" --format "{{.Names}}" 2>/dev/null | grep -q waha; then
        ok "Contenedor WAHA activo y corriendo"
    else
        fail "Contenedor WAHA detenido o no existe"
    fi

    # 2. WAHA Session
    echo -e "\n  ${AMARILLO}▸ 2/8 Sesión WhatsApp (WAHA)${NC}"
    local session_status
    session_status=$(curl -sS -m 5 -H "X-Api-Key: ${WAHA_API_KEY:-}" "$WAHA_HOST/api/sessions/default" 2>/dev/null | grep -o '"status":"[^"]*' | cut -d'"' -f4)
    if [ "$session_status" = "WORKING" ]; then
        ok "Sesión WhatsApp operativa: ${VERDE}WORKING${NC}"
    elif [ "$session_status" = "SCAN_QR_CODE" ]; then
        warn "Sesión WhatsApp requiere escaneo de código QR: ${AMARILLO}SCAN_QR_CODE${NC}"
    else
        warn "Sesión WhatsApp: ${session_status:-Desconocida / Sin respuesta}"
    fi

    # 3. Relay HTTP
    echo -e "\n  ${AMARILLO}▸ 3/8 Endpoint de Salud del Relay (:8765)${NC}"
    local relay_health
    relay_health=$(curl -sS -m 5 "$RELAY_HOST/health" 2>/dev/null)
    if [ -n "$relay_health" ]; then
        ok "Relay respondió: $relay_health"
    else
        fail "Relay no respondió en $RELAY_HOST/health"
    fi

    # 4. Relay systemd
    echo -e "\n  ${AMARILLO}▸ 4/8 Demonio Relay (systemd)${NC}"
    systemctl status wazuh-waha --no-pager 2>&1 | head -6 | sed 's/^/    /'

    # 5. Agente Wazuh local
    echo -e "\n  ${AMARILLO}▸ 5/8 Agente Wazuh Local${NC}"
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        ok "Servicio wazuh-agent activo"
        local ESTAB
        ESTAB=$(ss -tnp 2>/dev/null | grep -E ":1514\b" | grep "ESTAB" || true)
        if [ -n "$ESTAB" ]; then
            ok "Conexión activa al Manager en puerto 1514 (ESTAB)"
        else
            fail "Sin conexión establecida al Manager en puerto 1514"
        fi
    else
        warn "wazuh-agent local no activo o no instalado en este host"
    fi

    # 6. Wazuh Manager API
    echo -e "\n  ${AMARILLO}▸ 6/8 API del Manager Wazuh (:55000)${NC}"
    local token
    token=$(obtener_wazuh_token)
    if [ -n "$token" ]; then
        ok "Autenticación exitosa en Wazuh API (Token obtenido)"
    else
        fail "Fallo al autenticar contra Wazuh API (Verificar WAZUH_SERVER_IP y WAZUH_MANAGER_API_PASS)"
    fi

    # 7. Dashboard Nginx
    echo -e "\n  ${AMARILLO}▸ 7/8 Dashboard SOC Web (:8001)${NC}"
    if curl -s -m 3 "http://localhost:8001/" | grep -qi "Wazuh"; then
        ok "Dashboard Web sirviendo interfaz correctamente en http://localhost:8001"
    else
        fail "Dashboard Web no accesible en puerto 8001"
    fi

    # 8. Script de diagnóstico heredado si existe
    echo -e "\n  ${AMARILLO}▸ 8/8 Script de Diagnóstico del Proyecto${NC}"
    if [ -x "$PROJECT_ROOT/scripts/diagnose.sh" ]; then
        bash "$PROJECT_ROOT/scripts/diagnose.sh" 2>/dev/null | head -15 | sed 's/^/    /'
        ok "diagnose.sh ejecutado"
    else
        info "diagnose.sh no ejecutable directamente"
    fi

    separador
    log "DIAGNOSTICO: Se ejecutó diagnóstico completo del stack."
}

# ==============================================================================
# 4. VISOR DE LOGS
# ==============================================================================
ver_logs() {
    limpiar
    titulo "VISOR DE LOGS EN TIEMPO REAL"
    echo -e "  ${AMARILLO}1)${NC} Logs de Contenedores Docker (WAHA + Dashboard)"
    echo -e "  ${AMARILLO}2)${NC} Logs del Relay Daemon (journalctl -u wazuh-waha)"
    echo -e "  ${AMARILLO}3)${NC} Logs del Agente Wazuh (/var/ossec/logs/ossec.log)"
    echo -e "  ${AMARILLO}4)${NC} Logs del Wazuh Manager"
    echo -e "  ${AMARILLO}5)${NC} Logs combinados (Docker + Relay)"
    echo -e "  ${AMARILLO}6)${NC} Explorar registros de alertas guardadas (backups/*.jsonl)"
    echo -e "  ${ROJO}7)${NC} Volver al menú principal"
    separador
    read -rp "  Seleccione [1-7]: " sub

    case $sub in
        1)
            echo -e "\n  ${CYAN}Mostrando logs de Docker... (Presione Ctrl+C para salir)${NC}\n"
            (cd "$PROJECT_ROOT" && docker compose logs -f --tail=30) 2>&1
            ;;
        2)
            echo -e "\n  ${CYAN}Mostrando logs del Relay... (Presione Ctrl+C para salir)${NC}\n"
            journalctl -u wazuh-waha -f -n 30 2>&1
            ;;
        3)
            echo -e "\n  ${CYAN}Mostrando logs del Agente Wazuh... (Presione Ctrl+C para salir)${NC}\n"
            sudo tail -f /var/ossec/logs/ossec.log 2>/dev/null || journalctl -u wazuh-agent -f -n 30
            ;;
        4)
            echo -e "\n  ${CYAN}Mostrando logs del Wazuh Manager... (Presione Ctrl+C para salir)${NC}\n"
            sudo tail -f /var/ossec/logs/ossec.log 2>/dev/null || warn "No se encontró ossec.log del Manager"
            ;;
        5)
            echo -e "\n  ${CYAN}Mostrando logs combinados... (Presione Ctrl+C para salir)${NC}\n"
            (cd "$PROJECT_ROOT" && docker compose logs -f --tail=15) &
            DOCKER_PID=$!
            journalctl -u wazuh-waha -f -n 15 &
            RELAY_PID=$!
            trap "kill $DOCKER_PID $RELAY_PID 2>/dev/null; trap - SIGINT SIGTERM" SIGINT SIGTERM
            wait
            ;;
        6)
            echo -e "\n  ${BLANCO}Archivos de alertas en $BACKUP_DIR:${NC}\n"
            if [ -d "$BACKUP_DIR" ] && compgen -G "$BACKUP_DIR/*.jsonl" > /dev/null 2>&1; then
                ls -lh "$BACKUP_DIR"/*.jsonl 2>/dev/null | awk '{printf "    %-45s %6s  %s %s %s\n", $9, $5, $6, $7, $8}'
                echo ""
                read -rp "  ¿Desea ver las últimas 20 alertas del archivo más reciente? (s/n): " ver
                if [ "$ver" = "s" ] || [ "$ver" = "S" ]; then
                    local ultimo
                    ultimo=$(ls -t "$BACKUP_DIR"/*.jsonl 2>/dev/null | head -1)
                    echo -e "\n  ${CYAN}Archivo: $ultimo${NC}\n"
                    tail -n 20 "$ultimo" | jq . 2>/dev/null || tail -n 20 "$ultimo"
                fi
            else
                warn "No se encontraron archivos de alertas .jsonl en $BACKUP_DIR"
            fi
            pausar
            return
            ;;
        7) return ;;
        *) fail "Opción no válida"; sleep 1; return ;;
    esac
    log "LOGS: Se consultaron logs (opción $sub)."
}

# ==============================================================================
# 5. GESTIÓN Y DESPLIEGUE DE AGENTES WAZUH
# ==============================================================================
menu_agentes() {
    limpiar
    titulo "GESTIÓN Y DESPLIEGUE DE AGENTES WAZUH"
    echo -e "  ${AMARILLO}1)${NC} Listar agentes registrados en vivo (Estado, IP, SO)"
    echo -e "  ${AMARILLO}2)${NC} Asistente: Generar comando de despliegue de 1 línea (Linux/Win/Mac)"
    echo -e "  ${AMARILLO}3)${NC} Pre-registrar nuevo agente en el Manager vía API"
    echo -e "  ${AMARILLO}4)${NC} Eliminar agente del Manager por ID"
    echo -e "  ${ROJO}5)${NC} Volver al menú principal"
    separador
    read -rp "  Seleccione [1-5]: " opc_ag

    case $opc_ag in
        1)
            info "Consultando agentes en Wazuh Manager API..."
            local token
            token=$(obtener_wazuh_token)
            if [ -z "$token" ]; then
                fail "No se pudo obtener token de la API de Wazuh"
                pausar; return
            fi

            local res
            res=$(curl -k -s -m 10 -H "Authorization: Bearer $token" \
                "https://${WAZUH_SERVER_IP}:${WAZUH_MANAGER_API_PORT}/agents" 2>/dev/null)

            echo ""
            printf "  %-6s %-24s %-16s %-24s %-14s\n" "ID" "NOMBRE" "IP" "SISTEMA OPERATIVO" "ESTADO"
            echo "  -------------------------------------------------------------------------------------"

            # Parsear agentes con python3
            python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    items = data.get("data", {}).get("affected_items", [])
    for a in items:
        aid = a.get("id", "-")
        name = a.get("name", "-")
        ip = a.get("ip", "any")
        os_info = a.get("os", {}).get("name", "")
        status = a.get("status", "disconnected")
        color_status = "\033[0;32m[ACTIVO]\033[0m" if status == "active" else "\033[0;31m[DESCONECTADO]\033[0m"
        print(f"  {aid:<6} {name:<24} {ip:<16} {os_info:<24} {color_status}")
except Exception as e:
    print(f"  Error parseando agentes: {e}")
' "$res"
            echo ""
            log "AGENTES: Se listaron los agentes registrados."
            pausar
            ;;

        2)
            limpiar
            titulo "ASISTENTE DE DESPLIEGUE E INSTALACIÓN DE AGENTES"
            echo -e "  Seleccione el Sistema Operativo del cliente a monitorear:"
            echo -e "    ${AMARILLO}1)${NC} 🐧 Linux (Debian / Ubuntu / Kali / Mint)"
            echo -e "    ${AMARILLO}2)${NC} 🏔️ Linux (Arch Linux / Manjaro / EndeavourOS)"
            echo -e "    ${AMARILLO}3)${NC} 🎩 Linux (RHEL / CentOS / Rocky / Fedora)"
            echo -e "    ${AMARILLO}4)${NC} 🪟 Windows (PowerShell como Administrador)"
            echo -e "    ${AMARILLO}5)${NC} 🍎 macOS (Intel / Apple Silicon)"
            echo -e "    ${ROJO}6)${NC} Cancelar"
            separador
            read -rp "  Seleccione [1-6]: " sos
            if [ "$sos" = "6" ]; then return; fi

            echo ""
            read -rp "  Nombre para el agente (opcional, ej. server-bd-01): " AG_NAME
            read -rp "  IP del Wazuh Manager [Default: $WAZUH_SERVER_IP]: " AG_MGR_IP
            AG_MGR_IP="${AG_MGR_IP:-$WAZUH_SERVER_IP}"

            local NAME_ARG=""
            if [ -n "$AG_NAME" ]; then
                NAME_ARG="WAZUH_AGENT_NAME=\"$AG_NAME\" "
            fi

            echo ""
            echo -e "${VERDE}══════════════════════════════════════════════════════════════════════${NC}"
            echo -e "${BLANCO}  COPIE Y PEGUE ESTE COMANDO EN EL CLIENTE (${AG_MGR_IP}):${NC}"
            echo -e "${VERDE}══════════════════════════════════════════════════════════════════════${NC}"

            case $sos in
                1)
                    echo -e "\n${CYAN}curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg && echo \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\" | tee -a /etc/apt/sources.list.d/wazuh.list && apt-get update && WAZUH_MANAGER=\"${AG_MGR_IP}\" ${NAME_ARG}apt-get install -y wazuh-agent && systemctl daemon-reload && systemctl enable --now wazuh-agent${NC}\n"
                    ;;
                2)
                    echo -e "\n${CYAN}curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --import && sudo WAZUH_MANAGER=\"${AG_MGR_IP}\" ${NAME_ARG}pacman -U --noconfirm https://packages.wazuh.com/4.x/pacman/wazuh-agent-4.9.0-1-x86_64.pkg.tar.zst && sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent${NC}\n"
                    ;;
                3)
                    echo -e "\n${CYAN}rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && WAZUH_MANAGER=\"${AG_MGR_IP}\" ${NAME_ARG}yum install -y https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm && systemctl daemon-reload && systemctl enable --now wazuh-agent${NC}\n"
                    ;;
                4)
                    echo -e "\n${CYAN}Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi -OutFile \${env:tmp}\\wazuh-agent.msi; msiexec.exe /i \${env:tmp}\\wazuh-agent.msi /q WAZUH_MANAGER=\"${AG_MGR_IP}\" WAZUH_REGISTRATION_SERVER=\"${AG_MGR_IP}\" ${NAME_ARG}; NET START Wazuh${NC}\n"
                    ;;
                5)
                    echo -e "\n${CYAN}curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/mac/wazuh-agent-4.9.0-1.pkg && sudo WAZUH_MANAGER=\"${AG_MGR_IP}\" ${NAME_ARG}installer -pkg wazuh-agent.pkg -target / && sudo /Library/Ossec/bin/wazuh-control start${NC}\n"
                    ;;
            esac
            log "AGENTES: Se generó comando de despliegue para SO opción $sos."
            pausar
            ;;

        3)
            echo ""
            read -rp "  Nombre único del nuevo agente (obligatorio): " NEW_AG_NAME
            if [ -z "$NEW_AG_NAME" ]; then
                fail "El nombre del agente es obligatorio"
                pausar; return
            fi
            read -rp "  IP del endpoint [Default: any]: " NEW_AG_IP
            NEW_AG_IP="${NEW_AG_IP:-any}"

            local token
            token=$(obtener_wazuh_token)
            if [ -z "$token" ]; then
                fail "No se pudo obtener token de autenticación Wazuh"
                pausar; return
            fi

            local res
            res=$(curl -k -s -X POST -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
                -d "{\"name\":\"$NEW_AG_NAME\",\"ip\":\"$NEW_AG_IP\"}" \
                "https://${WAZUH_SERVER_IP}:${WAZUH_MANAGER_API_PORT}/agents" 2>/dev/null)

            if echo "$res" | grep -q '"id"'; then
                local aid akey
                aid=$(echo "$res" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
                akey=$(echo "$res" | grep -o '"key":"[^"]*' | cut -d'"' -f4)
                ok "¡Agente registrado exitosamente!"
                echo -e "    ${BLANCO}ID del Agente :${NC} ${VERDE}$aid${NC}"
                echo -e "    ${BLANCO}Clave de Auth :${NC} ${CYAN}$akey${NC}"
                log "AGENTES: Pre-registrado agente '$NEW_AG_NAME' con ID $aid."
            else
                fail "Error al registrar agente: $res"
            fi
            pausar
            ;;

        4)
            echo ""
            read -rp "  ID del agente a eliminar de Wazuh: " DEL_ID
            if [ -z "$DEL_ID" ] || [ "$DEL_ID" = "000" ]; then
                fail "ID inválido o protegido (el agente 000 es el Manager local)"
                pausar; return
            fi

            read -rp "  ¿Confirmas eliminar permanentemente el agente $DEL_ID? (s/n): " conf_del
            if [ "$conf_del" != "s" ] && [ "$conf_del" != "S" ]; then
                info "Operación cancelada."
                pausar; return
            fi

            local token
            token=$(obtener_wazuh_token)
            local del_res
            del_res=$(curl -k -s -X DELETE -H "Authorization: Bearer $token" \
                "https://${WAZUH_SERVER_IP}:${WAZUH_MANAGER_API_PORT}/agents?agents_list=$DEL_ID" 2>/dev/null)

            if echo "$del_res" | grep -q '"affected_items"'; then
                ok "Agente $DEL_ID eliminado del Wazuh Manager."
                log "AGENTES: Agente $DEL_ID eliminado de Wazuh."
            else
                fail "Fallo al eliminar agente: $del_res"
            fi
            pausar
            ;;
        5) return ;;
        *) fail "Opción no válida"; sleep 1 ;;
    esac
}

# ==============================================================================
# 6. CONTROL DE MÓDULOS DE SEGURIDAD WAZUH
# ==============================================================================
menu_modulos_seguridad() {
    limpiar
    titulo "CONTROL DE MÓDULOS DE SEGURIDAD WAZUH"
    echo -e "  Gestión de los 5 pilares de detección en agent.conf centralizado:"
    echo -e "    • 1. Evaluación de la Configuración (SCA)"
    echo -e "    • 2. Detección de Malware (Rootcheck / Syscheck)"
    echo -e "    • 3. Monitoreo de Integridad de Archivos (FIM)"
    echo -e "    • 4. Caza de Amenazas (Threat Hunting / Log Analysis)"
    echo -e "    • 5. Detección de Vulnerabilidades"
    separador

    echo -e "  ${AMARILLO}1)${NC} Consultar estado actual de los módulos en la flota"
    echo -e "  ${AMARILLO}2)${NC} Activar o Desactivar un módulo específico"
    echo -e "  ${AMARILLO}3)${NC} Activar TODOS los módulos de seguridad"
    echo -e "  ${AMARILLO}4)${NC} Desactivar TODOS los módulos de seguridad"
    echo -e "  ${AMARILLO}5)${NC} Enviar orden de reinicio inmediato a los agentes"
    echo -e "  ${ROJO}6)${NC} Volver al menú principal"
    separador
    read -rp "  Seleccione [1-6]: " opc_mod

    local RELAY_AUTH_HEADER=()
    if [ -n "$RELAY_API_KEY" ]; then
        RELAY_AUTH_HEADER=(-H "X-Api-Key: $RELAY_API_KEY")
    fi

    case $opc_mod in
        1)
            info "Consultando configuración de módulos vía Relay API..."
            local c_res
            c_res=$(curl -s -m 8 "${RELAY_AUTH_HEADER[@]}" "$RELAY_HOST/api/v1/dashboard/wazuh/modules/config" 2>/dev/null)
            if echo "$c_res" | grep -q '"modules_config"'; then
                echo ""
                python3 -c '
import sys, json
try:
    d = json.loads(sys.argv[1])
    cfg = d.get("modules_config", {}).get("global", {})
    names = {
        "sca": "1. Evaluación de la Configuración (SCA)",
        "rootcheck": "2. Detección de Malware (Rootcheck)",
        "syscheck": "3. Monitoreo de Integridad (FIM)",
        "threat_hunting": "4. Caza de Amenazas (Threat Hunting)",
        "vulnerability_detector": "5. Detección de Vulnerabilidades"
    }
    print("  ESTADO DE LOS MÓDULOS DE SEGURIDAD (Alcance: Global):")
    print("  -------------------------------------------------------------")
    for k, label in names.items():
        val = cfg.get(k, True)
        tag = "\033[0;32m[ACTIVADO]\033[0m" if val else "\033[0;31m[DESACTIVADO]\033[0m"
        print(f"  {label:<48} {tag}")
except Exception as e:
    print(f"Error procesando estado: {e}")
' "$c_res"
            else
                warn "No se pudo obtener el estado desde el Relay. Verificando conectividad con $RELAY_HOST..."
            fi
            pausar
            ;;

        2)
            echo ""
            echo -e "  Seleccione el módulo a modificar:"
            echo -e "    ${AMARILLO}1)${NC} sca                    (Evaluación de la Configuración)"
            echo -e "    ${AMARILLO}2)${NC} rootcheck              (Detección de Malware)"
            echo -e "    ${AMARILLO}3)${NC} syscheck               (Monitoreo de Integridad FIM)"
            echo -e "    ${AMARILLO}4)${NC} threat_hunting         (Caza de Amenazas)"
            echo -e "    ${AMARILLO}5)${NC} vulnerability_detector (Detección de Vulnerabilidades)"
            read -rp "  Módulo [1-5]: " m_sel

            local MOD_KEY=""
            case $m_sel in
                1) MOD_KEY="sca" ;;
                2) MOD_KEY="rootcheck" ;;
                3) MOD_KEY="syscheck" ;;
                4) MOD_KEY="threat_hunting" ;;
                5) MOD_KEY="vulnerability_detector" ;;
                *) fail "Selección inválida"; pausar; return ;;
            esac

            echo ""
            echo -e "  Acción:"
            echo -e "    ${VERDE}1)${NC} Activar"
            echo -e "    ${ROJO}2)${NC} Desactivar"
            read -rp "  Acción [1-2]: " a_sel

            local VAL_BOOL="true"
            if [ "$a_sel" = "2" ]; then VAL_BOOL="false"; fi

            info "Aplicando cambio en agent.conf..."
            local p_res
            p_res=$(curl -s -m 12 -X POST "${RELAY_AUTH_HEADER[@]}" -H "Content-Type: application/json" \
                -d "{\"module\":\"$MOD_KEY\",\"enabled\":$VAL_BOOL,\"scope\":\"global\"}" \
                "$RELAY_HOST/api/v1/dashboard/wazuh/modules/toggle" 2>/dev/null)

            if echo "$p_res" | grep -q '"ok":true'; then
                ok "Módulo $MOD_KEY actualizado a $VAL_BOOL con reinicio de agentes."
                log "MODULOS: $MOD_KEY modificado a $VAL_BOOL (scope: global)."
            else
                fail "Fallo al actualizar módulo: $p_res"
            fi
            pausar
            ;;

        3|4)
            local SET_BOOL="true"
            if [ "$opc_mod" = "4" ]; then SET_BOOL="false"; fi

            info "Aplicando cambio masivo ($SET_BOOL) a todos los módulos..."
            local b_res
            b_res=$(curl -s -m 15 -X POST "${RELAY_AUTH_HEADER[@]}" -H "Content-Type: application/json" \
                -d "{\"scope\":\"global\",\"enabled\":$SET_BOOL}" \
                "$RELAY_HOST/api/v1/dashboard/wazuh/modules/bulk" 2>/dev/null)

            if echo "$b_res" | grep -q '"ok":true'; then
                ok "Todos los módulos fueron cambiados a: $SET_BOOL"
                log "MODULOS: Bulk toggle a $SET_BOOL completado."
            else
                fail "Error al aplicar cambios masivos: $b_res"
            fi
            pausar
            ;;

        5)
            info "Enviando orden de reinicio a todos los agentes..."
            local token
            token=$(obtener_wazuh_token)
            if [ -n "$token" ]; then
                local r_out
                r_out=$(curl -k -s -X PUT -H "Authorization: Bearer $token" \
                    "https://${WAZUH_SERVER_IP}:${WAZUH_MANAGER_API_PORT}/agents/restart" 2>/dev/null)
                ok "Orden de reinicio despachada al Manager."
                echo "    $r_out"
            else
                fail "No se pudo contactar al Manager Wazuh"
            fi
            pausar
            ;;
        6) return ;;
        *) fail "Opción inválida"; sleep 1 ;;
    esac
}

# ==============================================================================
# 7. WHATSAPP (WAHA) Y NOTIFICACIONES
# ==============================================================================
menu_notificaciones() {
    limpiar
    titulo "GESTIÓN DE WHATSAPP (WAHA) Y NOTIFICACIONES"
    echo -e "  ${AMARILLO}1)${NC} Ver estado detallado de la sesión WhatsApp"
    echo -e "  ${AMARILLO}2)${NC} Vincular WhatsApp (Mostrar Código QR en Terminal)"
    echo -e "  ${AMARILLO}3)${NC} Enviar mensaje de alerta simulado a WhatsApp"
    echo -e "  ${AMARILLO}4)${NC} Enviar correo de prueba (Google SMTP a $ADMIN_EMAIL)"
    echo -e "  ${AMARILLO}5)${NC} Iniciar / Reiniciar sesión WAHA"
    echo -e "  ${AMARILLO}6)${NC} Detener sesión WAHA"
    echo -e "  ${ROJO}7)${NC} Volver al menú principal"
    separador
    read -rp "  Seleccione [1-7]: " opc_not

    local RELAY_AUTH_HEADER=()
    if [ -n "$RELAY_API_KEY" ]; then
        RELAY_AUTH_HEADER=(-H "X-Api-Key: $RELAY_API_KEY")
    fi

    case $opc_not in
        1)
            info "Consultando sesión WAHA..."
            local s_info
            s_info=$(curl -sS -m 5 -H "X-Api-Key: ${WAHA_API_KEY:-}" "$WAHA_HOST/api/sessions/default" 2>/dev/null)
            echo ""
            if [ -n "$s_info" ]; then
                echo "$s_info" | jq . 2>/dev/null || echo "  $s_info"
            else
                fail "No se pudo contactar a WAHA en $WAHA_HOST"
            fi
            pausar
            ;;

        2)
            limpiar
            titulo "VINCULACIÓN DE WHATSAPP CON CÓDIGO QR"
            info "Consultando código QR de autenticación..."

            local qr_data
            qr_data=$(curl -s -m 8 "${RELAY_AUTH_HEADER[@]}" "$RELAY_HOST/api/v1/dashboard/waha/qr" 2>/dev/null)
            local raw_qr
            raw_qr=$(echo "$qr_data" | grep -o '"raw":"[^"]*' | cut -d'"' -f4)

            if [ -n "$raw_qr" ] && [ "$raw_qr" != "null" ]; then
                echo ""
                echo -e "  ${VERDE}Escanee el siguiente código QR con WhatsApp en su teléfono:${NC}"
                echo ""
                if command -v qrencode &>/dev/null; then
                    qrencode -t ANSI256 "$raw_qr"
                else
                    echo -e "  ${AMARILLO}[!] qrencode no está instalado para renderizar en terminal.${NC}"
                    echo -e "  Texto del QR: ${CYAN}$raw_qr${NC}"
                    echo -e "\n  También puedes escanearlo cómodamente abriendo el Dashboard:"
                    echo -e "  👉 ${BLANCO}http://${WAZUH_SERVER_IP}:8001/${NC}"
                fi
            else
                local status_msg
                status_msg=$(echo "$qr_data" | grep -o '"status":"[^"]*' | cut -d'"' -f4)
                if [ "$status_msg" = "WORKING" ]; then
                    ok "¡La sesión ya se encuentra VINCULADA y ACTIVA (WORKING)!"
                else
                    warn "WAHA no ha generado un QR nuevo en este momento (Estado: ${status_msg:-desconocido})."
                    echo "  Inicie la sesión primero (opción 5) si está detenida."
                fi
            fi
            pausar
            ;;

        3)
            echo ""
            read -rp "  Mensaje a enviar [Default: Alerta de prueba SOC]: " TXT_MSG
            TXT_MSG="${TXT_MSG:-🛡️ [Prueba Wazuh SOC] Notificación enviada desde el Administrador de Terminal.}"

            info "Despachando mensaje a través de WAHA..."
            local send_res
            send_res=$(curl -s -m 8 -X POST -H "X-Api-Key: ${WAHA_API_KEY:-}" -H "Content-Type: application/json" \
                -d "{\"chatId\":\"${WAHA_RECIPIENT:-}\",\"text\":\"$TXT_MSG\",\"session\":\"default\"}" \
                "$WAHA_HOST/api/sendText" 2>/dev/null)

            if echo "$send_res" | grep -q '"id"'; then
                ok "¡Mensaje despachado con éxito a ${WAHA_RECIPIENT}!"
                log "NOTIFICACION: Mensaje de WhatsApp enviado con éxito."
            else
                fail "Fallo al enviar mensaje: $send_res"
            fi
            pausar
            ;;

        4)
            echo ""
            local DEST_EMAIL="$ADMIN_EMAIL"
            read -rp "  Correo destinatario [Default: ${DEST_EMAIL:-josededios3030@gmail.com}]: " INPUT_MAIL
            DEST_EMAIL="${INPUT_MAIL:-${DEST_EMAIL:-josededios3030@gmail.com}}"

            info "Enviando correo de prueba a $DEST_EMAIL..."
            local mail_res
            mail_res=$(curl -s -m 15 -X POST "${RELAY_AUTH_HEADER[@]}" -H "Content-Type: application/json" \
                -d "{\"dest\":\"$DEST_EMAIL\"}" \
                "$RELAY_HOST/api/v1/dashboard/test-email" 2>/dev/null)

            if echo "$mail_res" | grep -q '"ok":true'; then
                ok "¡Correo de prueba enviado exitosamente a $DEST_EMAIL!"
                echo "    Respuesta: $mail_res"
                log "NOTIFICACION: Correo de prueba enviado a $DEST_EMAIL."
            else
                fail "Error al enviar correo de prueba: $mail_res"
            fi
            pausar
            ;;

        5)
            info "Iniciando / Reiniciando sesión WAHA..."
            curl -s -m 8 -X POST -H "X-Api-Key: ${WAHA_API_KEY:-}" "$WAHA_HOST/api/sessions/default/restart" 2>/dev/null || \
            curl -s -m 8 -X POST -H "X-Api-Key: ${WAHA_API_KEY:-}" "$WAHA_HOST/api/sessions/default/start" 2>/dev/null
            sleep 3
            ok "Orden de inicio enviada a WAHA."
            pausar
            ;;

        6)
            info "Deteniendo sesión WAHA..."
            curl -s -m 8 -X POST -H "X-Api-Key: ${WAHA_API_KEY:-}" "$WAHA_HOST/api/sessions/default/stop" 2>/dev/null
            ok "Sesión WAHA detenida."
            pausar
            ;;
        7) return ;;
        *) fail "Opción no válida"; sleep 1 ;;
    esac
}

# ==============================================================================
# 8. RESPALDOS AUTOMATIZADOS EN CARPETA 'backups/'
# ==============================================================================
realizar_backup() {
    limpiar
    titulo "GENERAR RESPALDO AUTOMATIZADO EN 'backups/'"

    local FECHA
    FECHA=$(date +"%Y-%m-%d_%H-%M-%S")
    mkdir -p "$BACKUP_DIR"

    info "Directorio de almacenamiento: ${AMARILLO}$BACKUP_DIR${NC}\n"

    echo -e "  Seleccione el tipo de respaldo:"
    echo -e "    ${AMARILLO}1)${NC} Proyecto completo comprimido (backup_proyecto_*.tar.gz)"
    echo -e "    ${AMARILLO}2)${NC} Configuraciones críticas (.env, docker-compose, scripts) (.tar.gz)"
    echo -e "    ${AMARILLO}3)${NC} Solo registros de alertas y logs (.tar.gz)"
    echo -e "    ${AMARILLO}4)${NC} Snapshot descomprimido en carpeta (backup_YYYY-MM-DD_HH-MM-SS/)"
    echo -e "    ${AMARILLO}5)${NC} Directorio personal completo (\$HOME)"
    echo -e "    ${AMARILLO}6)${NC} Sesión WAHA (volumen docker wazuh_waha_sessions)"
    echo -e "    ${ROJO}7)${NC} Cancelar"
    separador
    read -rp "  Seleccione [1-7]: " tipo

    local ARCHIVO=""
    case $tipo in
        1)
            ARCHIVO="$BACKUP_DIR/backup_proyecto_$FECHA.tar.gz"
            info "Generando respaldo completo del proyecto en: $ARCHIVO ..."
            tar -czf "$ARCHIVO" \
                --exclude="$BACKUP_DIR" \
                --exclude="$PROJECT_ROOT/.git" \
                --exclude="$PROJECT_ROOT/relay/.venv" \
                --exclude="$PROJECT_ROOT/dashboard/node_modules" \
                --exclude="$PROJECT_ROOT/dashboard/dist" \
                -C "$(dirname "$PROJECT_ROOT")" "$(basename "$PROJECT_ROOT")" 2>/dev/null
            ;;
        2)
            ARCHIVO="$BACKUP_DIR/backup_config_$FECHA.tar.gz"
            info "Generando respaldo de configuración en: $ARCHIVO ..."
            tar -czf "$ARCHIVO" \
                -C "$PROJECT_ROOT" \
                .env docker-compose.yml scripts/ deploy/ manager-side/ 2>/dev/null
            ;;
        3)
            ARCHIVO="$BACKUP_DIR/backup_alertas_$FECHA.tar.gz"
            info "Generando respaldo de alertas y logs en: $ARCHIVO ..."
            tar -czf "$ARCHIVO" \
                -C "$PROJECT_ROOT" \
                backups/*.jsonl logs/ 2>/dev/null
            ;;
        4)
            local DEST_FOLDER="$BACKUP_DIR/backup_$FECHA"
            info "Creando snapshot descomprimido en: $DEST_FOLDER ..."
            mkdir -p "$DEST_FOLDER"
            cp -r "$PROJECT_ROOT/.env" "$DEST_FOLDER/" 2>/dev/null || true
            cp -r "$PROJECT_ROOT/docker-compose.yml" "$DEST_FOLDER/" 2>/dev/null || true
            cp -r "$PROJECT_ROOT/scripts" "$DEST_FOLDER/" 2>/dev/null || true
            cp -r "$PROJECT_ROOT/deploy" "$DEST_FOLDER/" 2>/dev/null || true
            cp -r "$PROJECT_ROOT/manager-side" "$DEST_FOLDER/" 2>/dev/null || true
            if compgen -G "$BACKUP_DIR/*.jsonl" > /dev/null 2>&1; then
                mkdir -p "$DEST_FOLDER/alertas"
                cp "$BACKUP_DIR"/*.jsonl "$DEST_FOLDER/alertas/" 2>/dev/null || true
            fi
            ok "¡Snapshot generado exitosamente en carpeta $DEST_FOLDER!"
            log "BACKUP: Generado snapshot en carpeta $DEST_FOLDER"
            pausar; return
            ;;
        5)
            ARCHIVO="$BACKUP_DIR/backup_home_$FECHA.tar.gz"
            info "Generando respaldo del directorio personal en: $ARCHIVO ..."
            tar -czf "$ARCHIVO" \
                --exclude="$BACKUP_DIR" \
                --exclude="$HOME/.cache" \
                --exclude="$HOME/.docker" \
                "$HOME" 2>/dev/null
            ;;
        6)
            ARCHIVO="$BACKUP_DIR/waha_sessions_$FECHA.tar.gz"
            detectar_docker_contexto
            local vol_size
            vol_size=$(docker exec wazuh-waha du -sh /app/.sessions 2>/dev/null | cut -f1)
            info "Respaldando volumen wazuh_waha_sessions (${vol_size:-2 GB}) → $(basename "$ARCHIVO")"
            info "Puede tardar varios minutos (los avisos 'file changed' de Chrome son normales)."
            # rc!=0 es esperado (sesiones en vivo); lo que importa es que el tar tenga datos
            docker exec wazuh-waha tar czf - -C /app/.sessions . > "$ARCHIVO" 2>/dev/null || true
            if [ ! -s "$ARCHIVO" ]; then
                rm -f "$ARCHIVO"
                docker run --rm -v wazuh_waha_sessions:/s:ro -v "$BACKUP_DIR":/b alpine \
                    tar czf "/b/waha_sessions_$FECHA.tar.gz" -C /s . 2>/dev/null || true
            fi
            if [ ! -s "$ARCHIVO" ]; then
                rm -f "$ARCHIVO"
                fail "No se pudo respaldar el volumen de sesión WAHA (contenedor o docker caído)."
                log "ERROR: Falla al respaldar la sesión WAHA (volumen wazuh_waha_sessions)"
                pausar
                return
            fi
            ;;
        7) return ;;
        *) fail "Opción no válida"; sleep 1; return ;;
    esac

    if [ -f "$ARCHIVO" ]; then
        local TAMANO
        TAMANO=$(du -sh "$ARCHIVO" | cut -f1)
        echo ""
        ok "¡Respaldo completado exitosamente!"
        echo -e "    ${BLANCO}Ubicación :${NC} ${CYAN}$ARCHIVO${NC}"
        echo -e "    ${BLANCO}Tamaño    :${NC} ${VERDE}$TAMANO${NC}"
        log "BACKUP: Generado $ARCHIVO ($TAMANO)"
    else
        fail "Error al crear el respaldo en $ARCHIVO"
        log "ERROR: Falla al generar respaldo en $ARCHIVO"
    fi
    pausar
}

# ==============================================================================
# 9. LISTAR Y EXPLORAR RESPALDOS EXISTENTES
# ==============================================================================
listar_backups() {
    limpiar
    titulo "HISTORIAL DE RESPALDOS EN CARPETA 'backups/'"

    if [ -d "$BACKUP_DIR" ]; then
        local TOTAL
        TOTAL=$(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.tar.gz" -o -name "*.jsonl" -o -type d ! -path "$BACKUP_DIR" \) 2>/dev/null | wc -l)
        if [ "$TOTAL" -gt 0 ]; then
            echo -e "  Ubicación: ${AMARILLO}$BACKUP_DIR${NC}\n"
            echo -e "  ${BLANCO}Archivos Comprimidos (.tar.gz):${NC}"
            ls -lh "$BACKUP_DIR"/*.tar.gz 2>/dev/null | awk '{printf "    %-52s %6s  %s %s %s\n", $9, $5, $6, $7, $8}' || echo "    (ninguno)"

            echo -e "\n  ${BLANCO}Snapshots en Subcarpetas:${NC}"
            find "$BACKUP_DIR" -maxdepth 1 -type d ! -path "$BACKUP_DIR" 2>/dev/null | while read -r d; do
                local dsize
                dsize=$(du -sh "$d" 2>/dev/null | cut -f1)
                printf "    %-52s %6s\n" "$d" "$dsize"
            done || echo "    (ninguna)"

            echo -e "\n  ${BLANCO}Archivos de Alertas Estructuradas (.jsonl):${NC}"
            ls -lh "$BACKUP_DIR"/*.jsonl 2>/dev/null | awk '{printf "    %-52s %6s  %s %s %s\n", $9, $5, $6, $7, $8}' || echo "    (ninguno)"

            local TOTAL_SIZE
            TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
            echo -e "\n  ${AMARILLO}Espacio total acumulado en backups:${NC} ${VERDE}$TOTAL_SIZE${NC}"
        else
            warn "No se encontraron respaldos en $BACKUP_DIR"
        fi
    else
        warn "La carpeta $BACKUP_DIR no existe"
    fi

    separador
    log "INFO: Se listaron los respaldos existentes."
    pausar
}

# ==============================================================================
# 10. LIMPIEZA Y MANTENIMIENTO DEL SERVIDOR
# ==============================================================================
limpieza() {
    limpiar
    titulo "LIMPIEZA DE REGISTROS Y MANTENIMIENTO"

    echo -e "  ${AMARILLO}1)${NC} Reducir journal de systemd (> 7 días)"
    echo -e "  ${AMARILLO}2)${NC} Limpiar caché e imágenes huérfanas de Docker (docker system prune)"
    echo -e "  ${AMARILLO}3)${NC} Limpiar paquetes obsoletos (apt autoremove / pacman -Sc / dnf clean)"
    echo -e "  ${AMARILLO}4)${NC} Purgar respaldos antiguos en backups/ (> 30 días)"
    echo -e "  ${AMARILLO}5)${NC} Ejecutar TODAS las acciones de limpieza recomendadas"
    echo -e "  ${ROJO}6)${NC} Cancelar"
    separador
    read -rp "  Seleccione [1-6]: " limp

    case $limp in
        1|5)
            info "Limpiando registros de journalctl mayores a 7 días..."
            sudo journalctl --vacuum-time=7d 2>/dev/null || true
            ;;&
        2|5)
            info "Limpiando caché y capas no utilizadas de Docker..."
            docker system prune -f 2>/dev/null || true
            ;;&
        3|5)
            info "Eliminando paquetes obsoletos y limpiando caché del gestor..."
            if command -v pacman >/dev/null 2>&1; then
                sudo pacman -Sc --noconfirm 2>/dev/null || true
            elif command -v apt-get >/dev/null 2>&1; then
                sudo apt-get autoremove -y -qq 2>/dev/null || true
                sudo apt-get clean -qq 2>/dev/null || true
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf clean all 2>/dev/null || true
            fi
            ;;&
        4|5)
            info "Buscando respaldos con más de 30 días en $BACKUP_DIR..."
            local eliminados
            eliminados=$(find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 2>/dev/null | wc -l)
            find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete 2>/dev/null || true
            ok "Se eliminaron $eliminados respaldos obsoletos."
            ;;&
        1|2|3|4|5)
            echo ""
            ok "Mantenimiento y limpieza finalizados."
            log "MANTENIMIENTO: Limpieza ejecutada (opción $limp)."
            ;;
        6) return ;;
        *) fail "Opción no válida"; sleep 1; return ;;
    esac
    pausar
}

# ==============================================================================
# 11. GESTIÓN DE SERVICIOS
# ==============================================================================
vista_estado_wazuh() {
    limpiar
    titulo "SERVICIOS WAZUH — LOCAL Y VM (${WAZUH_VM_SSH_USER:-root}@${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP})"
    if ! cargar_estado_vm 2>/dev/null; then
        warn "VM sin acceso SSH: configurar clave (ssh-copy-id) o WAZUH_VM_SSH_PASS en runtime."
    fi
    check_servicio_wazuh "Wazuh Manager"   "wazuh-manager"
    check_servicio_wazuh "Wazuh Indexer"   "wazuh-indexer"
    check_servicio_wazuh "Wazuh Dashboard" "wazuh-dashboard"
    check_servicio_wazuh "Filebeat"        "filebeat"
    check_servicio "Wazuh Agent (local)"   "wazuh-agent.service"
    local info_vm
    if info_vm=$(vm_ssh 'uptime -p; df -h / | tail -1' 2>/dev/null); then
        echo -e "\n  ${BLANCO}── VM ${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP} ──${NC}"
        echo "$info_vm" | sed 's/^/    /'
    fi
    separador
}

reiniciar_contenedor() {
    local cid="$1" nombre="$2"
    detectar_docker_contexto
    info "Reiniciando contenedor $nombre ($cid)..."
    if docker restart "$cid" >/dev/null 2>&1; then
        sleep 3
        check_docker_container "$nombre" "$cid"
    else
        fail "No se pudo reiniciar $cid (¿creado? docker compose up -d)"
    fi
}

gestionar_servicios() {
    limpiar
    titulo "CONTROL Y GESTIÓN DE SERVICIOS DEL STACK"

    echo -e "  ${AMARILLO} 1)${NC} Reiniciar Relay Daemon (wazuh-waha.service)"
    echo -e "  ${AMARILLO} 2)${NC} Reiniciar Agente Wazuh local"
    echo -e "  ${AMARILLO} 3)${NC} Reiniciar Wazuh Manager  ${GRIS}(local o VM, automático)${NC}"
    echo -e "  ${AMARILLO} 4)${NC} Reiniciar Wazuh Indexer  ${GRIS}(local o VM, automático)${NC}"
    echo -e "  ${AMARILLO} 5)${NC} Reiniciar Wazuh Dashboard ${GRIS}(local o VM, automático)${NC}"
    echo -e "  ${AMARILLO} 6)${NC} Estado de servicios Wazuh (local/VM + uptime y disco de la VM)"
    echo -e "  ${AMARILLO} 7)${NC} Reiniciar contenedor WAHA (docker)"
    echo -e "  ${AMARILLO} 8)${NC} Reiniciar contenedor Dashboard Web (docker)"
    echo -e "  ${AMARILLO} 9)${NC} Levantar Contenedores Docker (docker compose up -d)"
    echo -e "  ${AMARILLO}10)${NC} Detener Contenedores Docker (docker compose down)"
    echo -e "  ${AMARILLO}11)${NC} Reconstruir Dashboard Nginx (docker compose build dashboard)"
    echo -e "  ${AMARILLO}12)${NC} Alternar Timer de Watchdog WAHA (Habilitar / Deshabilitar)"
    echo -e "  ${AMARILLO}13)${NC} Alternar Monitor IP Manager"
    echo -e "  ${VERDE}14)${NC} ⚡ REINICIO MAESTRO DE TODO EL STACK"
    echo -e "  ${CYAN}15)${NC} 🚀 Desplegar / Sincronizar Servidor Completo (deploy-server.sh)"
    echo -e "  ${ROJO}16)${NC} Volver al menú principal"
    separador
    read -rp "  Seleccione [1-16]: " srv

    case $srv in
        1)
            info "Reiniciando Relay..."
            sudo systemctl restart wazuh-waha.service
            sleep 2
            check_servicio "Relay Wazuh-WAHA" "wazuh-waha.service"
            ;;
        2)
            info "Reiniciando Agente Wazuh..."
            sudo systemctl restart wazuh-agent.service 2>/dev/null || sudo /var/ossec/bin/wazuh-control restart 2>/dev/null
            sleep 2
            check_servicio "Agente Wazuh" "wazuh-agent.service"
            ;;
        3) wazuh_svc restart wazuh-manager.service "Wazuh Manager" ;;
        4) wazuh_svc restart wazuh-indexer.service "Wazuh Indexer" ;;
        5) wazuh_svc restart wazuh-dashboard.service "Wazuh Dashboard" ;;
        6) vista_estado_wazuh ;;
        7) reiniciar_contenedor "wazuh-waha" "WAHA (WhatsApp API)" ;;
        8) reiniciar_contenedor "wazuh-waha-dashboard" "Dashboard Web (Nginx)" ;;
        9)
            info "Levantando contenedores Docker..."
            detectar_docker_contexto
            (cd "$PROJECT_ROOT" && docker compose up -d)
            sleep 2
            docker compose -f "$PROJECT_ROOT/docker-compose.yml" ps 2>/dev/null
            ;;
        10)
            warn "¿Detener contenedores Docker de WAHA y Dashboard? (s/n): "
            read -rp "  Confirmar: " c_down
            if [ "$c_down" = "s" ] || [ "$c_down" = "S" ]; then
                detectar_docker_contexto
                (cd "$PROJECT_ROOT" && docker compose down)
            fi
            ;;
        11)
            info "Reconstruyendo Dashboard..."
            detectar_docker_contexto
            (cd "$PROJECT_ROOT" && docker compose build dashboard && docker compose up -d dashboard)
            ;;
        12)
            local st_wd
            st_wd=$(systemctl is-active wazuh-waha-watchdog.timer 2>/dev/null)
            if [ "$st_wd" = "active" ]; then
                info "Deshabilitando Watchdog WAHA..."
                sudo systemctl disable wazuh-waha-watchdog.timer --now
            else
                info "Habilitando Watchdog WAHA..."
                sudo systemctl enable wazuh-waha-watchdog.timer --now
            fi
            check_servicio "Watchdog WAHA" "wazuh-waha-watchdog.timer"
            ;;
        13)
            local st_wm
            st_wm=$(systemctl is-active watch_manager_ip.timer 2>/dev/null)
            if [ "$st_wm" = "active" ]; then
                info "Deshabilitando Monitor IP..."
                sudo systemctl disable watch_manager_ip.timer --now
            else
                info "Habilitando Monitor IP..."
                sudo systemctl enable watch_manager_ip.timer --now
            fi
            check_servicio "Monitor IP" "watch_manager_ip.timer"
            ;;
        14)
            warn "Esta acción reiniciará TODOS los servicios y contenedores."
            read -rp "  ¿Desea continuar con el Reinicio Maestro? (s/n): " c_rst
            if [ "$c_rst" = "s" ] || [ "$c_rst" = "S" ]; then
                info "Reiniciando servicios Wazuh (local o VM)..."
                wazuh_svc restart wazuh-manager.service  "Wazuh Manager"  --batch
                wazuh_svc restart wazuh-indexer.service  "Wazuh Indexer"  --batch
                wazuh_svc restart wazuh-dashboard.service "Wazuh Dashboard" --batch
                info "Reiniciando Agente y Filebeat locales..."
                sudo systemctl restart wazuh-agent.service 2>/dev/null || true
                sudo systemctl restart filebeat.service 2>/dev/null || true
                info "Reiniciando Relay..."
                sudo systemctl restart wazuh-waha.service 2>/dev/null || true
                info "Reiniciando Docker Compose..."
                detectar_docker_contexto
                (cd "$PROJECT_ROOT" && docker compose restart) 2>/dev/null || true
                sleep 3
                ok "¡Reinicio Maestro completado exitosamente!"
            fi
            ;;
        15)
            if [ -f "$PROJECT_ROOT/scripts/deploy-server.sh" ]; then
                sudo bash "$PROJECT_ROOT/scripts/deploy-server.sh"
            else
                fail "No se encontró $PROJECT_ROOT/scripts/deploy-server.sh"
            fi
            ;;
        16) return ;;
        *) fail "Opción no válida"; sleep 1 ;;
    esac
    log "SERVICIOS: Acción $srv ejecutada."
    pausar
}

# ==============================================================================
# 12. AUTO-DETECCIÓN Y RECONCILIACIÓN DE IP DEL MANAGER
# ==============================================================================
auto_setup_ip() {
    limpiar
    titulo "AUTO-CONFIGURACIÓN Y ESCANEO DE RED DE WAZUH MANAGER"

    if [ -x "$PROJECT_ROOT/scripts/auto-setup.sh" ]; then
        bash "$PROJECT_ROOT/scripts/auto-setup.sh"
    else
        echo -e "  ${AMARILLO}Escaneo de IP manual:${NC}"
        echo -e "  IP actual configurada: ${CYAN}$WAZUH_SERVER_IP${NC}"
        read -rp "  Ingrese la nueva IP para Wazuh Manager: " NEW_IP
        if [ -n "$NEW_IP" ]; then
            sed -i -E "s/^(WAZUH_SERVER_IP)=.*/\1=$NEW_IP/" "$ENV_FILE" 2>/dev/null || true
            ok "WAZUH_SERVER_IP actualizada a $NEW_IP en $ENV_FILE."
            WAZUH_SERVER_IP="$NEW_IP"
        fi
    fi
    log "RED: Auto-setup / Reconciliación de IP ejecutada."
    pausar
}

# ==============================================================================
# 13. AUDITORÍA DE SEGURIDAD
# ==============================================================================
verificar_seguridad() {
    limpiar
    titulo "VERIFICACIÓN DE SEGURIDAD Y AUDITORÍA DE ACCESOS"

    echo -e "  ${BLANCO}── Servicio SSH ──${NC}"
    check_servicio "OpenSSH Server" "ssh.service"
    echo -e "  ${AMARILLO}Puerto SSH en escucha:${NC}"
    ss -tlpn 2>/dev/null | grep ":22 " | sed 's/^/    /' || echo "    (puerto por defecto o no visible)"

    echo -e "\n  ${BLANCO}── Firewall UFW ──${NC}"
    local ESTADO_UFW
    ESTADO_UFW=$(sudo ufw status 2>/dev/null | head -1)
    info "Estado: ${AMARILLO}${ESTADO_UFW:-No disponible}${NC}"
    if echo "$ESTADO_UFW" | grep -qi "active"; then
        sudo ufw status numbered 2>/dev/null | sed 's/^/    /'
    fi

    echo -e "\n  ${BLANCO}── Últimos accesos exitosos por SSH (10) ──${NC}"
    sudo journalctl -u ssh --no-pager -n 10 2>/dev/null | grep "Accepted" | tail -10 | sed 's/^/    /' || echo "    (sin registros)"

    echo -e "\n  ${BLANCO}── Intentos de acceso fallidos recientes ──${NC}"
    sudo journalctl -u ssh --no-pager 2>/dev/null | grep -i "failed\|invalid" | tail -8 | sed 's/^/    /' || echo "    (ninguno detectado)"

    separador
    log "SEGURIDAD: Verificación de seguridad ejecutada."
    pausar
}

# ==============================================================================
# 14. INSTALACIÓN / ACTUALIZACIÓN DE HERRAMIENTAS
# ==============================================================================
instalar_herramientas() {
    limpiar
    titulo "INSTALACIÓN DE HERRAMIENTAS DE SOPORTE"

    local HERRAMIENTAS_DEB=("openssh-server" "htop" "curl" "net-tools" "ufw" "tree" "jq" "sshpass" "nmap" "qrencode")
    local HERRAMIENTAS_GEN=("openssh" "htop" "curl" "net-tools" "ufw" "tree" "jq" "sshpass" "nmap" "qrencode")
    local rc=0

    if command -v pacman >/dev/null 2>&1; then
        info "Gestor detectado: pacman (Arch) — sincronizando e instalando..."
        info "Paquetes: ${AMARILLO}${HERRAMIENTAS_GEN[*]}${NC}"
        sudo pacman -Sy --noconfirm --needed "${HERRAMIENTAS_GEN[@]}"
        rc=$?
    elif command -v apt-get >/dev/null 2>&1; then
        info "Gestor detectado: apt-get (Debian/Ubuntu) — sincronizando e instalando..."
        info "Paquetes: ${AMARILLO}${HERRAMIENTAS_DEB[*]}${NC}"
        sudo apt-get update -qq 2>/dev/null
        sudo apt-get install -y "${HERRAMIENTAS_DEB[@]}"
        rc=$?
    elif command -v dnf >/dev/null 2>&1; then
        info "Gestor detectado: dnf (RHEL/Fedora) — instalando..."
        info "Paquetes: ${AMARILLO}${HERRAMIENTAS_GEN[*]}${NC}"
        sudo dnf install -y "${HERRAMIENTAS_GEN[@]}"
        rc=$?
    else
        fail "Gestor de paquetes no reconocido (se esperaba pacman, apt-get o dnf)."
        pausar
        return
    fi

    if [ $rc -eq 0 ]; then
        ok "Todas las herramientas necesarias están operativas."
        log "INSTALACION: Herramientas instaladas correctamente."
    else
        warn "Algunos paquetes no pudieron instalarse automáticamente."
    fi
    pausar
}

# ==============================================================================
# 15. VER HISTORIAL DE AUDITORÍA
# ==============================================================================
ver_auditoria() {
    limpiar
    titulo "HISTORIAL DE ACCIONES DE ADMINISTRACIÓN"

    if [ -f "$ADMIN_LOG" ]; then
        info "Últimos registros en ${AMARILLO}$ADMIN_LOG${NC}:\n"
        tail -n 30 "$ADMIN_LOG" | sed 's/^/    /'
        echo -e "\n  ${GRIS}Total de eventos registrados: $(wc -l < "$ADMIN_LOG")${NC}"
    else
        warn "Aún no se han generado registros en $ADMIN_LOG"
    fi
    pausar
}

# ==============================================================================
# 16. EJECUTAR TODO EL MANTENIMIENTO
# ==============================================================================
ejecutar_todo() {
    limpiar
    echo -e "${MAGENTA}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLANCO}     EJECUCIÓN DE MANTENIMIENTO INTEGRAL DEL SISTEMA Y STACK          ${NC}"
    echo -e "${MAGENTA}══════════════════════════════════════════════════════════════════════${NC}"

    echo -e "\n${CYAN}>>> 1/5: INFORMACIÓN GENERAL DEL SERVIDOR <<<${NC}"
    info_sistema
    sleep 1

    echo -e "\n${CYAN}>>> 2/5: ESTADO DE SERVICIOS <<<${NC}"
    estado_servicios
    sleep 1

    echo -e "\n${CYAN}>>> 3/5: DIAGNÓSTICO PROFUNDO <<<${NC}"
    diagnostico
    sleep 1

    echo -e "\n${CYAN}>>> 4/5: GENERACIÓN DE RESPALDO AUTOMÁTICO EN 'backups/' <<<${NC}"
    local FECHA
    FECHA=$(date +"%Y-%m-%d_%H-%M-%S")
    local ARCHIVO="$BACKUP_DIR/backup_auto_$FECHA.tar.gz"
    tar -czf "$ARCHIVO" \
        --exclude="$BACKUP_DIR" \
        --exclude="$PROJECT_ROOT/.git" \
        --exclude="$PROJECT_ROOT/relay/.venv" \
        --exclude="$PROJECT_ROOT/dashboard/node_modules" \
        -C "$(dirname "$PROJECT_ROOT")" "$(basename "$PROJECT_ROOT")" 2>/dev/null
    if [ -f "$ARCHIVO" ]; then
        ok "Respaldo automático generado: $ARCHIVO ($(du -sh "$ARCHIVO" | cut -f1))"
    fi
    sleep 1

    echo -e "\n${CYAN}>>> 5/5: LIMPIEZA DE CACHÉ Y REGISTROS <<<${NC}"
    sudo journalctl --vacuum-time=7d 2>/dev/null || true
    docker system prune -f 2>/dev/null || true
    ok "Limpieza de mantenimiento completada."

    echo -e "\n${VERDE}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${VERDE}  [✓] ¡MANTENIMIENTO INTEGRAL COMPLETADO SATISFACTORIAMENTE!         ${NC}"
    echo -e "${VERDE}══════════════════════════════════════════════════════════════════════${NC}"
    log "MANTENIMIENTO: Ejecución completa finalizada con éxito."
    pausar
}

# ==============================================================================
# 17. VER CREDENCIALES DE ACCESO A WAZUH
# ==============================================================================
ver_credenciales() {
    limpiar
    titulo "CREDENCIALES DE ACCESO A WAZUH"

    warn "Se mostrará la contraseña de la API de Wazuh EN CLARO en la pantalla."
    read -rp "  ¿Desea continuar? (s/n): " c_sec
    if [ "$c_sec" != "s" ] && [ "$c_sec" != "S" ]; then
        info "Operación cancelada."
        log "CREDENCIALES: Visualización cancelada por el usuario."
        pausar
        return
    fi

    sec() {
        printf "  %-34s" "$1"
        if [ -n "$2" ]; then
            echo -e "${AMARILLO}$2${NC}"
        else
            echo -e "${GRIS}(no configurado)${NC}"
        fi
    }

    echo -e "\n  ${BLANCO}── Wazuh Manager API ──${NC}"
    sec "URL"                              "https://${WAZUH_SERVER_IP:-}:${WAZUH_MANAGER_API_PORT}"
    sec "Usuario"                          "${WAZUH_MANAGER_API_USER:-wazuh}"
    sec "Password"                         "${WAZUH_MANAGER_API_PASS:-}"

    echo -e "\n  ${BLANCO}── Servidor Wazuh (VM) por SSH ──${NC}"
    sec "Usuario@Host:Puerto"              "${WAZUH_VM_SSH_USER:-root}@${WAZUH_VM_SSH_HOST:-$WAZUH_SERVER_IP}:${WAZUH_VM_SSH_PORT:-22}"
    info "La contraseña SSH no está en el repo: se pide al conectarse (o use clave)."

    echo ""
    separador
    log "CREDENCIALES: Visualización de credenciales de Wazuh en pantalla."
    pausar
}

# ==============================================================================
# BUCLE DEL MENÚ PRINCIPAL
# ==============================================================================
while true; do
    limpiar
    echo -e "${AZUL}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${AZUL}║${NC}  ${BLANCO}    SISTEMA DE ADMINISTRACIÓN UNIFICADO - WAZUH WAHA${NC}              ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}    SOC Relay & Endpoint Security Control Panel${NC}                    ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${GRIS}    Host: $(hostname) | Manager: $WAZUH_SERVER_IP | $(date '+%d/%m/%Y %H:%M')${NC}   ${AZUL}║${NC}"
    echo -e "${AZUL}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${VERDE}── Configuración Rápida (1-Click Setup) ───────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${VERDE} 0)${NC} 🔑 Configurar / Sincronizar credenciales y reiniciar todo     ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}── Monitoreo y Diagnóstico ────────────────────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 1)${NC} Estado e información del sistema (CPU, RAM, Disco)           ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 2)${NC} Estado de TODOS los servicios (Wazuh, Docker, Relay)         ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 3)${NC} Diagnóstico completo del stack                               ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 4)${NC} Visor de logs en tiempo real                                 ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}── Gestión de Wazuh ───────────────────────────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 5)${NC} 🖥️  Gestión y Despliegue de Agentes (Comandos de 1 línea)     ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 6)${NC} 🎛️  Control de Módulos de Seguridad (SCA, Malware, FIM, Vuln)  ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}── Notificaciones y WhatsApp ──────────────────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 7)${NC} 📲 WhatsApp (WAHA) y Correo (Vincular QR, Pruebas de envío)   ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}── Respaldos y Mantenimiento ──────────────────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 8)${NC} 💾 Generar respaldo automatizado en 'backups/'                ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO} 9)${NC} 📂 Listar y explorar respaldos existentes en 'backups/'      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}10)${NC} 🧹 Limpieza y mantenimiento del servidor (Docker/Journal/Apt) ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}── Gestión de Infraestructura ─────────────────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}11)${NC} Gestionar servicios (iniciar/detener/reiniciar)              ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}12)${NC} Auto-detección y reconciliación de IP del Manager             ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}13)${NC} Verificación de seguridad (SSH, Firewall, accesos)           ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}14)${NC} Instalar / actualizar herramientas del sistema               ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}  ${CYAN}── Automatización y Auditoría ─────────────────────────────${NC}       ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}15)${NC} Ver historial de auditoría (admin-wazuh-waha.log)            ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${VERDE}16)${NC} ⚡ Ejecutar TODO el mantenimiento integral                    ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${AMARILLO}17)${NC} 🔑 Ver credenciales de acceso a Wazuh                     ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}   ${ROJO}18)${NC} Salir                                                         ${AZUL}║${NC}"
    echo -e "${AZUL}║${NC}                                                                      ${AZUL}║${NC}"
    echo -e "${AZUL}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    if ! read -rp "  Seleccione una opción [0-18]: " opcion; then
        echo -e "\n  ${VERDE}Saliendo del administrador. ¡Hasta pronto!${NC}\n"
        exit 0
    fi

    case $opcion in
        0)
            if [ -x "$PROJECT_ROOT/conectar.sh" ]; then
                bash "$PROJECT_ROOT/conectar.sh"
            else
                fail "No se encontró el script conectar.sh en $PROJECT_ROOT"
            fi
            pausar
            ;;
        1)  info_sistema;          pausar ;;
        2)  estado_servicios;      pausar ;;
        3)  diagnostico;           pausar ;;
        4)  ver_logs                      ;;
        5)  menu_agentes                  ;;
        6)  menu_modulos_seguridad         ;;
        7)  menu_notificaciones           ;;
        8)  realizar_backup               ;;
        9)  listar_backups                ;;
        10) limpieza                      ;;
        11) gestionar_servicios           ;;
        12) auto_setup_ip                 ;;
        13) verificar_seguridad           ;;
        14) instalar_herramientas         ;;
        15) ver_auditoria                 ;;
        16) ejecutar_todo                 ;;
        17) ver_credenciales              ;;
        18)
            echo -e "\n  ${VERDE}Saliendo del administrador. ¡Hasta pronto!${NC}\n"
            log "SESION: Salida del panel de administración."
            exit 0
            ;;
        *)
            echo -e "\n  ${ROJO}Opción no válida. Elija un número entre 0 y 18.${NC}"
            sleep 1.2
            ;;
    esac
done
