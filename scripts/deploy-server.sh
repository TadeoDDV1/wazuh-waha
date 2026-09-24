#!/bin/bash
# ==============================================================================
# deploy-server.sh - Despliegue, Actualización y Reinicio Maestro en Servidor
# ==============================================================================
# Diseñado para ejecutarse DIRECTAMENTE en el servidor (sin SSH, sin VM).
# - Carga de forma segura todas las claves de .env (sin fallar por espacios/comillas).
# - Sincroniza y sobrescribe /etc/wazuh-waha/relay.env.
# - Prepara o repara el virtualenv relay/.venv e instala dependencias.
# - Instala/sobrescribe wazuh-waha.service y directorios del sistema.
# - Integra directamente con Wazuh Manager local (/var/ossec):
#     * /var/ossec/integrations/custom/whatsapp_alert.py
#     * /var/ossec/etc/wsl-relay.conf (con RELAY_API_KEY y URL local)
#     * /var/ossec/etc/ossec.conf (inyección segura de bloque <integration>)
# - Sincroniza la API Key en dashboard/nginx.conf.
# - Reinicia wazuh-waha, wazuh-manager y los contenedores Docker.
# - Ejecuta verificación de salud y muestra estado en tiempo real.
# ==============================================================================

set -e

ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[1;33m'
CYAN='\033[0;36m'
BLANCO='\033[1;37m'
GRIS='\033[0;90m'
NC='\033[0m'

ok()   { echo -e "  ${VERDE}[✓]${NC} $1"; }
fail() { echo -e "  ${ROJO}[✗]${NC} $1"; }
warn() { echo -e "  ${AMARILLO}[!]${NC} $1"; }
info() { echo -e "  ${CYAN}[i]${NC} $1"; }

echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${BLANCO}  WAZUH-WAHA: Despliegue y Actualización Maestro de Servidor${NC}"
echo -e "${CYAN}======================================================================${NC}\n"

# 1. Verificar permisos de root / sudo
if [ "$(id -u)" -ne 0 ]; then
    fail "Este script requiere privilegios de superusuario para configurar systemd y /var/ossec."
    echo "  Por favor ejecútalo con: sudo bash $0"
    exit 1
fi

# 2. Rutas del proyecto y usuario real
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

REAL_USER="${SUDO_USER:-$USER}"
if [ -z "$REAL_USER" ] || [ "$REAL_USER" = "root" ]; then
    REAL_USER="root"
    REAL_GROUP="root"
else
    REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"
fi

info "Ruta del proyecto : ${BLANCO}$PROJECT_ROOT${NC}"
info "Usuario ejecutor  : ${BLANCO}$REAL_USER ($REAL_GROUP)${NC}"

# 3. Validar y leer .env con Python para evitar fallos de sintaxis/espacios en Bash
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$PROJECT_ROOT/.env.example" ]; then
        warn "No se encontró .env, copiando desde .env.example..."
        cp "$PROJECT_ROOT/.env.example" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        chown "$REAL_USER:$REAL_GROUP" "$ENV_FILE"
    else
        fail "No existe $ENV_FILE ni .env.example en $PROJECT_ROOT."
        exit 1
    fi
fi

echo -e "\n${BLANCO}── 1/7. Leyendo y validando variables de .env ──${NC}"

# Script auxiliar de python para extraer y validar variables de manera 100% segura
PARSED_ENV=$(python3 - <<EOF
import sys

env_file = "$ENV_FILE"
data = {}
try:
    with open(env_file, 'r', encoding='utf-8') as f:
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
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)

# Imprimir formato exportable seguro
for k, v in data.items():
    escaped = v.replace('\\\\', '\\\\\\\\').replace('"', '\\"')
    print(f'{k}="{escaped}"')
EOF
)

eval "$PARSED_ENV"

# Valores por defecto para variables críticas en servidor local
WAZUH_SERVER_IP="${WAZUH_SERVER_IP:-127.0.0.1}"
RELAY_PORT="${RELAY_PORT:-8765}"
RELAY_BIND="${RELAY_BIND:-0.0.0.0}"
RELAY_API_KEY="${RELAY_API_KEY:-}"
WAHA_API_KEY="${WAHA_API_KEY:-}"
WAHA_HOST="${WAHA_HOST:-http://localhost:3001}"
WAHA_SESSION="${WAHA_SESSION:-default}"
WAZUH_MANAGER_API_USER="${WAZUH_MANAGER_API_USER:-wazuh}"
WAZUH_MANAGER_API_PORT="${WAZUH_MANAGER_API_PORT:-55000}"
WAZUH_MANAGER_API_PASS="${WAZUH_MANAGER_API_PASS:-}"

# Si la RELAY_API_KEY está vacía, generar una segura
if [ -z "$RELAY_API_KEY" ] || [ "$RELAY_API_KEY" = "changeme" ]; then
    RELAY_API_KEY=$(openssl rand -hex 24 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 48)
    sed -i -E "s/^(RELAY_API_KEY)=.*/\1=$RELAY_API_KEY/" "$ENV_FILE" 2>/dev/null || echo "RELAY_API_KEY=$RELAY_API_KEY" >> "$ENV_FILE"
    ok "Nueva RELAY_API_KEY generada y guardada en .env"
fi

# Si la WAHA_API_KEY está vacía, generar una segura
if [ -z "$WAHA_API_KEY" ] || [ "$WAHA_API_KEY" = "changeme" ]; then
    WAHA_API_KEY=$(openssl rand -hex 24 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 48)
    sed -i -E "s/^(WAHA_API_KEY)=.*/\1=$WAHA_API_KEY/" "$ENV_FILE" 2>/dev/null || echo "WAHA_API_KEY=$WAHA_API_KEY" >> "$ENV_FILE"
    ok "Nueva WAHA_API_KEY generada y guardada en .env"
fi

ok "Variables cargadas correctamente desde .env"
echo "    • WAZUH_SERVER_IP : $WAZUH_SERVER_IP"
echo "    • RELAY_PORT      : $RELAY_PORT"
echo "    • RELAY_API_KEY   : ${RELAY_API_KEY:0:8}... (${#RELAY_API_KEY} chars)"
echo "    • WAHA_API_KEY    : ${WAHA_API_KEY:0:8}... (${#WAHA_API_KEY} chars)"

# 4. Sincronizar /etc/wazuh-waha/relay.env
echo -e "\n${BLANCO}── 2/7. Generando /etc/wazuh-waha/relay.env ──${NC}"
mkdir -p /etc/wazuh-waha
TARGET_RELAY_ENV="/etc/wazuh-waha/relay.env"

python3 - <<EOF
import os

env_file = "$ENV_FILE"
target = "$TARGET_RELAY_ENV"
data = {}
with open(env_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        k, v = k.strip(), v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        data[k] = v

with open(target, 'w', encoding='utf-8') as f:
    f.write("# Archivo auto-generado por deploy-server.sh\n")
    f.write(f"# Fuente: {env_file}\n\n")
    for k, v in data.items():
        escaped = v.replace('\\\\', '\\\\\\\\').replace('"', '\\"')
        f.write(f'{k}="{escaped}"\n')
EOF

chmod 600 "$TARGET_RELAY_ENV"
chown root:root "$TARGET_RELAY_ENV"
ok "/etc/wazuh-waha/relay.env sincronizado y protegido (0600 root:root)"

# 5. Configuración y preparación de relay/.venv
echo -e "\n${BLANCO}── 3/7. Verificando entorno virtual Python (relay/.venv) ──${NC}"
VENV_DIR="$PROJECT_ROOT/relay/.venv"
REBUILD_VENV=0

if [ ! -f "$VENV_DIR/bin/uvicorn" ] || [ ! -f "$VENV_DIR/bin/python" ]; then
    REBUILD_VENV=1
else
    # Probar que el python del venv realmente corre y encuentra dependencias básicas
    if ! "$VENV_DIR/bin/python" -c "import fastapi, uvicorn" 2>/dev/null; then
        REBUILD_VENV=1
    fi
fi

if [ "$REBUILD_VENV" -eq 1 ]; then
    info "Creando o reparando entorno virtual en $VENV_DIR..."
    rm -rf "$VENV_DIR"
    
    # Buscar interprete de Python 3.11+
    PYTHON_CMD=""
    for cmd in python3.11 python3.12 python3.13 python3; do
        if command -v "$cmd" &>/dev/null; then
            PY_VER=$("$cmd" -c "import sys; print(sys.version_info[:2] >= (3, 11))" 2>/dev/null || echo "False")
            if [ "$PY_VER" = "True" ]; then
                PYTHON_CMD="$cmd"
                break
            fi
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        fail "Se requiere Python >= 3.11 para wazuh-waha relay. Instala python3.11 o superior."
        exit 1
    fi

    info "Usando $PYTHON_CMD para crear venv..."
    sudo -u "$REAL_USER" "$PYTHON_CMD" -m venv "$VENV_DIR"
    sudo -u "$REAL_USER" "$VENV_DIR/bin/pip" install --upgrade pip -q
    info "Instalando dependencias de relay en modo editable..."
    sudo -u "$REAL_USER" "$VENV_DIR/bin/pip" install -e "$PROJECT_ROOT/relay" -q
    ok "Entorno virtual preparado y probado con éxito"
else
    ok "Entorno virtual ya existente y funcional en $VENV_DIR"
fi

# 6. Crear carpetas de logs y runtime
echo -e "\n${BLANCO}── 4/7. Configurando permisos y directorios del sistema ──${NC}"
mkdir -p /var/log/wazuh-waha /var/lib/wazuh-waha "$PROJECT_ROOT/backups"
chown -R "$REAL_USER:$REAL_GROUP" /var/log/wazuh-waha /var/lib/wazuh-waha "$PROJECT_ROOT/backups"
chmod 755 /var/log/wazuh-waha /var/lib/wazuh-waha "$PROJECT_ROOT/backups"
ok "Directorios /var/log/wazuh-waha y /var/lib/wazuh-waha listos"

# Instalar o sustituir wazuh-waha.service
UNIT_SRC="$PROJECT_ROOT/relay/systemd/wazuh-waha.service"
UNIT_DST="/etc/systemd/system/wazuh-waha.service"
TMP_UNIT=$(mktemp)

sed -e "s|<REEMPLAZAR_USUARIO>|${REAL_USER}|g" \
    -e "s|<REEMPLAZAR_PROYECTO>|${PROJECT_ROOT}|g" \
    "$UNIT_SRC" > "$TMP_UNIT"
cp "$TMP_UNIT" "$UNIT_DST"
rm -f "$TMP_UNIT"
chmod 644 "$UNIT_DST"

# Instalar drop-in override para cargar EnvironmentFile
OVERRIDE_DIR="/etc/systemd/system/wazuh-waha.service.d"
mkdir -p "$OVERRIDE_DIR"
cat << EOF > "$OVERRIDE_DIR/override.conf"
[Service]
EnvironmentFile=/etc/wazuh-waha/relay.env
WorkingDirectory=$PROJECT_ROOT/relay
ExecStart=
ExecStart=$PROJECT_ROOT/relay/.venv/bin/uvicorn wazuh_waha.main:app --host 0.0.0.0 --port $RELAY_PORT --workers 2
ReadWritePaths=/var/log/wazuh-waha /var/lib/wazuh-waha $PROJECT_ROOT /etc/wazuh-waha
EOF
chmod 644 "$OVERRIDE_DIR/override.conf"
ok "Servicio systemd configurado con EnvironmentFile y rutas reales"

# 7. Integración local con Wazuh Manager
echo -e "\n${BLANCO}── 5/7. Configurando integración en Wazuh Manager Local ──${NC}"
WAZUH_DIR="/var/ossec"

if [ -d "$WAZUH_DIR" ]; then
    WAZUH_USER="root"
    WAZUH_GROUP="wazuh"
    if ! getent group wazuh >/dev/null 2>&1; then
        WAZUH_GROUP="root"
    fi

    # 1. Instalar script whatsapp_alert.py
    mkdir -p "$WAZUH_DIR/integrations/custom"
    cp "$PROJECT_ROOT/manager-side/custom/whatsapp_alert.py" "$WAZUH_DIR/integrations/custom/whatsapp_alert.py"
    chmod 750 "$WAZUH_DIR/integrations/custom/whatsapp_alert.py"
    chown "root:$WAZUH_GROUP" "$WAZUH_DIR/integrations/custom/whatsapp_alert.py"
    ok "Script de integración instalado en $WAZUH_DIR/integrations/custom/whatsapp_alert.py"

    # 2. Generar /var/ossec/etc/wsl-relay.conf con API Key del .env
    WSL_CONF="$WAZUH_DIR/etc/wsl-relay.conf"
    cat << EOF > "$WSL_CONF"
# Auto-generado por deploy-server.sh
WAZUH_RELAY_URL=http://127.0.0.1:${RELAY_PORT}/alerts
WAZUH_RELAY_API_KEY=${RELAY_API_KEY}
WAZUH_RELAY_TIMEOUT=5
EOF
    chmod 640 "$WSL_CONF"
    chown "root:$WAZUH_GROUP" "$WSL_CONF"
    ok "Credenciales para Wazuh guardadas en $WSL_CONF"

    # 3. Validar e inyectar integration en ossec.conf si no está presente
    OSSEC_CONF="$WAZUH_DIR/etc/ossec.conf"
    if [ -f "$OSSEC_CONF" ]; then
        if ! grep -q "custom-whatsapp" "$OSSEC_CONF"; then
            info "Inyectando bloque <integration> de WhatsApp en $OSSEC_CONF..."
            cp "$OSSEC_CONF" "$OSSEC_CONF.bak.$(date +%s)"
            
            # Insertar antes del cierre </ossec_config>
            python3 - <<EOF
conf_path = "$OSSEC_CONF"
snippet = """  <integration>
    <name>custom-whatsapp</name>
    <level>8</level>
    <alert_format>json</alert_format>
    <options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 5</options>
  </integration>
"""
with open(conf_path, 'r', encoding='utf-8') as f:
    content = f.read()

if "</ossec_config>" in content and "custom-whatsapp" not in content:
    idx = content.rfind("</ossec_config>")
    new_content = content[:idx] + snippet + content[idx:]
    with open(conf_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("INJECT_OK")
EOF
            ok "Bloque <integration> añadido a $OSSEC_CONF"
        else
            ok "Bloque <integration> ya existe en $OSSEC_CONF"
        fi
    fi

    # 4. Copiar reglas locales
    if [ -f "$PROJECT_ROOT/manager-side/rules/local_rules.xml" ]; then
        cp "$PROJECT_ROOT/manager-side/rules/local_rules.xml" "$WAZUH_DIR/etc/rules/local_rules.xml" 2>/dev/null || true
        chown "root:$WAZUH_GROUP" "$WAZUH_DIR/etc/rules/local_rules.xml" 2>/dev/null || true
        ok "Reglas locales sincronizadas en $WAZUH_DIR/etc/rules/local_rules.xml"
    fi
else
    warn "No se encontró el directorio $WAZUH_DIR. Si Wazuh Manager no está en este servidor, omite este paso."
fi

# 8. Sincronizar Dashboard Nginx con la API Key actual
echo -e "\n${BLANCO}── 6/7. Sincronizando Dashboard Nginx con la API Key ──${NC}"
NGINX_CONF="$PROJECT_ROOT/dashboard/nginx.conf"
if [ -f "$NGINX_CONF" ]; then
    sed -i -E "s/proxy_set_header X-Api-Key \"[^\"]+\";/proxy_set_header X-Api-Key \"$RELAY_API_KEY\";/g" "$NGINX_CONF"
    ok "dashboard/nginx.conf actualizado con la RELAY_API_KEY actual"
fi

# 9. Reinicio maestro de todos los servicios
echo -e "\n${BLANCO}── 7/7. Reiniciando servicios y aplicando cambios ──${NC}"

# Recargar systemd
systemctl daemon-reload

# Habilitar y reiniciar relay
systemctl enable wazuh-waha.service >/dev/null 2>&1 || true
systemctl restart wazuh-waha.service
ok "Servicio wazuh-waha.service reiniciado"

# Reiniciar Wazuh Manager si existe
if systemctl list-unit-files | grep -q "wazuh-manager.service"; then
    info "Reiniciando wazuh-manager.service..."
    systemctl restart wazuh-manager.service >/dev/null 2>&1 || true
    ok "Wazuh Manager reiniciado"
elif [ -x "$WAZUH_DIR/bin/wazuh-control" ]; then
    info "Reiniciando Wazuh vía wazuh-control..."
    "$WAZUH_DIR/bin/wazuh-control" restart >/dev/null 2>&1 || true
    ok "Wazuh Manager reiniciado con wazuh-control"
fi

# Levantar Docker Compose si docker está disponible
if command -v docker &>/dev/null; then
    if [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
        info "Iniciando contenedores Docker (WAHA + Dashboard)..."
        (cd "$PROJECT_ROOT" && docker compose up -d --remove-orphans) 2>&1 | sed 's/^/    /'
        ok "Contenedores Docker levantados"
    fi
else
    warn "Docker no encontrado en el sistema. Asegúrate de iniciar WAHA manualmente."
fi

# 10. Verificación final de salud (Health Checks)
echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${BLANCO}  VERIFICACIÓN DE SALUD FINAL DEL STACK${NC}"
echo -e "${CYAN}======================================================================${NC}\n"

sleep 3

# Test 1: Relay HTTP
printf "  %-45s" "• Relay HTTP (http://127.0.0.1:${RELAY_PORT}/health)"
HTTP_RELAY=$(curl -s -m 5 "http://127.0.0.1:${RELAY_PORT}/health" 2>/dev/null || true)
if echo "$HTTP_RELAY" | grep -q '"status":"ok"'; then
    echo -e "${VERDE}[OK]${NC}"
    echo -e "    ${GRIS}$HTTP_RELAY${NC}"
else
    echo -e "${ROJO}[FALLO]${NC}"
    warn "Logs recientes del relay:"
    journalctl -u wazuh-waha.service -n 15 --no-pager | sed 's/^/      /'
fi

# Test 2: WAHA Docker
printf "  %-45s" "• WAHA WhatsApp API (Puerto 3001)"
HTTP_WAHA=$(curl -s -m 5 -H "X-Api-Key: $WAHA_API_KEY" "http://127.0.0.1:3001/api/server/version" 2>/dev/null || true)
if [ -n "$HTTP_WAHA" ]; then
    echo -e "${VERDE}[OK]${NC}"
    echo -e "    ${GRIS}$HTTP_WAHA${NC}"
else
    echo -e "${AMARILLO}[SIN RESPUESTA AÚN (iniciando)]${NC}"
fi

# Test 3: Dashboard Nginx
printf "  %-45s" "• Dashboard SOC Web (Puerto 8001)"
if curl -s -m 3 "http://127.0.0.1:8001/" >/dev/null 2>&1; then
    echo -e "${VERDE}[OK]${NC} (Accesible en http://localhost:8001/)"
else
    echo -e "${AMARILLO}[NO RESPONDE]${NC}"
fi

# Test 4: Wazuh API
if [ -d "$WAZUH_DIR" ]; then
    printf "  %-45s" "• Wazuh Manager API (Puerto ${WAZUH_MANAGER_API_PORT})"
    if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/${WAZUH_MANAGER_API_PORT}" 2>/dev/null; then
        echo -e "${VERDE}[PUERTO ABIERTO]${NC}"
    else
        echo -e "${ROJO}[PUERTO CERRADO]${NC}"
    fi
fi

echo -e "\n${VERDE}¡Despliegue y configuración completados con éxito!${NC}"
echo -e "Para revisar el diagnóstico completo en cualquier momento ejecuta:"
echo -e "  ${BLANCO}bash scripts/diagnose.sh${NC}\n"
