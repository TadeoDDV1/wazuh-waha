#!/bin/bash
# =============================================================================
# watch_manager_ip.sh - Detecta drift de IP del manager Wazuh y avisa.
# =============================================================================
# Corre desde systemd timer (watch_manager_ip.timer) cada 5 min.
#
# QUE HACE:
#   1. Lee la IP esperada del .env (WAZUH_SERVER_IP)
#   2. Verifica que el manager en ESA IP responde a TCP 1514 (conexion del agente)
#   3. Si falla: prueba IPs candidatas (rango de tu red local) y la IP anterior
#   4. Si NINGUNA responde: mantiene la IP vieja en ossec.conf pero avisa
#   5. Si OTRA IP responde (drift): avisa antes de tocar nada (decision humana)
#   6. Notifica via waha-notify.py (que dispara WhatsApp API + email)
#
# ESTADO: detecta y avisa. NO auto-mueve ossec.conf (eso lo decis vos).
# Para activar el auto-move, exportar AUTO_RECONCILE=1 antes de correrlo.
#
# VARIABLES DE ENTRADA (de /etc/wazuh-waha/relay.env):
#   WAZUH_SERVER_IP - IP actual del manager (la del .env)
#   WAZUH_SERVER_IP_FALLBACK - IPs candidatas separadas por coma (opcional)
#   AGENT_CONF - path al ossec.conf del agente (default /var/ossec/etc/ossec.conf)
#
# DEPENDE DE:
#   - /etc/wazuh-waha/relay.env (EnvironmentFile del timer)
#   - scripts/waha-notify.py (wrapper del notifier.py)
# =============================================================================

set +e

PROJECT_ROOT="${PROJECT_ROOT:-/home/tadeo/Desktop/wazuh-waha}"
ENV_FILE="${ENV_FILE:-/etc/wazuh-waha/relay.env}"
AGENT_CONF="${AGENT_CONF:-/var/ossec/etc/ossec.conf}"
STATE_FILE="/var/lib/wazuh-waha/manager_ip_state"
NOTIFY="$PROJECT_ROOT/scripts/waha-notify.py"

# Cargar .env del relay (mismas vars que waha-watchdog.sh)
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

CURRENT_IP="${WAZUH_SERVER_IP:-}"
FALLBACK_IPS="${WAZUH_SERVER_IP_FALLBACK:-}"  # ej: "192.168.1.82,172.44.30.5"

# Estado anterior del IP (para detectar cambio)
PREVIOUS_IP=""
if [ -f "$STATE_FILE" ]; then
  PREVIOUS_IP=$(cat "$STATE_FILE" 2>/dev/null)
fi

mkdir -p "$(dirname "$STATE_FILE")" 2>/dev/null

# Funcion: probar si una IP responde a TCP 1514 (puerto del manager)
ping_ip() {
  local ip="$1"
  timeout 3 bash -c "exec 3<>/dev/tcp/$ip/1514" 2>/dev/null && echo "open" || echo "closed"
}

# Funcion: leer la IP actual del ossec.conf del agente
read_agent_ip() {
  sudo grep -oE '<address>[^<]+</address>' "$AGENT_CONF" 2>/dev/null \
    | head -1 \
    | sed 's|</\?address>||g' \
    | tr -d ' '
}

# Funcion: notificar via waha-notify.py (que llama al notifier.py)
notify_drift() {
  local description="$1"
  local detected_ip="$2"
  local level="${3:-15}"
  if [ -f "$NOTIFY" ]; then
    python3 "$NOTIFY" \
      --description "$description" \
      --level "$level" \
      --action ip_drift \
      --expected_ip "$CURRENT_IP" \
      --detected_ip "$detected_ip" \
      --previous_ip "$PREVIOUS_IP" \
      --agent_ip "$(read_agent_ip)" 2>/dev/null
  fi
}

# --- Loop principal ---

log() { echo "watch_manager_ip $*"; }
log "started expected=$CURRENT_IP previous=$PREVIOUS_IP"

# 1. Ping al IP esperado (TCP 1514)
EXPECTED_RESULT=$(ping_ip "$CURRENT_IP")
if [ "$EXPECTED_RESULT" = "open" ]; then
  log "manager OK en $CURRENT_IP - sin drift"
  # Guardar IP actual como estado si cambio
  if [ "$PREVIOUS_IP" != "$CURRENT_IP" ]; then
    echo "$CURRENT_IP" > "$STATE_FILE"
    if [ -n "$PREVIOUS_IP" ]; then
      log "NOTA: IP anterior $PREVIOUS_IP ya no es la fuente de verdad"
    fi
  fi
  exit 0
fi

# 2. Drift probable - la IP del manager cambio
log "ALERTA: manager $CURRENT_IP no responde a TCP 1514"

DETECTED_IP=""

# 3. Probar IPs candidatas antes de declarar IP perdida
if [ -n "$FALLBACK_IPS" ]; then
  IFS=',' read -ra CANDIDATES <<< "$FALLBACK_IPS"
  for cand in "${CANDIDATES[@]}"; do
    cand=$(echo "$cand" | tr -d ' ')
    [ -z "$cand" ] && continue
    [ "$cand" = "$CURRENT_IP" ] && continue
    log "probando candidata $cand..."
    if [ "$(ping_ip "$cand")" = "open" ]; then
      DETECTED_IP="$cand"
      log "drift detectado: $CURRENT_IP -> $cand"
      break
    fi
  done
fi

# 4. Construir mensaje segun caso
AGENT_IP=$(read_agent_ip)

if [ -n "$DETECTED_IP" ]; then
  # Drift claro: nueva IP encontrada
  DESCRIPTION="Wazuh manager cambio de IP: $CURRENT_IP -> $DETECTED_IP. Agente apunta a $AGENT_IP. Reconexion manual requerida."
  notify_drift "$DESCRIPTION" "$DETECTED_IP" 12
  log "notificacion enviada: drift $CURRENT_IP -> $DETECTED_IP"

  # Opcionalmente, auto-reconciliar si AUTO_RECONCILE=1
  if [ "${AUTO_RECONCILE:-0}" = "1" ]; then
    log "AUTO_RECONCILE activo - actualizando ossec.conf del agente..."
    sudo cp "$AGENT_CONF" "$AGENT_CONF.bak.$(date +%s)" 2>/dev/null
    sudo sed -i "s|<address>$CURRENT_IP</address>|<address>$DETECTED_IP</address>|" "$AGENT_CONF" 2>/dev/null
    sudo python3 -c "import xml.etree.ElementTree as ET; ET.parse('$AGENT_CONF'); print('XML_OK')" 2>/dev/null
    sudo systemctl restart wazuh-agent 2>/dev/null
    echo "$DETECTED_IP" > "$STATE_FILE"
    # Actualizar el .env para mantener consistencia
    if grep -q "WAZUH_SERVER_IP=" "$ENV_FILE" 2>/dev/null; then
      sudo sed -i "s|WAZUH_SERVER_IP=.*|WAZUH_SERVER_IP=$DETECTED_IP|" "$ENV_FILE" 2>/dev/null
    fi
    log "auto-reconciliacion completada"
  fi

elif [ -z "$PREVIOUS_IP" ] || [ "$PREVIOUS_IP" = "$CURRENT_IP" ]; then
  # Manager perdido sin candidato conocido (primer drift o IP anterior == actual)
  DESCRIPTION="Wazuh manager $CURRENT_IP no responde. Verificar VM apagada o cambio de red. Agente apunta a $AGENT_IP."
  notify_drift "$DESCRIPTION" "" 15
  log "notificacion enviada: manager $CURRENT_IP no responde"

else
  # Drift previo conocido pero tampoco responde ninguno de los candidatos
  DESCRIPTION="Wazuh manager caido: $CURRENT_IP (esperado) y $PREVIOUS_IP (anterior) no responden. Verificar VM."
  notify_drift "$DESCRIPTION" "" 15
  log "notificacion enviada: ambas IPs caidas"
fi

exit 0
