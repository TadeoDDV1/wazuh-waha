#!/bin/bash
# =============================================================================
# boot_stack_status.sh - Sondea el estado de cada pieza del stack wazuh-waha.
# =============================================================================
# Usado por boot-notify.py al iniciar el host, pero corre standalone y sin
# side effects para que se pueda invocar a mano.
#
# Salida: lineas KEY=VALUE faciles de parsear. Exit code 0 siempre.
#
# Uso:
#   bash scripts/boot_stack_status.sh
#   bash scripts/boot_stack_status.sh | sort
#   bash scripts/boot_stack_status.sh | jq -R 'split("=") | {(.[0]): .[1]}'
# =============================================================================

set +e
PROJECT_ROOT="${PROJECT_ROOT:-/home/tadeo/Desktop/wazuh-waha}"
ENV_FILE="${ENV_FILE:-/etc/wazuh-waha/relay.env}"

# Cargar config (para WAZUH_SERVER_IP, WAHA_HOST, etc)
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

WAHA_HOST="${WAHA_HOST:-http://localhost:3000}"
WAHA_SESSION="${WAHA_SESSION:-default}"
WAHA_API_KEY="${WAHA_API_KEY:-}"

# --- Helpers de output ---
WAZUH_SERVER_IP_FALLBACK="${WAZUH_SERVER_IP_FALLBACK:-}"

# --- Helpers de output ---
emit() { printf "%s=%s\n" "$1" "$2"; }

check_service() {
  local name="$1" unit="$2"
  local state
  state=$(systemctl is-active "$unit" 2>/dev/null)
  if [ "$state" = "active" ]; then
    emit "$name" "active"
  else
    emit "$name" "down:$state"
  fi
}

check_timer() {
  local name="$1" unit="$2"
  local state
  state=$(systemctl is-active "$unit" 2>/dev/null)
  if [ "$state" = "active" ]; then
    emit "$name" "active"
  else
    emit "$name" "down:$state"
  fi
}

check_docker() {
  local name="$1" container="$2"
  local status
  status=$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)
  if [ "$status" = "true" ]; then
    emit "$name" "running"
  else
    emit "$name" "down:${status:-not_found}"
  fi
}

check_waha_session() {
  if [ -z "$WAHA_API_KEY" ]; then
    emit "waha_session" "unknown:no_api_key"
    return
  fi
  local status
  status=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
    "$WAHA_HOST/api/sessions/$WAHA_SESSION" 2>/dev/null \
    | jq -r .status 2>/dev/null)
  emit "waha_session" "${status:-unreachable}"
}

check_tcp() {
  local name="$1" host="$2" port="$3"
  if timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
    emit "$name" "open"
  else
    emit "$name" "closed"
  fi
}

# --- Metadata del host ---
emit "host" "$(hostname)"
emit "local_ip" "$(ip -4 route get 1 2>/dev/null | awk '/src/ {print $7; exit}')"
emit "boot_id" "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
emit "uptime_sec" "$(awk '{print int($1)}' /proc/uptime 2>/dev/null)"
emit "timestamp" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- Servicios systemd (los del stack wazuh-waha) ---
check_service "wazuh_waha_service"     "wazuh-waha.service"
check_timer   "wazuh_waha_watchdog"    "wazuh-waha-watchdog.timer"
check_timer   "watch_manager_ip"       "watch_manager_ip.timer"
check_service "wazuh_agent_service"    "wazuh-agent.service"

# --- Docker ---
check_docker  "docker_wazuh_waha"      "wazuh-waha"

# --- WAHA sesion WhatsApp ---
check_waha_session

# --- Manager Wazuh (TCP 1514) ---
# La IP "actual" es la que el .env cree que es; si no responde, marcamos down
# pero conservamos la IP para el reporte (asi se ve el drift).
emit "manager_expected_ip" "${WAZUH_SERVER_IP:-unset}"
if [ -n "$WAZUH_SERVER_IP" ]; then
  check_tcp "manager_expected_tcp1514" "$WAZUH_SERVER_IP" "1514"
else
  emit "manager_expected_tcp1514" "skipped:no_ip"
fi

# Probar fallbacks tambien (para el reporte)
if [ -n "$WAZUH_SERVER_IP_FALLBACK" ]; then
  IFS=',' read -ra FB_ARR <<< "$WAZUH_SERVER_IP_FALLBACK"
  i=0
  for fb in "${FB_ARR[@]}"; do
    fb=$(echo "$fb" | tr -d ' ')
    [ -z "$fb" ] && continue
    [ "$fb" = "$WAZUH_SERVER_IP" ] && continue
    check_tcp "manager_fallback_${i}_tcp1514" "$fb" "1514"
    i=$((i+1))
  done
fi

# --- Ollama (opcional, IA local) ---
check_tcp "ollama_local" "127.0.0.1" "11434"

# --- Manager API (para el notifier fallback) ---
if [ -n "$WAZUH_SERVER_IP" ]; then
  check_tcp "manager_api_55000" "$WAZUH_SERVER_IP" "55000"
fi

exit 0
