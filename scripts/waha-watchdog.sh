#!/bin/bash
# waha-watchdog.sh - Chequea la sesion WAHA y la recupera si esta caida.
# Corre via systemd timer (wazuh-waha-watchdog.timer).
# Independiente del relay: si el relay esta muerto, este watchdog igual actua.
#
# Si la sesion esta WORKING: sale silencioso (exit 0).
# Si la sesion NO esta WORKING:
#   1. Log a journal
#   2. Ejecuta scripts/recover-waha.sh
#   3. Si recover OK -> notifica (Wazuh API + email) "recovered"
#   4. Si recover FAIL -> notifica "recovery_failed"
#
# Variables leidas de /etc/wazuh-waha/relay.env (via EnvironmentFile en el .service).
# Las notificaciones las hace el script Python wazuh-waha/wazuh_waha/notifier.py
# mediante un wrapper (waha-notify.py en este mismo directorio).

set +e
PROJECT_ROOT="${PROJECT_ROOT:-/home/tadeo/Desktop/wazuh-waha}"
ENV_FILE="${ENV_FILE:-/etc/wazuh-waha/relay.env}"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

WAHA_HOST="${WAHA_HOST:-http://localhost:3000}"
WAHA_API_KEY="${WAHA_API_KEY:-}"
WAHA_SESSION="${WAHA_SESSION:-default}"

if [ -z "$WAHA_API_KEY" ]; then
  echo "waha-watchdog ERROR: WAHA_API_KEY no seteada en $ENV_FILE" >&2
  exit 1
fi

# 1. Estado actual de la sesion
STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
  "$WAHA_HOST/api/sessions/$WAHA_SESSION" 2>/dev/null \
  | jq -r .status 2>/dev/null)

if [ "$STATUS" = "WORKING" ]; then
  # Sesion sana. Nada que hacer.
  exit 0
fi

# 2. Sesion caida. Loguear y recuperar.
echo "waha-watchdog ALERT session=$WAHA_SESSION status=$STATUS triggering_recovery"

# 3. Llamar al script de recovery (el mismo que usa el operator manual)
RECOVER_SCRIPT="$PROJECT_ROOT/scripts/recover-waha.sh"
if [ ! -x "$RECOVER_SCRIPT" ]; then
  echo "waha-watchdog ERROR: $RECOVER_SCRIPT no existe o no es ejecutable" >&2
  # Aun asi, intentar notificar
  RECOVER_RESULT="script_missing"
else
  bash "$RECOVER_SCRIPT" >/tmp/waha-watchdog-recover.log 2>&1
  RECOVER_RESULT=$?
fi

# 4. Chequear si el recover llevo a WORKING
NEW_STATUS=$(curl -sS -m 5 -H "X-Api-Key: $WAHA_API_KEY" \
  "$WAHA_HOST/api/sessions/$WAHA_SESSION" 2>/dev/null \
  | jq -r .status 2>/dev/null)

# 5. Notificar via wrapper Python (que dispara ambos canales)
NOTIFY="$PROJECT_ROOT/scripts/waha-notify.py"
if [ -x "$NOTIFY" ] || [ -f "$NOTIFY" ]; then
  if [ "$NEW_STATUS" = "WORKING" ]; then
    python3 "$NOTIFY" --description "WAHA session $WAHA_SESSION recovered by watchdog" \
      --level 10 --action watchdog_recovered --previous_status "$STATUS" \
      --new_status "$NEW_STATUS" 2>/dev/null
  else
    python3 "$NOTIFY" --description "WAHA session $WAHA_SESSION recovery FAILED (watchdog)" \
      --level 15 --action watchdog_recovery_failed --previous_status "$STATUS" \
      --new_status "$NEW_STATUS" --recover_exit_code "$RECOVER_RESULT" 2>/dev/null
  fi
else
  echo "waha-watchdog WARN: $NOTIFY no existe, notificacion omitida" >&2
fi

exit 0