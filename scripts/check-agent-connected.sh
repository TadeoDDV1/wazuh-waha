#!/usr/bin/env bash
# =============================================================================
# check-agent-connected.sh
# =============================================================================
# Health check del agente Wazuh: verifica que el ESTAB TCP :1514 con el manager
# este vivo. Si NO lo esta, notifica via waha-notify.py.
#
# Disparado por wazuh-agent-health.timer cada 5 min.
#
# Salida:
#   0 = agente conectado (no notifica)
#   1 = agente NO conectado (notifica email+WhatsApp)
#   2 = error interno (no notifica para no spamear)
#
# Idempotencia:
#   - Cache en /var/lib/wazuh-waha/agent_disconnected_notified con timestamp
#   - Solo re-notifica si pasaron > ALERT_COOLDOWN_SEC desde la ultima alerta
#   - Default cooldown: 30 min (asi no spameamos cada 5 min mientras este caido)
# =============================================================================

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PROJECT_ROOT}/relay/.venv/bin/python"

# Config (env vars con defaults)
ALERT_COOLDOWN_SEC="${AGENT_ALERT_COOLDOWN_SEC:-1800}"  # 30 min
MANAGER_IP="${WAZUH_SERVER_IP:-}"
NOTIFIED_CACHE="/var/lib/wazuh-waha/agent_disconnected_notified"

if [[ -z "${MANAGER_IP}" ]]; then
    # Fallback: leer del .env del repo
    if [[ -f "${PROJECT_ROOT}/.env" ]]; then
        MANAGER_IP=$(grep -E "^WAZUH_SERVER_IP=" "${PROJECT_ROOT}/.env" | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
    fi
fi

if [[ -z "${MANAGER_IP}" ]]; then
    echo "[check-agent] ERROR: no se pudo resolver WAZUH_SERVER_IP" >&2
    exit 2
fi

# Chequeo: hay alguna conexion ESTAB al :1514 del manager?
# ss puede no estar si el path es raro, pero confio en que esta.
if ! command -v ss >/dev/null 2>&1; then
    echo "[check-agent] ERROR: ss no disponible" >&2
    exit 2
fi

ESTAB_LINE=$(ss -tnp 2>/dev/null | grep -E ":1514\b" | grep "ESTAB" | grep -F "${MANAGER_IP}" || true)

if [[ -n "${ESTAB_LINE}" ]]; then
    # Conectado. Si teniamos un cache de "disconnected", limpiarlo y notificar recovery.
    if [[ -f "${NOTIFIED_CACHE}" ]]; then
        echo "[check-agent] OK: agente re-conectado a ${MANAGER_IP}:1514 (cache limpiado)"
        rm -f "${NOTIFIED_CACHE}"
        # Notificar recovery (solo email, no WhatsApp, no manager-api: meta evento)
        if [[ -x "${PY}" ]]; then
            "${PY}" "${PROJECT_ROOT}/scripts/waha-notify.py" \
                --description "wazuh-agent RECONECTADO al manager ${MANAGER_IP}:1514" \
                --level 6 \
                --action agent_reconnected \
                --service wazuh-agent \
                --no-manager-api \
                >/dev/null 2>&1 || true
        fi
    else
        echo "[check-agent] OK: agente conectado a ${MANAGER_IP}:1514"
    fi
    exit 0
fi

# NO conectado. Respetar cooldown.
NOW=$(date +%s)
if [[ -f "${NOTIFIED_CACHE}" ]]; then
    LAST=$(cat "${NOTIFIED_CACHE}" 2>/dev/null || echo 0)
    ELAPSED=$(( NOW - LAST ))
    if (( ELAPSED < ALERT_COOLDOWN_SEC )); then
        echo "[check-agent] WARN: agente desconectado pero cooldown activo (${ELAPSED}s < ${ALERT_COOLDOWN_SEC}s), skip notify"
        exit 1
    fi
fi

echo "[check-agent] FAIL: agente NO conectado a ${MANAGER_IP}:1514"

# Notificar
if [[ ! -x "${PY}" ]]; then
    echo "[check-agent] WARN: venv python no encontrado, no se puede notificar" >&2
    exit 2
fi

mkdir -p "$(dirname "${NOTIFIED_CACHE}")"

"${PY}" "${PROJECT_ROOT}/scripts/waha-notify.py" \
    --description "wazuh-agent DESCONECTADO del manager ${MANAGER_IP}:1514 hace >5 min" \
    --level 12 \
    --action agent_disconnected \
    --service wazuh-agent \
    --no-manager-api \
    >/dev/null 2>&1 && {
        date +%s > "${NOTIFIED_CACHE}"
        echo "[check-agent] OK: notificacion enviada, cache=${NOTIFIED_CACHE}"
    } || {
        echo "[check-agent] WARN: notificacion fallo (no se actualiza cache)" >&2
    }

exit 1