#!/usr/bin/env bash
# =============================================================================
# notify-agent-failure.sh
# =============================================================================
# Hook de OnFailure= para wazuh-agent.service.
#
# Cuando wazuh-agent falla al arrancar o se cae y entra en failed state,
# systemd corre este script. Llama a waha-notify.py para mandar email +
# WhatsApp con el detalle.
#
# Precondiciones:
#   - /etc/wazuh-waha/relay.env existe (lo mantiene scripts/sync_relay_env.sh)
#   - El usuario tadeo tiene acceso al repo (este script corre como root via
#     systemd, pero el wrapper Python re-ejecuta bajo el venv del relay)
#
# Salida: loguea a journal (lo recoje systemd).
#
# Configuracion en /etc/systemd/system/wazuh-agent.service.d/notify.conf:
#   [Unit]
#   OnFailure=wazuh-agent-failure-notify.service
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PY="${PROJECT_ROOT}/relay/.venv/bin/python"

if [[ ! -x "${PY}" ]]; then
    echo "[notify-agent-failure] ERROR: venv python no encontrado en ${PY}" >&2
    exit 1
fi

# systemd nos pasa estas vars automaticamente cuando OnFailure= dispara:
#   $SERVICE_UNIT   = nombre del unit que fallo (wazuh-agent.service)
#   $SERVICE_RESULT = resultado (exit-code, signal, timeout, etc.)
#   $EXIT_STATUS    = exit code del proceso
#   $EXIT_CODE      = codigo (de EXIT_STATUS/CONTROL_GROUP/...)
SERVICE_NAME="${SERVICE_UNIT:-wazuh-agent.service}"
SERVICE_RESULT="${SERVICE_RESULT:-unknown}"
EXIT_CODE="${EXIT_CODE:-?}"
RESTART_COUNT="${RESTART_COUNT:-0}"

# Descripcion legible para el reporte
case "${SERVICE_RESULT}" in
    exit-code) RESULT_DESC="exit code ${EXIT_CODE}" ;;
    signal)    RESULT_DESC="señal ${EXIT_CODE}" ;;
    timeout)   RESULT_DESC="timeout (no respondio en TimeoutStartSec)" ;;
    *)         RESULT_DESC="${SERVICE_RESULT} (code=${EXIT_CODE})" ;;
esac

DESCRIPTION="wazuh-agent fallo: ${RESULT_DESC}"
LEVEL=12  # High: el agente esta caido y no reporta al manager

"${PY}" "${PROJECT_ROOT}/scripts/waha-notify.py" \
    --description "${DESCRIPTION}" \
    --level "${LEVEL}" \
    --action agent_failed \
    --service "${SERVICE_NAME}" \
    --restart-count "${RESTART_COUNT}" \
    --no-manager-api \
    >/dev/null 2>&1 || {
        echo "[notify-agent-failure] WARN: waha-notify.py fallo, no se pudo notificar" >&2
        exit 0  # No propagamos el error al OnFailure (queremos que systemd continue su ciclo)
    }

echo "[notify-agent-failure] OK: notificacion enviada (service=${SERVICE_NAME} result=${SERVICE_RESULT} code=${EXIT_CODE})"