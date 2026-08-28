#!/usr/bin/env bash
# =============================================================================
# notify-relay-failure.sh
# =============================================================================
# Hook de OnFailure= para wazuh-waha.service (el relay HTTP).
#
# Cuando el relay falla al arrancar o se cae, el pipeline entero se rompe:
#   - Wazuh sigue mandando alertas al manager pero el relay no las pasa a WAHA
#   - El watchdog de sesion WAHA no puede actuar (no hay relay)
#
# Por eso nivel 15 (Critical). Notifica email + WhatsApp.
#
# Configuracion en /etc/systemd/system/wazuh-waha.service.d/notify.conf:
#   [Unit]
#   OnFailure=wazuh-waha-failure-notify.service
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PY="${PROJECT_ROOT}/relay/.venv/bin/python"

if [[ ! -x "${PY}" ]]; then
    echo "[notify-relay-failure] ERROR: venv python no encontrado en ${PY}" >&2
    exit 1
fi

SERVICE_NAME="${SERVICE_UNIT:-wazuh-waha.service}"
SERVICE_RESULT="${SERVICE_RESULT:-unknown}"
EXIT_CODE="${EXIT_CODE:-?}"

case "${SERVICE_RESULT}" in
    exit-code) RESULT_DESC="exit code ${EXIT_CODE}" ;;
    signal)    RESULT_DESC="señal ${EXIT_CODE}" ;;
    timeout)   RESULT_DESC="timeout (no respondio en TimeoutStartSec)" ;;
    *)         RESULT_DESC="${SERVICE_RESULT} (code=${EXIT_CODE})" ;;
esac

DESCRIPTION="wazuh-waha relay fallo: ${RESULT_DESC}"
LEVEL=15  # Critical: el pipeline esta caido

"${PY}" "${PROJECT_ROOT}/scripts/waha-notify.py" \
    --description "${DESCRIPTION}" \
    --level "${LEVEL}" \
    --action relay_failed \
    --service "${SERVICE_NAME}" \
    --no-manager-api \
    >/dev/null 2>&1 || {
        echo "[notify-relay-failure] WARN: waha-notify.py fallo, no se pudo notificar" >&2
        exit 0
    }

echo "[notify-relay-failure] OK: notificacion enviada (service=${SERVICE_NAME} result=${SERVICE_RESULT} code=${EXIT_CODE})"