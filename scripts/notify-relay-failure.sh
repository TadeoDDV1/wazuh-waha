#!/usr/bin/env bash
# =============================================================================
# notify-relay-failure.sh - Hook OnFailure= de wazuh-waha.service.
# =============================================================================
# Lo invoca wazuh-waha-failure-notify.service. Usa host_notify.py para
# avisar por WhatsApp (si WAHA esta WORKING), Telegram y email.
# =============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PY="${PROJECT_ROOT}/relay/.venv/bin/python"
[ -x "$PY" ] || PY=/usr/bin/python3

SERVICE_NAME="${SERVICE_UNIT:-wazuh-waha.service}"
SERVICE_RESULT="${SERVICE_RESULT:-unknown}"
EXIT_CODE="${EXIT_CODE:-?}"

# Un `systemctl restart` limpio tambien puede disparar OnFailure con
# SERVICE_RESULT=unknown y sin exit code. No avisar en ese caso para evitar
# falsos positivos por mantenimiento manual.
if [ "${SERVICE_RESULT}" = "unknown" ] && { [ "${EXIT_CODE}" = "?" ] || [ "${EXIT_CODE}" = "0" ]; }; then
    echo "[notify-relay-failure] sin datos de fallo real (probable reinicio manual); se omite aviso"
    exit 0
fi

case "${SERVICE_RESULT}" in
    exit-code) RESULT_DESC="exit code ${EXIT_CODE}" ;;
    signal)    RESULT_DESC="senal ${EXIT_CODE}" ;;
    timeout)   RESULT_DESC="timeout" ;;
    *)         RESULT_DESC="${SERVICE_RESULT} (code=${EXIT_CODE})" ;;
esac

echo "[notify-relay-failure] service=${SERVICE_NAME} result=${SERVICE_RESULT} code=${EXIT_CODE}"
"${PY}" "${PROJECT_ROOT}/scripts/host_notify.py" \
    --event service-down \
    --detail "Relay ${SERVICE_NAME} fallo: ${RESULT_DESC}" \
    --with-status \
    || echo "[notify-relay-failure] WARN: no se pudo notificar (ver eventos.log)" >&2

exit 0
