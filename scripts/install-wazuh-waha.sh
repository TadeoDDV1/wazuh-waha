#!/bin/bash
# install-wazuh-waha.sh - Instala el relay como servicio systemd.
# Ejecutar MANUALMENTE en una terminal con TTY (sandbox bloquea sudo -S).
#
# Asume que el proyecto está en ~/Desktop/wazuh-waha/.
# Si está en otro path, exportar PROJECT_ROOT antes de correr.
#
# IMPORTANTE: este script sustituye los placeholders <REEMPLAZAR_USUARIO> y
# <REEMPLAZAR_PROYECTO> en los unit files antes de instalarlos. Sin esa
# sustitucion, systemd rechaza el unit con "WorkingDirectory= path is not
# absolute" y el relay queda en estado bad-setting.

set -e

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/Desktop/wazuh-waha}"

echo "=== Verificando precondiciones ==="
if [ ! -d "$PROJECT_ROOT" ]; then
  echo "ERROR: $PROJECT_ROOT no existe. Exportar PROJECT_ROOT o mover el proyecto ahi."
  exit 1
fi

# Detectar usuario real (no root, no nobody). El unit commiteable asume que
# el relay corre como el usuario del Desktop (no root).
DETECTED_USER="${SUDO_USER:-$USER}"
if [[ -z "${DETECTED_USER}" || "${DETECTED_USER}" == "root" ]]; then
  echo "ERROR: no pude detectar el usuario real del Desktop (SUDO_USER/USER vacios o root)."
  echo "       Correr el script con sudo desde una sesion de tu usuario, no como root."
  exit 1
fi

echo "  PROJECT_ROOT=${PROJECT_ROOT}"
echo "  USER=${DETECTED_USER}"

UNIT_SRC="$PROJECT_ROOT/relay/systemd/wazuh-waha.service"
if [ ! -f "$UNIT_SRC" ]; then
  echo "ERROR: no encuentro $UNIT_SRC"
  exit 1
fi

# Funcion auxiliar: susbtituye placeholders en un archivo y lo copia al destino.
install_unit() {
  local src="$1"
  local dst="$2"
  local tmpfile
  tmpfile="$(mktemp)"
  sed -e "s|<REEMPLAZAR_USUARIO>|${DETECTED_USER}|g" \
      -e "s|<REEMPLAZAR_PROYECTO>|${PROJECT_ROOT}|g" \
      "${src}" > "${tmpfile}"
  sudo cp "${tmpfile}" "${dst}"
  rm -f "${tmpfile}"
}

echo "=== 1. Instalar unit file (con placeholders sustituidos) ==="
install_unit "$UNIT_SRC" /etc/systemd/system/wazuh-waha.service
sudo systemctl daemon-reload
echo "OK"

echo "=== 1b. Arreglar shebangs del venv (si fueron creados con path viejo) ==="
# El proyecto se movio de wazuh-integration/ a relay/ y los shebangs del venv
# quedaron apuntando a paths que no existen. Sin este fix, systemd tira
# "Failed to execute uvicorn: No such file or directory" o
# "ModuleNotFoundError: No module named 'uvicorn'" si apuntan al python de uv.
# Idempotente: si los shebangs ya estan bien, no hace nada.
if [ -x "${PROJECT_ROOT}/scripts/fix_venv_shebangs.sh" ]; then
  bash "${PROJECT_ROOT}/scripts/fix_venv_shebangs.sh" --apply || \
    echo "WARN: fix_venv_shebangs.sh fallo (puede no ser critico si ya estaban bien)"
else
  echo "WARN: no encuentro scripts/fix_venv_shebangs.sh"
fi

echo "=== 2. Crear directorios de log y state ==="
sudo mkdir -p /var/log/wazuh-waha /var/lib/wazuh-waha
sudo chown -R "$USER:$USER" /var/log/wazuh-waha /var/lib/wazuh-waha
echo "OK"

echo "=== 3. Si hay override.conf de deploy/, instalarlo ==="
OVERRIDE_SRC="$PROJECT_ROOT/deploy/arch-host/wazuh-waha.service.override.conf"
if [ -f "$OVERRIDE_SRC" ]; then
  sudo mkdir -p /etc/systemd/system/wazuh-waha.service.d
  install_unit "$OVERRIDE_SRC" /etc/systemd/system/wazuh-waha.service.d/override.conf
  sudo systemctl daemon-reload
  echo "Override instalado."
else
  echo "No hay override.conf en $OVERRIDE_SRC, se usa el unit commiteable tal cual."
fi

echo "=== 4. Drop-in de OnFailure= para wazuh-waha ==="
NOTIFY_DROPIN_SRC="$PROJECT_ROOT/deploy/arch-host/wazuh-waha.service.d-notify.conf"
if [ -f "$NOTIFY_DROPIN_SRC" ]; then
  sudo mkdir -p /etc/systemd/system/wazuh-waha.service.d
  install_unit "$NOTIFY_DROPIN_SRC" /etc/systemd/system/wazuh-waha.service.d/notify.conf
  sudo systemctl daemon-reload
  echo "Drop-in de OnFailure= instalado."
else
  echo "WARN: no encuentro $NOTIFY_DROPIN_SRC"
fi

echo "=== 5. Drop-in de OnFailure= para wazuh-agent ==="
AGENT_DROPIN_SRC="$PROJECT_ROOT/deploy/arch-host/wazuh-agent.service.d-notify.conf"
if [ -f "$AGENT_DROPIN_SRC" ]; then
  sudo mkdir -p /etc/systemd/system/wazuh-agent.service.d
  install_unit "$AGENT_DROPIN_SRC" /etc/systemd/system/wazuh-agent.service.d/notify.conf
  sudo systemctl daemon-reload
  echo "Drop-in de OnFailure= para agente instalado."
else
  echo "WARN: no encuentro $AGENT_DROPIN_SRC"
fi

echo "=== 6. Habilitar y arrancar relay ==="
sudo systemctl enable wazuh-waha.service
sudo systemctl restart wazuh-waha.service
echo "OK"

echo "=== 7. Instalar watchdog (chequea sesion WAHA cada 5 min) ==="
WATCHDOG_SERVICE="$PROJECT_ROOT/relay/systemd/wazuh-waha-watchdog.service"
WATCHDOG_TIMER="$PROJECT_ROOT/relay/systemd/wazuh-waha-watchdog.timer"
if [ -f "$WATCHDOG_SERVICE" ] && [ -f "$WATCHDOG_TIMER" ]; then
  install_unit "$WATCHDOG_SERVICE" /etc/systemd/system/wazuh-waha-watchdog.service
  install_unit "$WATCHDOG_TIMER" /etc/systemd/system/wazuh-waha-watchdog.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now wazuh-waha-watchdog.timer
  echo "Watchdog instalado y habilitado (cada 5 min)"
else
  echo "WARN: no encuentro los unit files del watchdog, saltando"
fi

echo "=== 8. Instalar boot-notify (heartbeat al iniciar el host) ==="
BOOT_NOTIFY_SERVICE="$PROJECT_ROOT/deploy/arch-host/wazuh-waha-boot-notify.service"
BOOT_NOTIFY_TIMER="$PROJECT_ROOT/deploy/arch-host/wazuh-waha-boot-notify.timer"
if [ -f "$BOOT_NOTIFY_SERVICE" ] && [ -f "$BOOT_NOTIFY_TIMER" ]; then
  install_unit "$BOOT_NOTIFY_SERVICE" /etc/systemd/system/wazuh-waha-boot-notify.service
  install_unit "$BOOT_NOTIFY_TIMER" /etc/systemd/system/wazuh-waha-boot-notify.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now wazuh-waha-boot-notify.timer
  echo "Boot-notify instalado y habilitado (OnBootSec=90s)"
else
  echo "WARN: no encuentro los unit files de boot-notify, saltando"
fi

echo "=== 9. Instalar watch_manager_ip (drift de IP del manager) ==="
DRIFT_SERVICE="$PROJECT_ROOT/deploy/arch-host/watch_manager_ip.service"
DRIFT_TIMER="$PROJECT_ROOT/deploy/arch-host/watch_manager_ip.timer"
if [ -f "$DRIFT_SERVICE" ] && [ -f "$DRIFT_TIMER" ]; then
  install_unit "$DRIFT_SERVICE" /etc/systemd/system/watch_manager_ip.service
  install_unit "$DRIFT_TIMER" /etc/systemd/system/watch_manager_ip.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now watch_manager_ip.timer
  echo "Drift detector instalado y habilitado (cada 5 min)"
else
  echo "WARN: no encuentro los unit files de drift, saltando"
fi

echo "=== 10. Instalar services oneshot de OnFailure= (notify) ==="
for UNIT in wazuh-agent-failure-notify.service wazuh-waha-failure-notify.service; do
  SRC="$PROJECT_ROOT/deploy/arch-host/$UNIT"
  if [ -f "$SRC" ]; then
    install_unit "$SRC" "/etc/systemd/system/$UNIT"
    echo "  $UNIT instalado (no requiere enable, lo dispara OnFailure=)"
  else
    echo "WARN: no encuentro $SRC"
  fi
done

echo "=== 11. Instalar health-check del agente (cada 5 min chequea ESTAB) ==="
AGENT_HEALTH_SERVICE="$PROJECT_ROOT/deploy/arch-host/wazuh-agent-health.service"
AGENT_HEALTH_TIMER="$PROJECT_ROOT/deploy/arch-host/wazuh-agent-health.timer"
if [ -f "$AGENT_HEALTH_SERVICE" ] && [ -f "$AGENT_HEALTH_TIMER" ]; then
  install_unit "$AGENT_HEALTH_SERVICE" /etc/systemd/system/wazuh-agent-health.service
  install_unit "$AGENT_HEALTH_TIMER" /etc/systemd/system/wazuh-agent-health.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now wazuh-agent-health.timer
  echo "Health-check del agente instalado y habilitado (cada 5 min)"
else
  echo "WARN: no encuentro los unit files de health-check, saltando"
fi

echo "=== 12. Verificar ==="
sleep 2
sudo systemctl status wazuh-waha.service --no-pager | head -5
echo "---"
curl -s http://localhost:8765/health || true
echo ""

echo "=== 13. Limpiar backups .shebak.bak (si quedo alguno) ==="
# El script fix_venv_shebangs.sh deja backups *.shebak.bak. Despues de verificar
# que todo arranca, se pueden borrar. Es seguro hacerlo automaticamente porque
# si algo fallo en el paso 1b, los archivos originales seguirian en los backups.
SHEBAK_COUNT=$(find "${PROJECT_ROOT}/relay/.venv/bin" -maxdepth 1 -name "*.shebak.bak" 2>/dev/null | wc -l)
if [[ ${SHEBAK_COUNT} -gt 0 ]]; then
  find "${PROJECT_ROOT}/relay/.venv/bin" -maxdepth 1 -name "*.shebak.bak" -delete
  echo "  ${SHEBAK_COUNT} backups .shebak.bak eliminados"
else
  echo "  No hay backups .shebak.bak"
fi

echo "=== Listo. Para ver logs: ==="
echo "  journalctl -u wazuh-waha -f"
echo "  journalctl -u wazuh-waha-watchdog -f"
echo "  journalctl -u wazuh-agent-failure-notify -f"
echo "  journalctl -u wazuh-waha-failure-notify -f"
echo "  journalctl -u wazuh-agent-health -f"