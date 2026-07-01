#!/bin/bash
# install-wazuh-waha.sh - Instala el relay como servicio systemd.
# Ejecutar MANUALMENTE en una terminal con TTY (sandbox bloquea sudo -S).
#
# Asume que el proyecto está en ~/Desktop/wazuh-waha/.
# Si está en otro path, exportar PROJECT_ROOT antes de correr.

set -e

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/Desktop/wazuh-waha}"

echo "=== Verificando precondiciones ==="
if [ ! -d "$PROJECT_ROOT" ]; then
  echo "ERROR: $PROJECT_ROOT no existe. Exportar PROJECT_ROOT o mover el proyecto ahi."
  exit 1
fi

UNIT_SRC="$PROJECT_ROOT/relay/systemd/wazuh-waha.service"
if [ ! -f "$UNIT_SRC" ]; then
  echo "ERROR: no encuentro $UNIT_SRC"
  exit 1
fi

echo "=== 1. Instalar unit file ==="
sudo cp "$UNIT_SRC" /etc/systemd/system/wazuh-waha.service
sudo systemctl daemon-reload
echo "OK"

echo "=== 2. Crear directorios de log y state ==="
sudo mkdir -p /var/log/wazuh-waha /var/lib/wazuh-waha
sudo chown -R "$USER:$USER" /var/log/wazuh-waha /var/lib/wazuh-waha
echo "OK"

echo "=== 3. Si hay override.conf de deploy/, instalarlo ==="
OVERRIDE_SRC="$PROJECT_ROOT/deploy/arch-host/wazuh-waha.service.override.conf"
if [ -f "$OVERRIDE_SRC" ]; then
  sudo mkdir -p /etc/systemd/system/wazuh-waha.service.d
  sudo cp "$OVERRIDE_SRC" /etc/systemd/system/wazuh-waha.service.d/override.conf
  sudo systemctl daemon-reload
  echo "Override instalado."
else
  echo "No hay override.conf en $OVERRIDE_SRC, se usa el unit commiteable tal cual."
fi

echo "=== 4. Habilitar y arrancar ==="
sudo systemctl enable wazuh-waha.service
sudo systemctl restart wazuh-waha.service
echo "OK"

echo "=== 5. Instalar watchdog (chequea sesion WAHA cada 5 min) ==="
WATCHDOG_SERVICE="$PROJECT_ROOT/relay/systemd/wazuh-waha-watchdog.service"
WATCHDOG_TIMER="$PROJECT_ROOT/relay/systemd/wazuh-waha-watchdog.timer"
if [ -f "$WATCHDOG_SERVICE" ] && [ -f "$WATCHDOG_TIMER" ]; then
  sudo cp "$WATCHDOG_SERVICE" /etc/systemd/system/wazuh-waha-watchdog.service
  sudo cp "$WATCHDOG_TIMER" /etc/systemd/system/wazuh-waha-watchdog.timer
  sudo systemctl daemon-reload
  sudo systemctl enable wazuh-waha-watchdog.timer
  sudo systemctl start wazuh-waha-watchdog.timer
  echo "Watchdog instalado y habilitado (cada 5 min)"
else
  echo "WARN: no encuentro los unit files del watchdog, saltando"
fi

echo "=== 6. Verificar ==="
sleep 2
sudo systemctl status wazuh-waha.service --no-pager
echo "---"
curl -s http://localhost:8765/health
echo ""

echo "=== Listo. Para ver logs: ==="
echo "  journalctl -u wazuh-waha -f"
echo "  journalctl -u wazuh-waha-watchdog -f"
