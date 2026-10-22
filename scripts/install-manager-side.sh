#!/usr/bin/env bash
# Instala la integración de wazuh-waha en el Wazuh Manager (local o remoto).
# Uso: sudo bash scripts/install-manager-side.sh [--relay-url http://host:8765]
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
ENV_FILE="$APP_DIR/.env"

getenv() {
  [ -f "$ENV_FILE" ] || return 1
  grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/' | sed -E "s/^'(.*)'$/\1/"
}

RELAY_URL="${RELAY_URL:-}"
for arg in "$@"; do
  case "$arg" in
    --relay-url=*) RELAY_URL="${arg#*=}" ;;
    --relay-url) shift; RELAY_URL="${1:-}" ;;
  esac
done

RELAY_PORT="$(getenv RELAY_PORT || true)"; RELAY_PORT="${RELAY_PORT:-8765}"
RELAY_API_KEY="$(getenv RELAY_API_KEY || true)"
MANAGER_HOST="$(getenv WAZUH_MANAGER_HOST || true)"
[ -z "$MANAGER_HOST" ] && MANAGER_HOST="$(getenv WAZUH_SERVER_IP || true)"
SSH_USER="$(getenv WAZUH_VM_SSH_USER || true)"
SSH_PORT="$(getenv WAZUH_VM_SSH_PORT || true)"; SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="$(getenv WAZUH_VM_SSH_KEY_PATH || true)"
STRICT="$(getenv WAZUH_VM_SSH_STRICT_HOST_KEY || true)"; STRICT="${STRICT:-yes}"

[ -n "$RELAY_API_KEY" ] || { echo "ERROR: RELAY_API_KEY vacía en .env"; exit 1; }

LOCAL_MANAGER=0
if [ -d /var/ossec ] && { [ -z "$MANAGER_HOST" ] || [ "$MANAGER_HOST" = "127.0.0.1" ] || [ "$MANAGER_HOST" = "localhost" ]; }; then
  LOCAL_MANAGER=1
fi
if [ "$LOCAL_MANAGER" -eq 1 ] && [ -z "$RELAY_URL" ]; then
  RELAY_URL="http://127.0.0.1:${RELAY_PORT}/alerts"
fi
if [ -z "$RELAY_URL" ]; then
  echo "ERROR: manager remoto detectado. Definir --relay-url http://<relay-host>:${RELAY_PORT}/alerts"
  exit 1
fi

echo "=== Instalación manager-side ==="
echo "  Manager : $([ "$LOCAL_MANAGER" -eq 1 ] && echo local || echo "$MANAGER_HOST")"
echo "  Relay   : $RELAY_URL"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/wsl-relay.conf" <<CONF
# Auto-generado por install-manager-side.sh
WAZUH_RELAY_URL=${RELAY_URL}
WAZUH_RELAY_API_KEY=${RELAY_API_KEY}
WAZUH_RELAY_TIMEOUT=5
CONF

INTEGRATION_SNIPPET='  <integration>
    <name>custom-whatsapp</name>
    <level>8</level>
    <alert_format>json</alert_format>
    <options>--script /var/ossec/integrations/custom/whatsapp_alert.py --timeout 5</options>
  </integration>'

inject_python='import sys
conf_path = "/var/ossec/etc/ossec.conf"
snippet = sys.stdin.read()
with open(conf_path, "r", encoding="utf-8") as f:
    content = f.read()
if "custom-whatsapp" not in content:
    idx = content.rfind("</ossec_config>")
    if idx == -1:
        raise SystemExit("no </ossec_config>")
    content = content[:idx] + snippet + content[idx:]
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("INJECT_OK")
else:
    print("ALREADY_PRESENT")
'

install_local() {
  local wazuh_group="wazuh"
  getent group wazuh >/dev/null 2>&1 || wazuh_group="root"
  mkdir -p /var/ossec/integrations/custom
  install -m 750 -o root -g "$wazuh_group" "$APP_DIR/manager-side/custom/whatsapp_alert.py" /var/ossec/integrations/custom/whatsapp_alert.py
  install -m 640 -o root -g "$wazuh_group" "$tmp/wsl-relay.conf" /var/ossec/etc/wsl-relay.conf
  if [ -f "$APP_DIR/manager-side/rules/local_rules.xml" ]; then
    install -m 640 -o root -g "$wazuh_group" "$APP_DIR/manager-side/rules/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
  fi
  cp /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak.$(date +%s)"
  printf '%s\n' "$INTEGRATION_SNIPPET" | python3 -c "$inject_python"
  if systemctl list-unit-files | grep -q '^wazuh-manager.service'; then
    systemctl restart wazuh-manager
  elif [ -x /var/ossec/bin/wazuh-control ]; then
    /var/ossec/bin/wazuh-control restart
  fi
  echo "  [OK] Integración instalada en el manager local"
}

install_remote() {
  [ -n "$SSH_USER" ] || { echo "ERROR: WAZUH_VM_SSH_USER vacío"; exit 1; }
  local ssh_opts=(-p "$SSH_PORT" -o "StrictHostKeyChecking=$STRICT" -o BatchMode=yes)
  local scp_opts=(-P "$SSH_PORT" -o "StrictHostKeyChecking=$STRICT" -o BatchMode=yes)
  [ -n "$SSH_KEY" ] && ssh_opts+=(-i "$SSH_KEY" -o IdentitiesOnly=yes) && scp_opts+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
  local dest="$SSH_USER@$MANAGER_HOST"

  scp "${scp_opts[@]}" "$APP_DIR/manager-side/custom/whatsapp_alert.py" "$dest:/tmp/whatsapp_alert.py"
  scp "${scp_opts[@]}" "$tmp/wsl-relay.conf" "$dest:/tmp/wsl-relay.conf"
  if [ -f "$APP_DIR/manager-side/rules/local_rules.xml" ]; then
    scp "${scp_opts[@]}" "$APP_DIR/manager-side/rules/local_rules.xml" "$dest:/tmp/local_rules.xml"
  fi
  ssh "${ssh_opts[@]}" "$dest" 'sudo -n true' || {
    echo "ERROR: el manager remoto requiere sudo sin contraseña para $SSH_USER"
    exit 1
  }
  ssh "${ssh_opts[@]}" "$dest" "sudo -n mkdir -p /var/ossec/integrations/custom && \
    sudo -n install -m 750 -o root -g wazuh /tmp/whatsapp_alert.py /var/ossec/integrations/custom/whatsapp_alert.py && \
    sudo -n install -m 640 -o root -g wazuh /tmp/wsl-relay.conf /var/ossec/etc/wsl-relay.conf && \
    (test -f /tmp/local_rules.xml && sudo -n install -m 640 -o root -g wazuh /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml || true) && \
    sudo -n cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.\$(date +%s)"
  printf '%s\n' "$INTEGRATION_SNIPPET" | ssh "${ssh_opts[@]}" "$dest" "sudo -n python3 -c '$inject_python'"
  ssh "${ssh_opts[@]}" "$dest" "if sudo -n systemctl list-unit-files | grep -q '^wazuh-manager.service'; then sudo -n systemctl restart wazuh-manager; elif sudo -n test -x /var/ossec/bin/wazuh-control; then sudo -n /var/ossec/bin/wazuh-control restart; fi"
  echo "  [OK] Integración instalada en el manager remoto"
}

if [ "$LOCAL_MANAGER" -eq 1 ]; then
  install_local
else
  install_remote
fi
