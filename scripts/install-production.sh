#!/usr/bin/env bash
# Instalación base de wazuh-waha en un servidor dedicado.
# Uso: sudo bash scripts/install-production.sh [--skip-deps]
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecutar con sudo/root." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
APP_USER="${APP_USER:-wazuh-waha}"
SKIP_DEPS=0
for arg in "$@"; do
  [ "$arg" = "--skip-deps" ] && SKIP_DEPS=1
done

ok()   { echo "  [OK]   $*"; }
info() { echo "  [INFO] $*"; }
warn() { echo "  [WARN] $*"; }
fail() { echo "  [FAIL] $*" >&2; exit 1; }

echo "=== Instalación de wazuh-waha ==="
echo "  Proyecto : $APP_DIR"
echo "  Usuario  : $APP_USER"

if [ "$SKIP_DEPS" -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
  info "Instalando dependencias del sistema..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  apt-get install -y -qq python3 python3-venv python3-pip git curl openssl rsync \
    ufw fail2ban logrotate ca-certificates || true
  if ! command -v docker >/dev/null 2>&1; then
    apt-get install -y -qq docker.io || true
  fi
  if ! docker compose version >/dev/null 2>&1; then
    apt-get install -y -qq docker-compose-v2 || apt-get install -y -qq docker-compose-plugin || true
  fi
  if ! command -v caddy >/dev/null 2>&1; then
    apt-get install -y -qq caddy || warn "No se pudo instalar Caddy; configurar TLS manualmente"
  fi
fi

command -v python3 >/dev/null 2>&1 || fail "python3 no disponible"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' \
  || fail "Se requiere Python >= 3.11"
command -v docker >/dev/null 2>&1 || fail "Docker no disponible"
docker compose version >/dev/null 2>&1 || fail "docker compose no disponible"

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  info "Creando usuario de servicio $APP_USER..."
  useradd --system --home-dir /var/lib/wazuh-waha --shell /usr/sbin/nologin \
    --comment "wazuh-waha service" "$APP_USER"
fi
APP_GROUP="$(id -gn "$APP_USER")"
ok "Usuario/grupo: $APP_USER:$APP_GROUP"

info "Creando directorios..."
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" /var/log/wazuh-waha
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" /var/lib/wazuh-waha
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" /var/backups/wazuh-waha
install -d -m 0750 -o root -g "$APP_GROUP" /etc/wazuh-waha
install -d -m 0750 -o root -g "$APP_GROUP" /etc/wazuh-waha/ssh
ok "Directorios listos"

if [ ! -f "$APP_DIR/.env" ]; then
  if [ -f "$APP_DIR/.env.production.example" ]; then
    cp "$APP_DIR/.env.production.example" "$APP_DIR/.env"
    ok "Creado .env desde .env.production.example"
  else
    fail "No existe .env ni .env.production.example"
  fi
fi
chown root:"$APP_GROUP" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

generate_key() {
  local current
  current="$(grep -E "^$1=" "$APP_DIR/.env" | tail -1 | cut -d= -f2- || true)"
  if [ -z "$current" ] || [[ "$current" == CAMBIAR* ]]; then
    local key
    key="$(openssl rand -hex 24)"
    if grep -qE "^$1=" "$APP_DIR/.env"; then
      sed -i -E "s|^$1=.*|$1=$key|" "$APP_DIR/.env"
    else
      printf '%s=%s\n' "$1" "$key" >> "$APP_DIR/.env"
    fi
    ok "Generada $1"
  fi
}
generate_key RELAY_API_KEY
generate_key WAHA_API_KEY

info "Preparando entorno virtual..."
if [ ! -x "$APP_DIR/relay/.venv/bin/uvicorn" ]; then
  rm -rf "$APP_DIR/relay/.venv"
  python3 -m venv "$APP_DIR/relay/.venv"
fi
"$APP_DIR/relay/.venv/bin/pip" install --upgrade pip -q
"$APP_DIR/relay/.venv/bin/pip" install -e "$APP_DIR/relay" -q
ok "Dependencias Python instaladas"

info "Ajustando permisos del proyecto..."
chown -R root:"$APP_GROUP" "$APP_DIR"
chmod -R g+rX "$APP_DIR"
chmod 600 "$APP_DIR/.env"
ok "Permisos ajustados"

info "Sincronizando /etc/wazuh-waha/relay.env..."
bash "$APP_DIR/scripts/sync_relay_env.sh" apply >/dev/null
chown root:"$APP_GROUP" /etc/wazuh-waha/relay.env
chmod 640 /etc/wazuh-waha/relay.env
ok "relay.env generado"

info "Instalando unidad systemd del relay..."
RELAY_PORT="$(grep -E '^RELAY_PORT=' "$APP_DIR/.env" | cut -d= -f2- | tr -d '"' || true)"
RELAY_PORT="${RELAY_PORT:-8765}"
sed -e "s|__APP_USER__|$APP_USER|g" \
    -e "s|__APP_DIR__|$APP_DIR|g" \
    -e "s|__RELAY_PORT__|$RELAY_PORT|g" \
    "$APP_DIR/deploy/production/systemd/wazuh-waha.service" \
    > /etc/systemd/system/wazuh-waha.service
sed -e "s|__APP_USER__|$APP_USER|g" \
    -e "s|__APP_DIR__|$APP_DIR|g" \
    "$APP_DIR/deploy/production/systemd/wazuh-waha-watchdog.service" \
    > /etc/systemd/system/wazuh-waha-watchdog.service
cp "$APP_DIR/deploy/production/systemd/wazuh-waha-watchdog.timer" /etc/systemd/system/wazuh-waha-watchdog.timer
chmod 644 /etc/systemd/system/wazuh-waha.service /etc/systemd/system/wazuh-waha-watchdog.service /etc/systemd/system/wazuh-waha-watchdog.timer
systemctl daemon-reload
ok "Unidades systemd instaladas"

info "Configurando Caddy..."
DOMAIN="$(grep -E '^DOMAIN=' "$APP_DIR/.env" | cut -d= -f2- | tr -d '"' || true)"
if command -v caddy >/dev/null 2>&1; then
  if [ -n "$DOMAIN" ]; then
    CADDY_SITE="$DOMAIN"
  else
    CADDY_SITE=":80"
    warn "DOMAIN vacío: Caddy servirá HTTP en :80 (usar túnel SSH/VPN)"
  fi
  if [ -f /etc/caddy/Caddyfile ]; then
    cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
  fi
  sed "s|__DOMAIN__|$CADDY_SITE|g" "$APP_DIR/deploy/production/Caddyfile" > /etc/caddy/Caddyfile
  chown root:caddy /etc/caddy/Caddyfile 2>/dev/null || true
  chmod 644 /etc/caddy/Caddyfile
  install -d -m 0750 -o caddy -g caddy /var/log/caddy 2>/dev/null || true
  systemctl enable caddy >/dev/null 2>&1 || true
  ok "Caddyfile instalado para $CADDY_SITE"
else
  warn "Caddy no instalado; configurar TLS/reverse proxy manualmente"
fi

info "Configurando sudoers para acciones del dashboard..."
SUDOERS=/etc/sudoers.d/wazuh-waha
cat > "$SUDOERS" <<SUDO
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart wazuh-waha.service
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart wazuh-agent.service
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl start wazuh-agent.service
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl stop wazuh-agent.service
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl enable wazuh-waha-watchdog.timer --now
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl disable wazuh-waha-watchdog.timer --now
SUDO
chmod 440 "$SUDOERS"
if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$SUDOERS" >/dev/null || fail "sudoers inválido"
fi
ok "sudoers instalado"

systemctl enable wazuh-waha.service >/dev/null 2>&1 || true

cat <<NEXT

=== Instalación base completada ===

Siguientes pasos:
  1. Editar secretos y datos reales:
       sudo nano $APP_DIR/.env
     (WAZUH_MANAGER_API_PASS, ADMIN_PHONE, Telegram, SMTP, DOMAIN, etc.)

  2. Desplegar:
       sudo bash $APP_DIR/scripts/deploy-production.sh

  3. Integrar con el Wazuh Manager:
       sudo bash $APP_DIR/scripts/install-manager-side.sh

  4. Configuraciones manuales:
       - DNS del dominio
       - QR de WhatsApp en el dashboard
       - Token/chat de Telegram
       - Usuario API de Wazuh
       - Firewall (ufw) y backups externos

Documentación: $APP_DIR/docs/DEPLOYMENT.md
NEXT
