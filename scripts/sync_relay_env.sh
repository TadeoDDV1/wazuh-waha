#!/bin/bash
# =============================================================================
# sync_relay_env.sh - Sincroniza /etc/wazuh-waha/relay.env desde el .env del repo.
# =============================================================================
# Fuente de verdad: ~/Desktop/wazuh-waha/.env
# Destino:         /etc/wazuh-waha/relay.env (root:root 0600)
#
# Por que: el relay (servicio wazuh-waha.service), el waha-watchdog y el
# watch_manager_ip leen de /etc/wazuh-waha/relay.env mediante
# EnvironmentFile= en sus units. Si esa config queda desfasada del .env del
# repo, el relay usa defaults y los watchers quedan ciegos.
#
# Uso:
#   bash scripts/sync_relay_env.sh           # preview, dry-run
#   sudo bash scripts/sync_relay_env.sh apply
#
# El .env del repo puede tener secrets con espacios (ej: Gmail App Password).
# Para evitar que `set -a; source /etc/wazuh-waha/relay.env; set +a` rompa por
# espacios, este script QUOTA los valores con espacios antes de escribirlos.
# =============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_ENV="$PROJECT_ROOT/.env"
TARGET_ENV="/etc/wazuh-waha/relay.env"

DRY_RUN=1
[ "${1:-}" = "apply" ] && DRY_RUN=0

if [ ! -f "$SOURCE_ENV" ]; then
  echo "ERROR: $SOURCE_ENV no existe" >&2
  exit 1
fi

if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] Mostrando destino que se generaria. Re-ejecutar con 'apply' para aplicar."
  BACKUP_OPT=""
else
  sudo mkdir -p "$(dirname "$TARGET_ENV")"
  if [ -f "$TARGET_ENV" ]; then
    BACKUP_OPT="/etc/wazuh-waha/relay.env.bak.$(date +%s)"
    sudo cp "$TARGET_ENV" "$BACKUP_OPT"
    echo "[apply] Backup -> $BACKUP_OPT"
  fi
fi

# Generar el archivo destino. Usar un path escribible por root si estamos
# en modo apply, sino /tmp/ regular sirve.
if [ "$DRY_RUN" = 0 ]; then
  TMP_NEW="$(mktemp /tmp/relay.env.XXXXXX)"
else
  TMP_NEW="/tmp/relay.env.new"
fi
rm -f "$TMP_NEW"
{
  echo "# Auto-generado desde $SOURCE_ENV"
  echo "# Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "# Fuente de verdad: el .env del repo. NO editar este archivo a mano."
  echo "# Para regenerar: sudo bash $PROJECT_ROOT/scripts/sync_relay_env.sh apply"
  echo ""
} > "$TMP_NEW"

# Claves a sincronizar, en orden estable para diffs predecibles
KEYS=(
  WAZUH_SERVER_IP
  WAZUH_SERVER_IP_FALLBACK
  AUTO_RECONCILE
  WAZUH_MANAGER_HOST
  WAZUH_MANAGER_API_USER
  WAZUH_MANAGER_API_PASS
  WAZUH_MANAGER_API_PORT
  WAZUH_MANAGER_API_VERIFY_TLS
  ADMIN_PHONE
  WAHA_HOST
  WAHA_API_KEY
  WAHA_SESSION
  WAHA_LOG_LEVEL
  WAHA_HOOK_URL
  WAHA_RECOVERY_COOLDOWN_SEC
  WAHA_RECOVERY_MAX_WAIT_SEC
  WAHA_WATCHDOG_INTERVAL_SEC
  RELAY_PORT
  RELAY_BIND
  RELAY_API_KEY
  RELAY_READONLY_API_KEY
  RELAY_DEDUP_TTL
  RELAY_MIN_LEVEL_UNKNOWN
  RELAY_LOG_DIR
  RELAY_LIB_DIR
  RELAY_WORKERS
  RELAY_LIFESPAN_TIMEOUT
  SESSION_TTL_HOURS
  MAX_BODY_BYTES
  TRUSTED_PROXIES
  ENABLE_DOCS
  TRAFFIC_SOURCE
  TRAFFIC_POLL_INTERVAL_SEC
  TRAFFIC_JOURNAL_PATH
  WAZUH_VM_SSH_USER
  WAZUH_VM_SSH_PORT
  WAZUH_VM_SSH_KEY_PATH
  WAZUH_VM_SSH_STRICT_HOST_KEY
  ALLOWED_ORIGINS
  EMAIL_PROVIDER
  SMTP_HOST
  SMTP_PORT
  SMTP_USER
  SMTP_PASS
  SMTP_FROM
  SMTP_TLS
  ADMIN_EMAIL
  HYVOR_BASE_URL
  HYVOR_API_KEY
  HYVOR_FROM
)

# Parsear .env (ignorar comentarios / líneas vacías)
declare -A VALUES
while IFS='=' read -r key value; do
  # Saltar comentarios / blanks
  [[ -z "$key" || "$key" =~ ^# ]] && continue
  # Trim
  key="${key%% }"; key="${key## }"
  value="${value## }"; value="${value%% }"
  VALUES["$key"]="$value"
done < <(grep -v '^[[:space:]]*#' "$SOURCE_ENV" | grep -v '^[[:space:]]*$')

# Escribir al archivo temporal. Quote SIEMPRE los valores con comillas dobles
# para sobrevivir espacios, caracteres especiales y Gmail App Passwords.
for k in "${KEYS[@]}"; do
  v="${VALUES[$k]:-}"
  if [ -n "$v" ]; then
    # Escapar backslash y doble comilla dentro del valor
    escaped="${v//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    echo "${k}=\"${escaped}\""
  fi
done >> "$TMP_NEW"

echo ""
echo "=== Preview (sin secrets): ==="
grep -v -E '(PASS|API_KEY|SMTP_PASS|SMTP_USER|SMTP_FROM|RELAY_API_KEY|WAHA_API_KEY)' "$TMP_NEW" | head -25
echo ""
echo "=== Total keys: $(grep -E '^[A-Z_]+=' "$TMP_NEW" | wc -l) ==="
echo ""

if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] No se escribio nada. Aplicar con: sudo bash $0 apply"
  rm -f "$TMP_NEW"
  exit 0
fi

# Aplicar
sudo mv "$TMP_NEW" "$TARGET_ENV"
sudo chown root:root "$TARGET_ENV"
sudo chmod 600 "$TARGET_ENV"
echo "[apply] OK: $TARGET_ENV actualizado"
echo ""
echo "Reiniciar servicios para que releean: sudo systemctl restart wazuh-waha wazuh-waha-watchdog watch_manager_ip"
