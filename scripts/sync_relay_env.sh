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
# Sincronizar TODAS las claves del .env (evita olvidar variables nuevas).
# Se ignoran comentarios y líneas vacías. El orden es el del archivo.
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" =~ ^# ]] && continue
  [[ "$key" =~ ^[A-Z0-9_]+$ ]] || continue
  key="${key%% }"; key="${key## }"
  value="${value## }"; value="${value%% }"
  [ -z "$value" ] && continue
  escaped="${value//\\/\\\\}"
  escaped="${escaped//\"/\\\"}"
  echo "${key}=\"${escaped}\""
done < <(grep -v '^[[:space:]]*#' "$SOURCE_ENV" | grep -v '^[[:space:]]*$') >> "$TMP_NEW"

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
