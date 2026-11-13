#!/usr/bin/env bash
# =============================================================================
# export-logs.sh - Genera un archivo unico con el historial del stack.
# =============================================================================
# Reune en un solo fichero de texto:
#   - journal del relay, monitor, respaldos y avisos del host
#   - logs rotados del relay (/var/log/wazuh-waha/wazuh-waha-*.log)
#   - logs de los contenedores WAHA y dashboard
#   - eventos de infraestructura (eventos.log)
#   - ultimas alertas del manager Wazuh
#   - resumen de respaldos existentes
#
# Uso:
#   bash scripts/export-logs.sh
#   bash scripts/export-logs.sh --lines 5000
#   bash scripts/export-logs.sh --output /tmp/mi-historial.log --open
#
# El archivo por defecto es:
#   /var/log/wazuh-waha/historial-wazuh-waha.log
# =============================================================================
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${WAZUH_WAHA_LOG_DIR:-/var/log/wazuh-waha}"
OUTPUT="${WAZUH_WAHA_HISTORY_FILE:-$LOG_DIR/historial-wazuh-waha.log}"
LINES=2000
OPEN=0
SINCE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --lines) LINES="${2:-2000}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --since) SINCE="${2:-}"; shift 2 ;;
    --open) OPEN=1; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "Opcion desconocida: $1" >&2; exit 2 ;;
  esac
done

case "$LINES" in
  ''|*[!0-9]*) echo "--lines debe ser un numero" >&2; exit 2 ;;
esac
LINES=$((LINES < 50 ? 50 : LINES))
LINES=$((LINES > 20000 ? 20000 : LINES))

mkdir -p "$(dirname "$OUTPUT")"
umask 027
TMP="$(mktemp "${OUTPUT}.tmp.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

sanitize() {
  sed -E \
    -e 's#(bot)[0-9]+:[A-Za-z0-9_-]+#\1<redacted>#g' \
    -e 's#([?&](token|api_key|apikey|key|password|pass)=)[^&[:space:]]+#\1<redacted>#gi' \
    -e 's#(X-Api-Key:[[:space:]]*)[^[:space:]]+#\1<redacted>#gi' \
    -e 's#(Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+)[^[:space:]]+#\1<redacted>#gi'
}

journal_section() {
  local title="$1"; shift
  local units=("$@")
  echo
  echo "===== $title ====="
  if command -v journalctl >/dev/null 2>&1; then
    local args=(-n "$LINES" --no-pager -q -o short-iso)
    for unit in "${units[@]}"; do
      args+=(-u "$unit")
    done
    if [ -n "$SINCE" ]; then
      args+=(--since "$SINCE")
    fi
    journalctl "${args[@]}" 2>&1 || true
  else
    echo "(journalctl no disponible)"
  fi
}

{
  echo "================================================================================"
  echo " HISTORIAL WAZUH-WAHA"
  echo " Generado: $(date -Is)"
  echo " Host: $(hostname)"
  echo " IP local: $(ip -4 route get 1 2>/dev/null | awk '/src/ {print $7; exit}')"
  echo " Proyecto: $PROJECT_ROOT"
  echo " Lineas por seccion: $LINES"
  echo "================================================================================"

  journal_section "RELAY (wazuh-waha.service)" "wazuh-waha"
  journal_section "MONITOR Y AVISOS DEL HOST" "wazuh-waha-monitor" "wazuh-waha-boot-notify" "wazuh-waha-shutdown-notify" "wazuh-waha-failure-notify"
  journal_section "RESPALDOS" "wazuh-waha-backup"

  echo
  echo "===== LOGS ROTADOS DEL RELAY ====="
  if compgen -G "$LOG_DIR/wazuh-waha-*.log" >/dev/null 2>&1; then
    # Los 8 archivos mas recientes; 400 lineas por archivo para no explotar.
    while IFS= read -r file; do
      echo
      echo "--- $file"
      tail -n 400 "$file" 2>/dev/null || true
    done < <(ls -1t "$LOG_DIR"/wazuh-waha-*.log 2>/dev/null | head -8)
  else
    echo "(sin logs rotados en $LOG_DIR)"
  fi

  echo
  echo "===== CONTENEDOR WAHA ====="
  docker logs --tail "$LINES" wazuh-waha 2>&1 || echo "(no disponible)"
  echo
  echo "===== CONTENEDOR DASHBOARD ====="
  docker logs --tail "$LINES" wazuh-waha-dashboard 2>&1 || echo "(no disponible)"

  echo
  echo "===== EVENTOS DE INFRAESTRUCTURA ====="
  if [ -f "$LOG_DIR/eventos.log" ]; then
    tail -n "$LINES" "$LOG_DIR/eventos.log"
  else
    echo "(sin eventos registrados)"
  fi

  echo
  echo "===== ULTIMAS ALERTAS WAZUH ====="
  if [ -f /var/ossec/logs/alerts/alerts.json ]; then
    tail -n 200 /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
  else
    echo "(no existe /var/ossec/logs/alerts/alerts.json)"
  fi

  echo
  echo "===== RESPALDOS DISPONIBLES ====="
  if [ -d /var/backups/wazuh-waha ]; then
    ls -lah /var/backups/wazuh-waha 2>/dev/null || true
  else
    echo "(no existe /var/backups/wazuh-waha)"
  fi

  echo
  echo "===== FIN DEL HISTORIAL ====="
} 2>&1 | sanitize >"$TMP"

chmod 640 "$TMP"
mv -f "$TMP" "$OUTPUT"
trap - EXIT
echo "$OUTPUT"

if [ "$OPEN" -eq 1 ] && [ -t 1 ]; then
  "${PAGER:-less}" "$OUTPUT"
fi
