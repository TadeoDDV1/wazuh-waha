#!/usr/bin/env bash
# =============================================================================
# backup.sh - Respaldo de configuracion y estado de wazuh-waha.
# =============================================================================
# Uso:
#   sudo bash scripts/backup.sh
#   sudo BACKUP_RETENTION_DAYS=30 bash scripts/backup.sh
#
# Genera un directorio por corrida:
#   /var/backups/wazuh-waha/20261106T203000Z/
#     env/.env
#     etc/wazuh-waha/...
#     systemd/...
#     wazuh/ossec.conf, client.keys, wsl-relay.conf, integration...
#     state/...
#     logs/eventos.log
#     alerts/alerts-*.jsonl
#     waha_sessions.tar.gz
#     MANIFEST.txt
#     SHA256SUMS
#
# La unidad wazuh-waha-backup.timer lo ejecuta a diario. El script es
# idempotente y usa flock para que dos ejecuciones no se pisen.
# =============================================================================
set -Eeuo pipefail
umask 077

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${APP_DIR:-$PROJECT_ROOT}"
ENV_FILE="$APP_DIR/.env"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/wazuh-waha}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${WAZUH_WAHA_LOG_DIR:-/var/log/wazuh-waha}"
LOG_FILE="${BACKUP_LOG:-$LOG_DIR/backup.log}"
FAILED=0
WARNINGS=0

mkdir -p "$BACKUP_ROOT" "$LOG_DIR" 2>/dev/null || true
exec 9>"$BACKUP_ROOT/.backup.lock"
if ! flock -n 9; then
  echo "Ya hay un respaldo en curso; salgo." >&2
  exit 0
fi

getenv() {
  [ -f "$ENV_FILE" ] || return 1
  grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- \
    | sed -E 's/^"(.*)"$/\1/' | sed -E "s/^'(.*)'$/\1/"
}

log() {
  local msg="[$(date -u +%FT%TZ)] $*"
  printf '%s\n' "$msg"
  printf '%s\n' "$msg" >>"$LOG_FILE" 2>/dev/null || true
}
warn() { log "WARN: $*"; WARNINGS=$((WARNINGS + 1)); }
fail() { log "ERROR: $*"; FAILED=$((FAILED + 1)); }

copy_item() {
  local src="$1" dst="$2" required="${3:-0}"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$DEST/$dst")"
    if cp -a "$src" "$DEST/$dst" 2>>"$LOG_FILE"; then
      log "  + $src"
    else
      fail "No se pudo copiar $src"
    fi
  elif [ "$required" = "1" ]; then
    fail "Falta archivo requerido: $src"
  else
    warn "No existe (se omite): $src"
  fi
}

copy_glob() {
  local pattern="$1" dst="$2"
  local found=0
  shopt -s nullglob
  local files=($pattern)
  shopt -u nullglob
  for src in "${files[@]}"; do
    found=1
    copy_item "$src" "$dst/$(basename "$src")"
  done
  [ "$found" -eq 1 ] || warn "Sin coincidencias para $pattern"
}

DEST="$BACKUP_ROOT/$STAMP"
[ ! -e "$DEST" ] || DEST="$BACKUP_ROOT/${STAMP}-$$"
mkdir -p "$DEST"
chmod 700 "$DEST"

log "=== Inicio de respaldo wazuh-waha ==="
log "Destino: $DEST"

# ── Configuracion del proyecto ─────────────────────────────────────────────
copy_item "$ENV_FILE" "env/.env" 1
copy_item "$APP_DIR/docker-compose.yml" "project/docker-compose.yml"
copy_item "$APP_DIR/deploy/production/docker-compose.prod.yml" "project/docker-compose.prod.yml"
copy_item "$APP_DIR/deploy/production/Caddyfile" "project/Caddyfile"

# ── Configuracion del sistema ───────────────────────────────────────────────
copy_item "/etc/wazuh-waha" "etc/wazuh-waha" 1
copy_item "/etc/caddy/Caddyfile" "etc/Caddyfile"
copy_item "/etc/logrotate.d/wazuh-waha" "etc/logrotate.d-wazuh-waha"

# ── Unidades systemd ────────────────────────────────────────────────────────
copy_glob "/etc/systemd/system/wazuh-waha*.service" "systemd"
copy_glob "/etc/systemd/system/wazuh-waha*.timer" "systemd"
copy_glob "/etc/systemd/system/wazuh-waha.service.d/*.conf" "systemd/dropins"
copy_item "/etc/sudoers.d/wazuh-waha" "systemd/sudoers-wazuh-waha"

# ── Wazuh manager ───────────────────────────────────────────────────────────
copy_item "/var/ossec/etc/ossec.conf" "wazuh/ossec.conf" 1
copy_item "/var/ossec/etc/client.keys" "wazuh/client.keys"
copy_item "/var/ossec/etc/shared/default/agent.conf" "wazuh/agent.conf"
copy_item "/var/ossec/etc/wsl-relay.conf" "wazuh/wsl-relay.conf"
copy_item "/var/ossec/integrations/custom/whatsapp_alert.py" "wazuh/integrations/whatsapp_alert.py"

# ── Estado del relay ────────────────────────────────────────────────────────
copy_glob "/var/lib/wazuh-waha/*.json" "state"
copy_glob "/var/lib/wazuh-waha/*.jsonl" "state"
copy_item "/var/lib/wazuh-waha/manager_ip_state" "state/manager_ip_state"
copy_item "/var/lib/wazuh-waha/boot_notified" "state/boot_notified"

# ── Eventos y auditoria ─────────────────────────────────────────────────────
copy_item "$LOG_DIR/eventos.log" "logs/eventos.log"
copy_item "$LOG_DIR/eventos.jsonl" "logs/eventos.jsonl"
copy_item "$LOG_DIR/backup.log" "logs/backup.log"

# ── Ultimos respaldos de alertas (JSONL) ────────────────────────────────────
# RELAY_BACKUP_DIR puede apuntar a /var/backups/wazuh-waha (mismo BACKUP_ROOT)
# o al directorio backups/ del proyecto. Soportamos ambos.
ALERTS_DIR="${RELAY_BACKUP_DIR:-$(getenv RELAY_BACKUP_DIR || true)}"
ALERTS_DIR="${ALERTS_DIR:-$APP_DIR/backups}"
if [ -d "$ALERTS_DIR" ]; then
  mkdir -p "$DEST/alerts"
  shopt -s nullglob
  alert_files=("$ALERTS_DIR"/alerts-*.jsonl)
  shopt -u nullglob
  copied=0
  for f in "${alert_files[@]}"; do
    if [ -f "$f" ] && [ "$(find "$f" -mtime -14 -print -quit 2>/dev/null)" ]; then
      if cp -a "$f" "$DEST/alerts/" 2>>"$LOG_FILE"; then
        copied=$((copied + 1))
      else
        warn "No se pudo copiar $f"
      fi
    fi
  done
  [ "$copied" -gt 0 ] || warn "Sin archivos de alertas recientes en $ALERTS_DIR"
else
  warn "No existe $ALERTS_DIR"
fi

# ── Volumen de WAHA (sesion de WhatsApp, evita reescanear QR) ───────────────
backup_waha_volume() {
  local tmp="$DEST/.waha_sessions.tar.gz.tmp"
  local final="$DEST/waha_sessions.tar.gz"
  local image

  if docker inspect wazuh-waha >/dev/null 2>&1; then
    if docker exec wazuh-waha tar -czf - -C /app/.sessions . >"$tmp" 2>>"$LOG_FILE"; then
      if tar -tzf "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$final"
        log "  + volumen Docker wazuh_waha_sessions"
        return 0
      fi
      warn "El tar del volumen WAHA quedo corrupto (docker exec)"
    fi
    rm -f "$tmp"
  fi

  image="$(docker inspect -f '{{.Config.Image}}' wazuh-waha 2>/dev/null || true)"
  image="${image:-${WAHA_IMAGE:-devlikeapro/waha:latest}}"
  if docker run --rm --entrypoint tar \
      -v wazuh_waha_sessions:/data:ro \
      -v "$DEST":/backup \
      "$image" -czf /backup/waha_sessions.tar.gz -C /data . >>"$LOG_FILE" 2>&1; then
    if tar -tzf "$final" >/dev/null 2>&1; then
      log "  + volumen Docker wazuh_waha_sessions (imagen $image)"
      return 0
    fi
    warn "El tar del volumen WAHA quedo corrupto (docker run)"
  fi
  rm -f "$final"
  fail "No se pudo respaldar el volumen WAHA"
  return 1
}
backup_waha_volume || true

# ── Verificaciones minimas ──────────────────────────────────────────────────
[ -s "$DEST/env/.env" ] || fail "El .env respaldado esta vacio"
[ -s "$DEST/wazuh/ossec.conf" ] || fail "El ossec.conf respaldado esta vacio"
[ -s "$DEST/waha_sessions.tar.gz" ] || fail "No hay respaldo del volumen WAHA"

# ── Manifiesto y checksums ──────────────────────────────────────────────────
{
  echo "Backup wazuh-waha"
  echo "Fecha: $(date -Is)"
  echo "Host: $(hostname)"
  echo "Proyecto: $APP_DIR"
  echo "Destino: $DEST"
  echo "Warnings: $WARNINGS"
  echo "Errores: $FAILED"
  echo
  echo "Archivos:"
  find "$DEST" -type f ! -name MANIFEST.txt ! -name SHA256SUMS -printf '%P\t%s bytes\n' | sort
} >"$DEST/MANIFEST.txt"

(
  cd "$DEST"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
) 2>>"$LOG_FILE" || warn "No se pudieron generar los checksums"

chmod -R go-rwx "$DEST" 2>/dev/null || true
SIZE="$(du -sh "$DEST" 2>/dev/null | awk '{print $1}')"
log "Respaldo generado: $DEST (${SIZE:-?})"

# ── Retencion ───────────────────────────────────────────────────────────────
if [ "$RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d \
    -name '20*T*Z*' -mtime +"$RETENTION_DAYS" -exec rm -rf {} \; 2>/dev/null || true
  log "Retencion aplicada: $RETENTION_DAYS dias"
fi

if [ "$FAILED" -gt 0 ]; then
  log "=== Respaldo con $FAILED error(es) y $WARNINGS advertencia(s) ==="
  exit 1
fi
log "=== Respaldo completado OK ($WARNINGS advertencia(s)) ==="
exit 0
