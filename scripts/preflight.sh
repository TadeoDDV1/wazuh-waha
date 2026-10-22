#!/usr/bin/env bash
# Preflight de producción para wazuh-waha.
# Uso: bash scripts/preflight.sh [--domain ejemplo.com]
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN="${DOMAIN:-}"
FAIL=0
WARN=0

ok()   { printf '  [OK]   %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; WARN=$((WARN+1)); }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }

for arg in "$@"; do
  case "$arg" in
    --domain=*) DOMAIN="${arg#*=}" ;;
    --domain) shift; DOMAIN="${1:-}" ;;
  esac
done

echo "=== wazuh-waha preflight ==="
echo "Proyecto: $PROJECT_ROOT"

if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) ok "OS ${ID} ${VERSION_ID:-}" ;;
    *) warn "OS ${ID:-desconocido}; el soporte probado es Ubuntu 24.04/Debian 12" ;;
  esac
else
  warn "No se pudo leer /etc/os-release"
fi

if command -v python3 >/dev/null 2>&1; then
  if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'; then
    ok "Python $(python3 -V 2>&1 | awk '{print $2}')"
  else
    fail "Se requiere Python >= 3.11"
  fi
else
  fail "python3 no instalado"
fi

command -v docker >/dev/null 2>&1 && ok "Docker $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ,)" || fail "Docker no instalado"
if docker compose version >/dev/null 2>&1; then
  ok "Docker Compose $(docker compose version --short 2>/dev/null)"
else
  fail "docker compose no disponible"
fi

command -v caddy >/dev/null 2>&1 && ok "Caddy $(caddy version 2>/dev/null | head -1)" || warn "Caddy no instalado (TLS manual o reverse proxy alternativo)"
command -v ufw >/dev/null 2>&1 && ok "ufw disponible" || warn "ufw no instalado (configurar firewall manualmente)"
command -v rsync >/dev/null 2>&1 && ok "rsync disponible" || warn "rsync no instalado"

AVAIL_KB=$(df -Pk /var 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "${AVAIL_KB:-}" ] && [ "$AVAIL_KB" -lt 2097152 ]; then
  warn "Menos de 2 GB libres en /var ($((AVAIL_KB/1024)) MB). Recomendado: >= 5 GB"
else
  [ -n "${AVAIL_KB:-}" ] && ok "Espacio libre en /var: $((AVAIL_KB/1024)) MB"
fi

if [ -f "$PROJECT_ROOT/.env" ]; then
  ok ".env presente"
else
  warn ".env no existe; se copiará desde .env.production.example"
fi

if [ -n "$DOMAIN" ]; then
  if getent hosts "$DOMAIN" >/dev/null 2>&1; then
    ok "DNS resuelve $DOMAIN -> $(getent hosts "$DOMAIN" | awk '{print $1}' | head -1)"
  else
    warn "DNS no resuelve $DOMAIN (configurar registro A/AAAA antes de TLS)"
  fi
fi

echo
if [ "$FAIL" -gt 0 ]; then
  echo "Preflight con $FAIL error(es) crítico(s) y $WARN advertencia(s)."
  exit 1
fi
echo "Preflight OK ($WARN advertencia(s))."
