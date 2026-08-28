#!/usr/bin/env bash
# =============================================================================
# fix_venv_shebangs.sh
# =============================================================================
# Arregla shebangs rotos en relay/.venv/bin/* cuando el proyecto fue movido
# o renombrado y los paths absolutos quedaron apuntando al lugar viejo.
#
# Sintoma: systemd dice "Failed to execute .../uvicorn: No such file or
# directory" aunque el archivo existe. Causa: el shebang apunta a un
# python que esta en otro path (tipicamente porque el proyecto se movio
# de wazuh-integration/ a relay/, o se clono en otro lado).
#
# Antes (roto):
#   #!/home/tadeo/Desktop/wazuh-waha/wazuh-waha/.venv/bin/python3.11
#                                                       ^^^^^^^^^^
#                                                       path duplicado
#
# Despues (correcto):
#   #!/home/tadeo/Desktop/wazuh-waha/relay/.venv/bin/python3.11
#
# Uso:
#   bash scripts/fix_venv_shebangs.sh                # dry-run (muestra)
#   bash scripts/fix_venv_shebangs.sh --apply        # arregla
#   bash scripts/fix_venv_shebangs.sh --venv /path   # otro venv (default: relay/.venv)
#
# Idempotente: si el shebang ya esta bien, no toca nada.
# =============================================================================

set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/Desktop/wazuh-waha}"
VENV_REL="${VENV_REL:-relay/.venv}"
VENV_PATH="${PROJECT_ROOT}/${VENV_REL}"
VENV_BIN="${VENV_PATH}/bin"

# Parsear flags
APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --venv)  shift; VENV_PATH="$1"; VENV_BIN="${VENV_PATH}/bin" ;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'
      exit 0
      ;;
  esac
done

if [[ ! -d "${VENV_BIN}" ]]; then
  echo "ERROR: no encuentro ${VENV_BIN}" >&2
  echo "       Ajustar PROJECT_ROOT o pasar --venv /path/to/venv" >&2
  exit 1
fi

# Detectar el python "real" del venv (lo que el shebang deberia apuntar).
# IMPORTANTE: el shebang de los entry-points tiene que apuntar al python DEL
# VENV (relay/.venv/bin/python3.11), NO al binario real que el symlink
# resuelve. Esto es porque Python, al arrancar desde un venv, setea sys.path
# y site-packages relativos a la ubicacion del executable. Si el shebang
# apunta a /home/tadeo/.local/share/uv/.../python3.11 (el "binario real"),
# NO se carga el venv y los modulos del proyecto no se encuentran.
REAL_PY=""
for cand in "${VENV_BIN}"/python3.11 "${VENV_BIN}"/python3 "${VENV_BIN}"/python; do
  if [[ -e "${cand}" && -x "${cand}" ]]; then
    REAL_PY="${cand}"  # el path del symlink, no readlink -f
    break
  fi
done

if [[ -z "${REAL_PY}" ]]; then
  echo "ERROR: no encuentro un python ejecutable en ${VENV_BIN}" >&2
  echo "       El venv parece roto. Recrearlo: rm -rf ${VENV_PATH} && uv venv ${VENV_PATH}" >&2
  exit 1
fi

# Shebang correcto (el "despues" deseado)
GOOD_SHEBANG="#!${REAL_PY}"

echo "Proyecto:   ${PROJECT_ROOT}"
echo "Venv:       ${VENV_PATH}"
echo "Shebang OK: ${GOOD_SHEBANG}"
echo ""

# Buscar archivos con shebang problematico. Hay 2 patrones que vimos:
#   1) Path duplicado tipo /wazuh-waha/wazuh-waha/.venv/bin/python
#   2) Cualquier shebang que apunte a un path que NO existe en disco
FIXED=0
SKIPPED=0
CHECKED=0

# Recolectar candidatos: todos los archivos ejecutables en bin/
mapfile -t BIN_FILES < <(find "${VENV_BIN}" -maxdepth 1 -type f -executable 2>/dev/null | sort)

if [[ ${#BIN_FILES[@]} -eq 0 ]]; then
  echo "ERROR: ${VENV_BIN} esta vacio" >&2
  exit 1
fi

for f in "${BIN_FILES[@]}"; do
  # Solo archivos regulares (no symlinks)
  [[ -L "${f}" ]] && continue
  [[ -f "${f}" ]] || continue
  # Saltar backups creados por corridas anteriores de este script
  [[ "${f}" == *.shebak.bak ]] && continue
  CHECKED=$((CHECKED + 1))

  # Leer primera linea (shebang)
  first_line=$(head -n 1 "${f}" 2>/dev/null || echo "")
  [[ "${first_line}" =~ ^#!.*python ]] || continue

  # Caso 1: shebang ya correcto
  if [[ "${first_line}" == "${GOOD_SHEBANG}" ]]; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  # Caso 2: shebang apunta a un python que NO es el del venv actual.
  # Esto cubre 2 situaciones:
  #   - Path duplicado tipo /wazuh-waha/wazuh-waha/.venv/bin/python (viejo)
  #   - Path al binario "real" (readlink -f) tipo /home/tadeo/.local/share/uv/...
  #     que existe pero NO carga el venv (Python no encuentra site-packages)
  # En ambos casos el shebang esta MAL. La regla es: tiene que apuntar
  # EXACTAMENTE a "${VENV_BIN}/python3.11" (o python3/python).
  declared_path="${first_line#\#!}"
  if [[ "${declared_path}" != "${REAL_PY}" ]]; then
    if [[ ${APPLY} -eq 1 ]]; then
      # Backup + replace
      cp -p "${f}" "${f}.shebak.bak"
      printf '%s\n%s\n' "${GOOD_SHEBANG}" "$(tail -n +2 "${f}")" > "${f}.new"
      mv "${f}.new" "${f}"
      chmod +x "${f}"
      echo "  [FIX]   ${f##*/}"
      FIXED=$((FIXED + 1))
    else
      echo "  [DRY]   ${f##*/}: '${first_line}' -> '${GOOD_SHEBANG}'"
      FIXED=$((FIXED + 1))
    fi
  else
    # Shebang correcto, no tocar
    SKIPPED=$((SKIPPED + 1))
  fi
done

echo ""
echo "=== Resumen ==="
echo "  Chequeados:  ${CHECKED}"
echo "  Arreglados:  ${FIXED}"
echo "  Sin cambios: ${SKIPPED}"
echo ""

if [[ ${APPLY} -eq 0 ]]; then
  echo "DRY-RUN: no se modifico nada. Correr con --apply para arreglar."
  exit 0
fi

if [[ ${FIXED} -gt 0 ]]; then
  echo "OK: ${FIXED} shebangs arreglados. Backups en ${VENV_BIN}/*.shebak.bak"
fi
exit 0