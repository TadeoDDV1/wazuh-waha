#!/usr/bin/env python3
"""
render_manager_snippet.py - Renderiza manager/ossec.conf.snippet.xml con los
valores del .env local.

Lee:
  - WAZUH_SERVER_IP         IP del manager (fuente de verdad, NUEVO)
  - WAZUH_MANAGER_HOST      alias deprecated (compat)
  - WAZUH_VM_SSH_HOST       alias deprecated (compat)
  - RELAY_API_KEY           API key del relay (solo se inyecta con --with-key)

Sustituye en el snippet:
  - REEMPLAZAR_RELAY_HOST   -> WAZUH_SERVER_IP (o alias)
  - REEMPLAZAR_RELAY_API_KEY -> RELAY_API_KEY (solo si --with-key)

Uso:
  # Modo commiteable (default): imprime el snippet con placeholders literales.
  python3 scripts/render_manager_snippet.py

  # Modo deploy: inyecta la API key real del .env local.
  python3 scripts/render_manager_snippet.py --with-key > /tmp/integration.xml

  # Redirigir directamente a la VM via scp:
  python3 scripts/render_manager_snippet.py --with-key | ssh tadeou7@172.44.30.12 \
    'cat > /tmp/integration.xml'

Por que --with-key es opt-in:
  Por seguridad, por default el snippet se imprime con REEMPLAZAR_RELAY_API_KEY
  literal (commiteable). Solo cuando se genera el archivo que va a la VM se
  inyecta el secret del .env local. Esto evita filtrar la API key en logs,
  en el repo, o en capturas de pantalla.
"""
import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SNIPPET = REPO_ROOT / "manager" / "ossec.conf.snippet.xml"
ENV_PATHS = [
    REPO_ROOT / ".env",
    Path.home() / "Desktop" / "wazuh-waha" / ".env",
]


def _load_env() -> dict[str, str]:
    """Carga KEY=VALUE de un .env (formato bash, ignora comentarios y vacias)."""
    out: dict[str, str] = {}
    for p in ENV_PATHS:
        if not p.exists():
            continue
        with open(p, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
        break  # Solo el primer .env que exista
    return out


def _resolve_server_ip(env: dict[str, str]) -> str:
    """Devuelve la IP del manager con prioridad: SERVER_IP > MANAGER_HOST > VM_SSH_HOST."""
    for key in ("WAZUH_SERVER_IP", "WAZUH_MANAGER_HOST", "WAZUH_VM_SSH_HOST"):
        if env.get(key):
            return env[key]
    print(
        "[render] ERROR: no encontre WAZUH_SERVER_IP ni aliases deprecated "
        "(WAZUH_MANAGER_HOST, WAZUH_VM_SSH_HOST) en .env",
        file=sys.stderr,
    )
    sys.exit(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument(
        "--with-key",
        action="store_true",
        help="Inyecta RELAY_API_KEY del .env local en el snippet (modo deploy)",
    )
    ap.add_argument(
        "--snippet",
        default=str(DEFAULT_SNIPPET),
        help=f"Path al snippet (default: {DEFAULT_SNIPPET})",
    )
    args = ap.parse_args()

    env = _load_env()
    if not env:
        unique_paths = sorted(set(ENV_PATHS), key=lambda p: str(p))
        print(
            f"[render] WARN: no encontre .env en {unique_paths}. "
            "Procedo con valores vacios (IP/KEY quedaran como placeholder).",
            file=sys.stderr,
        )

    server_ip = _resolve_server_ip(env)

    snippet_path = Path(args.snippet)
    if not snippet_path.exists():
        print(f"[render] ERROR: snippet no existe: {snippet_path}", file=sys.stderr)
        return 2

    content = snippet_path.read_text(encoding="utf-8")
    content = content.replace("REEMPLAZAR_RELAY_HOST", server_ip)

    if args.with_key:
        api_key = env.get("RELAY_API_KEY", "")
        if not api_key or api_key == "changeme":
            print(
                "[render] ERROR: --with-key requiere RELAY_API_KEY real en .env "
                "(no 'changeme' ni vacio)",
                file=sys.stderr,
            )
            return 2
        content = content.replace("REEMPLAZAR_RELAY_API_KEY", api_key)
        print(f"[render] OK: snippet con IP={server_ip} y API key inyectada", file=sys.stderr)
    else:
        print(
            f"[render] OK: snippet con IP={server_ip}, API key queda como placeholder "
            "(usar --with-key para inyectar)",
            file=sys.stderr,
        )

    sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    sys.exit(main())