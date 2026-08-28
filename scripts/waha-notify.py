#!/usr/bin/env python3
"""
waha-notify.py - Wrapper CLI del notifier para que scripts bash/systemd
puedan disparar notificaciones sin importar modulos del venv del relay.

Pensado para ser invocado por:
  - waha-watchdog.sh (recovery de sesion WAHA)
  - watch_manager_ip.sh (drift de IP del manager)
  - notify-agent-failure.sh (OnFailure= de wazuh-agent)
  - notify-relay-failure.sh (OnFailure= de wazuh-waha)
  - check-agent-connected.sh (timer de health-check del agente)
  - boot-notify.py NO usa este wrapper (es Python y ya tiene acceso al notifier)

Uso:
  python3 scripts/waha-notify.py \\
    --description "WAHA session recovered" \\
    --level 12 \\
    --action watchdog_recovered \\
    --previous-status STOPPED \\
    --new-status WORKING

  python3 scripts/waha-notify.py \\
    --description "wazuh-agent restarted" \\
    --level 12 \\
    --action agent_restart \\
    --service wazuh-agent \\
    --restart-count 3

Flags:
  --no-manager-api : NO postear al Wazuh Manager API. Para meta-eventos de
                     infraestructura del propio relay/agente, no tiene sentido
                     generar una alerta en el SIEM (ruido). Email+WhatsApp siguen.
  --no-email       : NO enviar email. Usar para notificaciones locales (logs).
  --no-whatsapp    : NO enviar WhatsApp. Usar para eventos que solo van al SIEM.
  --service        : nombre del systemd unit (lo pone en fields.service para el reporte)
  --restart-count  : numero de reinicio (lo pone en fields.restart_count)

Lee config del .env del proyecto (mismo path que usa el relay).
"""
import argparse
import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENV_PY = PROJECT_ROOT / "relay" / ".venv" / "bin" / "python"

# Si nos invocan con el python del sistema pero el venv existe, re-ejecutar.
if VENV_PY.exists() and Path(sys.executable).resolve() != VENV_PY.resolve():
    import os
    os.execv(str(VENV_PY), [str(VENV_PY), __file__, *sys.argv[1:]])

sys.path.insert(0, str(PROJECT_ROOT / "relay"))

# Configurar logger basico para que notifier loguee a stderr cuando se llama
# standalone (el main.py hace lo mismo pero no se importa aca).
import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s :: %(message)s",
    stream=sys.stderr,
)

from wazuh_waha.infrastructure import notifier  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--description", required=True)
    p.add_argument("--level", type=int, default=15,
                   help="Nivel Wazuh (12=high, 15=critical). Default 15.")
    p.add_argument("--action", default="generic",
                   help="Identificador del tipo de evento (libre).")
    p.add_argument("--previous-status", default="")
    p.add_argument("--new-status", default="")
    p.add_argument("--recover-exit-code", default="")
    p.add_argument("--service", default="",
                   help="Nombre del systemd unit (para logs/fields).")
    p.add_argument("--restart-count", default="",
                   help="Nth restart desde el ultimo clean (para detectar loops).")
    p.add_argument("--no-manager-api", action="store_true",
                   help="Saltear la notificacion al Wazuh Manager API.")
    p.add_argument("--no-email", action="store_true",
                   help="Saltear email.")
    p.add_argument("--no-whatsapp", action="store_true",
                   help="Saltear WhatsApp.")
    args = p.parse_args()

    # Construir fields extra para el reporte
    fields = {"action": args.action}
    if args.previous_status:
        fields["previous_status"] = args.previous_status
    if args.new_status:
        fields["new_status"] = args.new_status
    if args.recover_exit_code:
        fields["recover_exit_code"] = args.recover_exit_code
    if args.service:
        fields["service"] = args.service
    if args.restart_count:
        fields["restart_count"] = args.restart_count

    # Notificar. El notifier interno respeta settings.email_provider.
    # Si --no-email/--no-whatsapp se piden, parcheamos settings antes de llamar.
    # (Mas limpio que duplicar el notify_health.)
    from wazuh_waha.config import settings

    # Snapshot + parche
    orig_email_provider = settings.email_provider
    orig_smtp_host = settings.smtp_host
    orig_hyvor = settings.hyvor_base_url
    orig_waha = (settings.waha_host, settings.waha_session)

    if args.no_email:
        settings.smtp_host = ""
        settings.smtp_to = ""
        settings.hyvor_base_url = ""
        settings.hyvor_api_key = ""
        settings.hyvor_to = ""

    if args.no_whatsapp:
        # Forzar waha_client a fallar limpiamente seteando un host invalido.
        # waha_client hace ping al iniciar; si el host es vacio, sale por except.
        settings.waha_host = ""
        settings.waha_session = ""

    try:
        asyncio.run(notifier.notify_health(args.description, args.level, **fields))
    finally:
        # Restaurar (por si el proceso sigue vivo, ej. tests)
        settings.email_provider = orig_email_provider
        settings.smtp_host = orig_smtp_host
        settings.hyvor_base_url = orig_hyvor
        settings.waha_host, settings.waha_session = orig_waha


if __name__ == "__main__":
    main()