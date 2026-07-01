#!/usr/bin/env python3
"""
waha-notify.py - Wrapper CLI del notifier para que el watchdog bash pueda
disparar notificaciones sin importar modulos del venv del relay.

Uso:
  python3 scripts/waha-notify.py \\
    --description "WAHA session default recovered by watchdog" \\
    --level 10 \\
    --action watchdog_recovered \\
    --previous_status STOPPED \\
    --new_status WORKING

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

from wazuh_waha import notifier  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--description", required=True)
    p.add_argument("--level", type=int, default=15)
    p.add_argument("--action", default="watchdog")
    p.add_argument("--previous-status", default="")
    p.add_argument("--new-status", default="")
    p.add_argument("--recover-exit-code", default="")
    args = p.parse_args()

    fields = {"action": args.action}
    if args.previous_status:
        fields["previous_status"] = args.previous_status
    if args.new_status:
        fields["new_status"] = args.new_status
    if args.recover_exit_code:
        fields["recover_exit_code"] = args.recover_exit_code

    asyncio.run(notifier.notify_health(args.description, args.level, **fields))


if __name__ == "__main__":
    main()