#!/usr/bin/env python3
"""
boot-notify.py - Heartbeat de boot del host Arch.

Corre desde wazuh-waha-boot-notify.service (triggered by .timer OnBootSec=90s).
Manda UN email + UN WhatsApp con el estado de todo el stack al iniciar el host.

Orden de notificacion (Tadeo pidio asi el 2026-07-01):
  1. SIEMPRE: email (no depende de WAHA, no depende del manager)
  2. SI WAHA responde: WhatsApp (ademas del email)
  3. Si WAHA no responde: solo email, loguea warning

Idempotencia: el /proc/sys/kernel/random/boot_id se resetea en cada reboot
real, asi que solo se manda una vez por boot. Si systemd re-ejecuta el unit
en el mismo boot (porque fallo y reinicia), el cache lo bloquea.

Uso:
  python3 scripts/boot-notify.py           # ejecuta (envia)
  DRY_RUN=1 python3 scripts/boot-notify.py  # imprime el mensaje, no envia
  FORCE=1 python3 scripts/boot-notify.py   # saltea el cache de boot_id
"""
import asyncio
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

# Re-ejecutar bajo el venv del relay si no estamos en el
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENV_PY = PROJECT_ROOT / "relay" / ".venv" / "bin" / "python"
if VENV_PY.exists() and Path(sys.executable).resolve() != VENV_PY.resolve():
    import os as _os
    _os.execv(str(VENV_PY), [str(VENV_PY), __file__, *sys.argv[1:]])

sys.path.insert(0, str(PROJECT_ROOT / "relay"))

# Logger basico a stderr (el relay no esta cargado, asi que main.py no loguea)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] boot-notify :: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("boot-notify")

# Cargar notifier y waha_client del paquete del relay
from wazuh_waha.infrastructure import notifier, waha_client  # noqa: E402
from wazuh_waha.config import settings  # noqa: E402

BOOT_STACK_SCRIPT = PROJECT_ROOT / "scripts" / "boot_stack_status.sh"
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")
NOTIFIED_CACHE = Path(settings.relay_lib_dir) / "boot_notified"

# Cargar WAZUH_SERVER_IP y WAZUH_SERVER_IP_FALLBACK del .env (que el config.py
# no expone porque son del agente, no del relay). Las necesitamos para el
# reporte de fallbacks.
def _read_env_var(name: str) -> str:
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return ""
    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""

WAZUH_SERVER_IP = _read_env_var("WAZUH_SERVER_IP")
WAZUH_SERVER_IP_FALLBACK = _read_env_var("WAZUH_SERVER_IP_FALLBACK")


# ------------------------------------------------------------------
# 1. Recolectar estado
# ------------------------------------------------------------------
def collect_status() -> dict:
    """Corre boot_stack_status.sh y parsea KEY=VALUE."""
    try:
        proc = subprocess.run(
            [str(BOOT_STACK_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as e:
        log.error("boot_stack_script_failed err=%s", e)
        return {}

    status = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        status[k.strip()] = v.strip()
    return status


# ------------------------------------------------------------------
# 2. Formatear el mensaje
# ------------------------------------------------------------------
def _icon(value: str, ok: str = "active") -> str:
    """Devuelve emoji segun el valor."""
    if value == ok or value.startswith(ok):
        return "\u2705"  # check
    if value.startswith("down") or value == "closed" or value == "unreachable":
        return "\u274c"  # cruz
    if value == "running" or value == "open" or value == "WORKING":
        return "\u2705"
    return "\u26a0\ufe0f"  # warning


def format_email(status: dict) -> tuple[str, str]:
    """
    Devuelve (subject, body) en texto plano para SMTP.
    """
    boot_id = status.get("boot_id", "?")[:8]
    host = status.get("host", "?")
    local_ip = status.get("local_ip", "?")
    uptime = int(status.get("uptime_sec", "0"))
    ts = status.get("timestamp", "?")

    subject = f"[wazuh-waha] Stack online @ {host} (boot {boot_id})"

    lines = [
        f"WAHA-WAHA STACK ONLINE",
        f"=" * 40,
        f"",
        f"Host:        {host}",
        f"Local IP:    {local_ip}",
        f"Boot ID:     {boot_id}",
        f"Timestamp:   {ts}",
        f"Uptime:      {uptime}s",
        f"",
        f"SERVICES:",
    ]

    services = [
        ("wazuh-waha.service",       "wazuh_waha_service"),
        ("wazuh-waha-watchdog.timer","wazuh_waha_watchdog"),
        ("watch_manager_ip.timer",   "watch_manager_ip"),
        ("wazuh-agent.service",      "wazuh_agent_service"),
    ]
    for label, key in services:
        val = status.get(key, "?")
        lines.append(f"  [{val:12s}] {label}")

    lines.append("")
    lines.append("DOCKER + WHATSAPP:")
    lines.append(f"  [{status.get('docker_wazuh_waha', '?'):12s}] container wazuh-waha")
    lines.append(f"  [{status.get('waha_session', '?'):12s}] WAHA session {settings.waha_session}")

    lines.append("")
    lines.append("WAZUH MANAGER:")
    mgr_ip = status.get("manager_expected_ip", "?")
    mgr_tcp = status.get("manager_expected_tcp1514", "?")
    mgr_api = status.get("manager_api_55000", "?")
    lines.append(f"  Expected IP:  {mgr_ip}")
    lines.append(f"  TCP 1514:     {mgr_tcp}  (agent->manager)")
    lines.append(f"  TCP 55000:    {mgr_api}  (REST API)")
    # Fallbacks
    fb_keys = sorted(k for k in status if k.startswith("manager_fallback_") and k.endswith("_tcp1514"))
    if fb_keys:
        lines.append("  Fallbacks:")
        for k in fb_keys:
            i = k.replace("manager_fallback_", "").replace("_tcp1514", "")
            # i es "0", "1", etc; la IP real esta en WAZUH_SERVER_IP_FALLBACK
            fb_ips = WAZUH_SERVER_IP_FALLBACK.split(",")
            fb_ip = fb_ips[int(i)].strip() if i.isdigit() and int(i) < len(fb_ips) else "?"
            lines.append(f"    [{status[k]:12s}] {fb_ip}")

    lines.append("")
    lines.append("LOCAL:")
    lines.append(f"  [{{:12s}}] Ollama 127.0.0.1:11434".format(status.get("ollama_local", "?")))

    if mgr_tcp != "open":
        lines.append("")
        lines.append("!! NOTA: El manager no responde en la IP esperada.")
        lines.append("   Si la red cambio, actualiza WAZUH_SERVER_IP en:")
        lines.append("     - /opt/wazuh-waha/.env")
        lines.append("     - /etc/wazuh-waha/relay.env (via sync_relay_env.sh apply)")
        lines.append("   o espera al watch_manager_ip.timer que lo detecte.")

    body = "\n".join(lines)
    return subject, body


def format_whatsapp(status: dict) -> str:
    """
    Devuelve el mensaje WhatsApp (markdown *bold*).
    Mas corto que el email - WhatsApp no banca bien mensajes largos.
    """
    boot_id = status.get("boot_id", "?")[:8]
    host = status.get("host", "?")
    local_ip = status.get("local_ip", "?")
    uptime = int(status.get("uptime_sec", "0"))
    uptime_min = uptime // 60

    # Servicios criticos: si alguno esta down, abrimos con WARNING
    criticos = [
        "wazuh_waha_service", "wazuh_agent_service", "wazuh_waha_watchdog",
        "watch_manager_ip", "docker_wazuh_waha",
    ]
    alguno_caido = any(
        not status.get(k, "").startswith(("active", "running", "WORKING"))
        for k in criticos
    )

    icono = "\u26a0\ufe0f" if alguno_caido else "\u2705"
    titulo = "*Stack wazuh-waha online* (con observaciones)" if alguno_caido else "*Stack wazuh-waha online*"

    lines = [
        f"{icono} {titulo}",
        f"Host:    {host} ({local_ip})",
        f"Boot:    {boot_id} | Uptime: {uptime_min}m",
        "",
    ]

    # Servicios - una linea compacta
    lines.append("*Servicios:*")
    lines.append(
        f"  relay={status.get('wazuh_waha_service', '?')}  "
        f"agent={status.get('wazuh_agent_service', '?')}  "
        f"watchdog={status.get('wazuh_waha_watchdog', '?')}"
    )
    lines.append(
        f"  watch_ip={status.get('watch_manager_ip', '?')}  "
        f"docker={status.get('docker_wazuh_waha', '?')}  "
        f"waha={status.get('waha_session', '?')}"
    )

    # Manager
    mgr_ip = status.get("manager_expected_ip", "?")
    mgr_tcp = status.get("manager_expected_tcp1514", "?")
    mgr_api = status.get("manager_api_55000", "?")
    mgr_icon = "\u2705" if mgr_tcp == "open" else "\u274c"
    lines.append("")
    lines.append(f"*Manager* {mgr_icon}  {mgr_ip}  tcp1514={mgr_tcp}  api={mgr_api}")
    if mgr_tcp != "open":
        # Buscar un fallback que responda
        fb_keys = sorted(k for k in status if k.startswith("manager_fallback_") and k.endswith("_tcp1514"))
        for k in fb_keys:
            if status[k] == "open":
                fallback_ip = k.replace("manager_fallback_", "").replace("_tcp1514", "")
                lines.append(f"  \u2705 Fallback {fallback_ip} responde \u2014 posible drift")
                break

    return "\n".join(lines)


# ------------------------------------------------------------------
# 3. Envio
# ------------------------------------------------------------------
async def send_email(subject: str, body: str) -> bool:
    """Email es el canal primario, SIEMPRE se intenta."""
    log.info("boot_notify_email_start subject=%r", subject)
    # notifier.notify_email es sync; la mandamos a un thread para no bloquear
    ok = await asyncio.to_thread(notifier.notify_email, subject, body)
    if ok:
        log.info("boot_notify_email_ok")
    else:
        log.warning("boot_notify_email_failed (smtp no configurado o error de envio)")
    return ok


async def send_whatsapp(message: str) -> bool:
    """WhatsApp es secundario, solo si WAHA responde."""
    log.info("boot_notify_whatsapp_start msg_len=%d", len(message))
    try:
        resp = await waha_client.send_text(message)
        msg_id = (resp or {}).get("id", {}).get("id", "?") if isinstance(resp, dict) else "?"
        log.info("boot_notify_whatsapp_ok waha_id=%s", msg_id)
        return True
    except waha_client.WAHAError as e:
        log.warning("boot_notify_whatsapp_skipped err=%s", e)
        return False
    except Exception as e:
        log.exception("boot_notify_whatsapp_unexpected err=%s", e)
        return False


# ------------------------------------------------------------------
# 4. Main
# ------------------------------------------------------------------
async def main():
    dry_run = os.environ.get("DRY_RUN") == "1"
    force = os.environ.get("FORCE") == "1"

    boot_id = BOOT_ID_FILE.read_text().strip() if BOOT_ID_FILE.exists() else "unknown"

    # Idempotencia: si ya notifique este boot_id, salir
    if not force and NOTIFIED_CACHE.exists():
        cached = NOTIFIED_CACHE.read_text().strip()
        if cached == boot_id:
            log.info("boot_notify_skip already_notified boot_id=%s", boot_id)
            return

    log.info("boot_notify_start boot_id=%s dry_run=%s", boot_id, dry_run)

    # 1) Recolectar
    status = collect_status()
    log.info("boot_notify_collected keys=%d", len(status))

    # 2) Formatear
    email_subject, email_body = format_email(status)
    wa_msg = format_whatsapp(status)

    if dry_run:
        print("=" * 60)
        print("DRY RUN - email subject:")
        print(email_subject)
        print("-" * 60)
        print("DRY RUN - email body:")
        print(email_body)
        print("=" * 60)
        print("DRY RUN - whatsapp msg:")
        print(wa_msg)
        print("=" * 60)
        return

    # 3) SIEMPRE email primero
    email_ok = await send_email(email_subject, email_body)

    # 4) DESPUES WhatsApp (si WAHA responde)
    wa_ok = await send_whatsapp(wa_msg)

    log.info("boot_notify_done email_ok=%s whatsapp_ok=%s", email_ok, wa_ok)

    # 5) Marcar como notificado (incluso si email fallo, asi no spameamos en reintentos)
    if not dry_run:
        try:
            NOTIFIED_CACHE.parent.mkdir(parents=True, exist_ok=True)
            NOTIFIED_CACHE.write_text(boot_id)
            log.info("boot_notify_cached boot_id=%s path=%s", boot_id, NOTIFIED_CACHE)
        except Exception as e:
            log.warning("boot_notify_cache_write_failed err=%s", e)


if __name__ == "__main__":
    asyncio.run(main())
