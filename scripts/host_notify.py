#!/usr/bin/env python3
"""
host_notify.py - Notificaciones de infraestructura del host.

Se usa desde:
  - wazuh-waha-shutdown-notify.service  (apagado / reinicio)
  - wazuh-waha-boot-notify.service      (vuelta a estar en linea)
  - wazuh-waha-monitor.timer            (caida de red / servicios / sesion WAHA)
  - wazuh-waha-failure-notify.service   (fallo del relay)
  - wazuh-waha-backup-failure-notify.service (fallo del respaldo)

Canales (se intentan en este orden):
  1. WhatsApp via WAHA (si la sesion esta WORKING)
  2. Telegram directo (Bot API)
  3. Email SMTP (se puede desactivar con HOST_NOTIFY_EMAIL=false)

No usa el paquete del relay ni requieren el venv: solo libreria estandar de
Python, para que funcione incluso durante el apagado o si el relay esta caido.

Uso:
  python3 scripts/host_notify.py --event test
  python3 scripts/host_notify.py --event shutdown --detail "apagado manual"
  python3 scripts/host_notify.py --event boot --force
  python3 scripts/host_notify.py --event network-down --dry-run

El historial legible queda en /var/log/wazuh-waha/eventos.log y en formato
JSONL en /var/log/wazuh-waha/eventos.jsonl.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = Path(os.environ.get("WAZUH_WAHA_ENV_FILE", str(PROJECT_ROOT / ".env")))
LOG_DIR = Path(os.environ.get("WAZUH_WAHA_LOG_DIR", "/var/log/wazuh-waha"))
STATE_DIR = Path(os.environ.get("WAZUH_WAHA_STATE_DIR", "/var/lib/wazuh-waha"))
EVENT_LOG = LOG_DIR / "eventos.log"
EVENT_JSONL = LOG_DIR / "eventos.jsonl"
BOOT_CACHE = STATE_DIR / "boot_notified"
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")
MAX_EVENT_LOG_BYTES = 5 * 1024 * 1024

EVENTS = (
    "test",
    "shutdown",
    "reboot",
    "boot",
    "network-down",
    "network-up",
    "service-down",
    "service-up",
    "waha-session-down",
    "waha-session-up",
    "backup-ok",
    "backup-failed",
)

TITLES = {
    "test": ("\U0001f9ea", "Prueba de notificacion"),
    "shutdown": ("\U0001f50c", "Servidor APAGANDOSE"),
    "reboot": ("\U0001f504", "Servidor REINICIANDOSE"),
    "boot": ("\u2705", "Servidor EN LINEA de nuevo"),
    "network-down": ("\U0001f4e1", "Conexion a Internet PERDIDA"),
    "network-up": ("\U0001f4e1", "Conexion a Internet RESTABLECIDA"),
    "service-down": ("\u26a0\ufe0f", "Servicio CAIDO"),
    "service-up": ("\u2705", "Servicio RECUPERADO"),
    "waha-session-down": ("\U0001f4f5", "WhatsApp DESCONECTADO"),
    "waha-session-up": ("\u2705", "WhatsApp RECONECTADO"),
    "backup-ok": ("\U0001f4be", "Respaldo completado"),
    "backup-failed": ("\u274c", "Respaldo FALLIDO"),
}


def _clean(value: str) -> str:
    return value.strip().strip('"').strip("'")


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if ENV_FILE.exists():
        try:
            for line in ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, value = raw.split("=", 1)
                env[key.strip()] = _clean(value)
        except Exception as exc:
            print(f"[host-notify] WARN no se pudo leer {ENV_FILE}: {exc}", file=sys.stderr)
    return env


def get(env: dict[str, str], key: str, default: str = "") -> str:
    return _clean(os.environ.get(key, "")) or env.get(key, default) or default


def _run(cmd: list[str], timeout: int = 3) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (result.stdout or result.stderr or "").strip()
    except Exception:
        return ""


def local_ip() -> str:
    ip = _run(["ip", "-4", "route", "get", "1"])
    match = re.search(r"\bsrc\s+(\S+)", ip)
    if match:
        return match.group(1)
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "?"


def uptime_human() -> str:
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return "?"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def boot_id() -> str:
    try:
        return BOOT_ID_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return "unknown"


def _rotate(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size > MAX_EVENT_LOG_BYTES:
            previous = path.with_suffix(path.suffix + ".1")
            if previous.exists():
                previous.unlink()
            path.rename(previous)
    except Exception:
        pass


def log_event(
    event: str,
    message: str,
    channels: dict[str, dict[str, Any]] | None = None,
    detail: str = "",
) -> None:
    """Escribe el evento en texto legible y JSONL. Nunca falla el proceso."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _rotate(EVENT_LOG)
    _rotate(EVENT_JSONL)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S%z")
    one_line = " ".join(str(message).split())
    line = f"{timestamp} [{event}] {one_line}\n"
    record = {
        "ts": timestamp,
        "event": event,
        "host": socket.gethostname(),
        "message": one_line,
        "detail": detail,
        "channels": {
            name: {"ok": bool(res.get("ok")), "detail": res.get("detail", "")}
            for name, res in (channels or {}).items()
        },
    }
    try:
        with EVENT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(EVENT_LOG, 0o640)
    except Exception as exc:
        print(f"[host-notify] WARN no se pudo escribir {EVENT_LOG}: {exc}", file=sys.stderr)
    try:
        with EVENT_JSONL.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(EVENT_JSONL, 0o640)
    except Exception:
        pass


def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(512).decode("utf-8", "replace")
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def send_whatsapp(env: dict[str, str], text: str) -> dict[str, Any]:
    api_key = get(env, "WAHA_API_KEY")
    phone = re.sub(r"\D", "", get(env, "ADMIN_PHONE"))
    host = get(env, "WAHA_HOST", "http://127.0.0.1:3001").rstrip("/")
    session = get(env, "WAHA_SESSION", "default")
    if not api_key or not phone:
        return {"ok": False, "skipped": True, "detail": "WAHA_API_KEY o ADMIN_PHONE vacios"}

    # Solo intentar si la sesion esta operativa: evita errores durante el QR.
    status, body = _http_json(
        f"{host}/api/sessions/{session}",
        headers={"X-Api-Key": api_key},
        timeout=3.0,
    )
    if status != 200:
        return {"ok": False, "skipped": True, "detail": f"WAHA no responde ({status})"}
    try:
        if json.loads(body).get("status") != "WORKING":
            return {"ok": False, "skipped": True, "detail": "sesion WAHA no esta WORKING"}
    except Exception:
        return {"ok": False, "skipped": True, "detail": "respuesta WAHA invalida"}

    status, body = _http_json(
        f"{host}/api/sendText",
        method="POST",
        payload={"session": session, "chatId": f"{phone}@c.us", "text": text},
        headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
        timeout=5.0,
    )
    if 200 <= status < 300:
        return {"ok": True, "detail": f"WAHA HTTP {status}"}
    return {"ok": False, "detail": f"WAHA HTTP {status}: {body[:160]}"}


def send_telegram(env: dict[str, str], text: str) -> dict[str, Any]:
    token = get(env, "TELEGRAM_BOT_TOKEN")
    chat_id = get(env, "TELEGRAM_CHAT_ID") or get(env, "TELEGRAM_ADMIN_CHAT_IDS")
    chat_id = chat_id.split(",")[0].strip()
    if not token or not chat_id:
        return {"ok": False, "skipped": True, "detail": "Telegram no configurado"}
    data = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=6.0) as response:
            return {"ok": 200 <= response.status < 300, "detail": f"Telegram HTTP {response.status}"}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "detail": f"Telegram HTTP {exc.code}"}
    except Exception as exc:
        return {"ok": False, "detail": f"Telegram {type(exc).__name__}"}


def send_email(env: dict[str, str], subject: str, body: str) -> dict[str, Any]:
    if get(env, "HOST_NOTIFY_EMAIL", "true").lower() in ("0", "false", "no", "off"):
        return {"ok": False, "skipped": True, "detail": "HOST_NOTIFY_EMAIL=false"}
    smtp_host = get(env, "SMTP_HOST")
    admin_email = get(env, "ADMIN_EMAIL") or get(env, "SMTP_USER")
    if not smtp_host or not admin_email:
        return {"ok": False, "skipped": True, "detail": "SMTP no configurado"}

    sender = get(env, "SMTP_FROM") or get(env, "SMTP_USER") or admin_email
    try:
        port = int(get(env, "SMTP_PORT", "587") or "587")
    except ValueError:
        port = 587
    use_tls = get(env, "SMTP_TLS", "true").lower() not in ("0", "false", "no", "off")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = admin_email
    message.set_content(body)

    try:
        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, port, timeout=8) as smtp:
                smtp.starttls(context=context)
                if get(env, "SMTP_USER"):
                    smtp.login(get(env, "SMTP_USER"), get(env, "SMTP_PASS"))
                smtp.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, port, timeout=8) as smtp:
                if get(env, "SMTP_USER"):
                    smtp.login(get(env, "SMTP_USER"), get(env, "SMTP_PASS"))
                smtp.send_message(message)
        return {"ok": True, "detail": f"SMTP {smtp_host}:{port}"}
    except Exception as exc:
        return {"ok": False, "detail": f"SMTP {type(exc).__name__}"}


def collect_status(env: dict[str, str]) -> list[str]:
    lines: list[str] = []
    units = [
        "wazuh-waha",
        "wazuh-manager",
        "wazuh-indexer",
        "wazuh-dashboard",
        "filebeat",
        "docker",
    ]
    parts = []
    for unit in units:
        state = _run(["systemctl", "is-active", f"{unit}.service"], timeout=2) or "unknown"
        parts.append(f"{unit}={state}")
    lines.append("Servicios: " + "  ".join(parts))

    containers = []
    for name in ("wazuh-waha", "wazuh-waha-dashboard"):
        state = _run(
            ["docker", "inspect", "-f", "{{.State.Status}}", name],
            timeout=3,
        ) or "not_found"
        containers.append(f"{name}={state}")
    lines.append("Contenedores: " + "  ".join(containers))

    api_key = get(env, "WAHA_API_KEY")
    if api_key:
        host = get(env, "WAHA_HOST", "http://127.0.0.1:3001").rstrip("/")
        session = get(env, "WAHA_SESSION", "default")
        code, body = _http_json(
            f"{host}/api/sessions/{session}",
            headers={"X-Api-Key": api_key},
            timeout=3.0,
        )
        state = "unreachable"
        if code == 200:
            try:
                state = json.loads(body).get("status", "unknown")
            except Exception:
                state = "invalid"
        lines.append(f"WhatsApp ({session}): {state}")
    return lines


def build_message(
    event: str,
    env: dict[str, str],
    detail: str = "",
    with_status: bool = False,
) -> tuple[str, str]:
    emoji, title = TITLES.get(event, ("\u2139\ufe0f", event))
    subject = f"[wazuh-waha] {title}"
    lines = [
        f"{emoji} {title}",
        f"Host: {socket.gethostname()} ({local_ip()})",
        f"Hora: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Uptime: {uptime_human()}",
    ]
    if detail:
        lines.append(f"Detalle: {detail}")

    if event == "shutdown":
        lines.append("")
        lines.append("El servidor se esta apagando o reiniciando. Este es el ultimo aviso.")
    elif event == "reboot":
        lines.append("")
        lines.append("El servidor se esta reiniciando. Se enviara otro aviso cuando vuelva.")
    elif event == "boot":
        lines.append("")
        lines.append("El servidor volvio a estar en linea.")
    elif event == "network-up":
        lines.append("")
        lines.append("La conexion se restablecio. Se envian los eventos pendientes si los hay.")
    elif event == "network-down":
        lines.append("")
        lines.append("Se detecto perdida de conectividad. Si no llega el aviso de recuperacion, revisar el servidor.")

    if with_status or event in ("boot", "test", "service-down", "backup-failed"):
        lines.append("")
        lines.extend(collect_status(env))

    lines.append("")
    lines.append(f"Historial: {EVENT_LOG}")
    body = "\n".join(lines)
    return subject, body


def send_message(
    event: str,
    *,
    env: dict[str, str] | None = None,
    detail: str = "",
    with_status: bool = False,
    dry_run: bool = False,
) -> dict[str, dict[str, Any]]:
    env = env or load_env()
    subject, body = build_message(event, env, detail=detail, with_status=with_status)

    if dry_run:
        print("=" * 70)
        print(f"DRY-RUN [{event}]")
        print(subject)
        print("-" * 70)
        print(body)
        print("=" * 70)
        return {"dry-run": {"ok": True, "detail": "no enviado"}}

    results: dict[str, dict[str, Any]] = {}
    results["whatsapp"] = send_whatsapp(env, body)
    results["telegram"] = send_telegram(env, body)
    results["email"] = send_email(env, subject, body)

    log_event(event, body, channels=results, detail=detail)

    summary = ", ".join(
        f"{name}={'ok' if res.get('ok') else ('skip' if res.get('skipped') else 'fail')}"
        for name, res in results.items()
    )
    print(f"[host-notify] event={event} {summary}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Notificaciones del host wazuh-waha")
    parser.add_argument("--event", required=True, choices=EVENTS)
    parser.add_argument("--detail", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="ignorar cache de boot")
    parser.add_argument(
        "--with-status",
        action="store_true",
        help="incluir estado de servicios y contenedores",
    )
    args = parser.parse_args()

    if args.event == "boot" and not args.force and not args.dry_run:
        current_boot = boot_id()
        try:
            if BOOT_CACHE.exists() and BOOT_CACHE.read_text(encoding="utf-8").strip() == current_boot:
                print(f"[host-notify] boot ya notificado ({current_boot[:8]})")
                return 0
        except Exception:
            pass

    send_message(
        args.event,
        detail=args.detail,
        with_status=args.with_status,
        dry_run=args.dry_run,
    )

    if args.event == "boot" and not args.dry_run:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            BOOT_CACHE.write_text(boot_id(), encoding="utf-8")
        except Exception as exc:
            print(f"[host-notify] WARN no se pudo guardar cache de boot: {exc}", file=sys.stderr)

    # Nunca devolver fallo por canales caidos: eso podria crear bucles de
    # OnFailure en systemd. El resultado queda en eventos.log.
    return 0


if __name__ == "__main__":
    sys.exit(main())
