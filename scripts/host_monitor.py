#!/usr/bin/env python3
"""
host_monitor.py - Vigila red, relay, contenedores, servicios y sesion WAHA.

Se ejecuta cada minuto desde wazuh-waha-monitor.timer. Guarda el ultimo
estado en /var/lib/wazuh-waha/host_monitor_state.json y solo notifica en los
cambios (evita spam). Los eventos que no se pueden entregar por falta de
Internet quedan pendientes y se envian al recuperar la conexion.

Uso:
  python3 scripts/host_monitor.py            # una pasada (la usa el timer)
  python3 scripts/host_monitor.py --dry-run  # muestra el estado sin enviar
  python3 scripts/host_monitor.py --reset    # borra el estado y vuelve a baseline
  python3 scripts/host_monitor.py --interval 60  # bucle para pruebas manuales
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from host_notify import (  # noqa: E402
    LOG_DIR,
    STATE_DIR,
    get,
    load_env,
    log_event,
    send_message,
)

STATE_FILE = STATE_DIR / "host_monitor_state.json"
LOCK_FILE = STATE_DIR / "host_monitor.lock"

SERVICES = (
    "wazuh-manager",
    "wazuh-indexer",
    "wazuh-dashboard",
    "filebeat",
    "wazuh-waha",
    "docker",
)
CONTAINERS = ("wazuh-waha", "wazuh-waha-dashboard")


def _run(cmd: list[str], timeout: int = 4) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return (result.stdout or result.stderr or "").strip()
    except Exception:
        return ""


def internet_ok() -> bool:
    """Prueba TCP/DNS contra Telegram y, como respaldo, DNS publicos.

    Probar varios destinos evita falsos "sin Internet" cuando el firewall
    bloquea un servicio concreto pero la conectividad general funciona.
    """
    for host in ("api.telegram.org", "1.1.1.1", "8.8.8.8"):
        try:
            with socket.create_connection((host, 443), timeout=4):
                return True
        except Exception:
            continue
    return False


def _http_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 4.0) -> tuple[int, str]:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(256).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def check(env: dict[str, str]) -> dict[str, Any]:
    relay_port = get(env, "RELAY_PORT", "8765") or "8765"
    relay_code, _ = _http_json(f"http://127.0.0.1:{relay_port}/health", timeout=3.0)
    relay_ok = relay_code == 200

    containers: dict[str, bool] = {}
    for name in CONTAINERS:
        state = _run(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=3)
        containers[name] = state == "true"

    services: dict[str, bool] = {}
    for unit in SERVICES:
        services[unit] = _run(["systemctl", "is-active", f"{unit}.service"], timeout=2) == "active"

    waha_session = "unknown"
    api_key = get(env, "WAHA_API_KEY")
    if api_key and containers.get("wazuh-waha"):
        host = get(env, "WAHA_HOST", "http://127.0.0.1:3001").rstrip("/")
        session = get(env, "WAHA_SESSION", "default")
        code, body = _http_json(
            f"{host}/api/sessions/{session}",
            headers={"X-Api-Key": api_key},
            timeout=3.0,
        )
        if code == 200:
            try:
                waha_session = json.loads(body).get("status", "unknown")
            except Exception:
                waha_session = "invalid"
        else:
            waha_session = "unreachable"

    return {
        "ts": int(time.time()),
        "internet": internet_ok(),
        "relay": relay_ok,
        "containers": containers,
        "services": services,
        "waha_session": waha_session,
    }


def load_state() -> dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_name(f".{STATE_FILE.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


def fmt_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def _notify(
    state: dict[str, Any],
    event: str,
    detail: str,
    *,
    dry_run: bool,
    queue_if_failed: bool = True,
) -> None:
    if dry_run:
        print(f"[monitor] DRY-RUN notificar {event}: {detail}")
        return
    results = send_message(event, detail=detail)
    delivered = any(result.get("ok") for result in results.values())
    if not delivered and queue_if_failed:
        state.setdefault("pending", []).append(
            {"event": event, "detail": detail, "queued_at": int(time.time())}
        )
        print(f"[monitor] pendiente encolado: {event} ({detail})")


def _transition(
    state: dict[str, Any],
    key: str,
    previous: Any,
    current: Any,
    event_down: str,
    event_up: str,
    detail: str,
    *,
    dry_run: bool,
    queue_if_failed: bool = True,
) -> None:
    """Notifica una transicion booleana true->false / false->true."""
    if previous is None:
        return
    since = state.setdefault("since", {})
    if previous and not current:
        since[key] = int(time.time())
        _notify(state, event_down, detail, dry_run=dry_run, queue_if_failed=queue_if_failed)
    elif not previous and current:
        down_since = int(since.pop(key, state.get("ts", int(time.time()))))
        duration = fmt_duration(int(time.time()) - down_since)
        _notify(
            state,
            event_up,
            f"{detail} (caido {duration})",
            dry_run=dry_run,
            queue_if_failed=queue_if_failed,
        )


def process(current: dict[str, Any], previous: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    state = json.loads(json.dumps(previous)) if previous else {}
    baseline = not previous.get("initialized")

    if baseline:
        state.update(current)
        state["initialized"] = True
        state.setdefault("pending", [])
        state["since"] = {}
        state["baseline_at"] = current["ts"]
        if not dry_run:
            log_event(
                "monitor-baseline",
                "Monitor inicializado; se notificara solo en cambios de estado",
            )
            save_state(state)
        print("[monitor] baseline creado (sin notificaciones)")
        return state

    # Red: caida y recuperacion con duracion. La caida no se encola porque
    # no hay Internet para enviarla; la recuperacion informa la duracion.
    prev_internet = previous.get("internet")
    now_internet = current["internet"]
    if prev_internet is not None and prev_internet != now_internet:
        if prev_internet and not now_internet:
            state.setdefault("since", {})["internet"] = int(time.time())
            _notify(
                state,
                "network-down",
                "Se perdio la conectividad a Internet",
                dry_run=dry_run,
                queue_if_failed=False,
            )
        else:
            down_since = int(
                state.get("since", {}).pop("internet", state.get("ts", int(time.time())))
            )
            _notify(
                state,
                "network-up",
                f"Conectividad restablecida (caida {fmt_duration(int(time.time()) - down_since)})",
                dry_run=dry_run,
            )

    _transition(
        state,
        "relay",
        previous.get("relay"),
        current["relay"],
        "service-down",
        "service-up",
        f"Relay HTTP :{get(load_env(), 'RELAY_PORT', '8765')}",
        dry_run=dry_run,
    )

    prev_containers = previous.get("containers", {})
    for name, running in current["containers"].items():
        _transition(
            state,
            f"container:{name}",
            prev_containers.get(name),
            running,
            "service-down",
            "service-up",
            f"Contenedor {name}",
            dry_run=dry_run,
        )

    prev_services = previous.get("services", {})
    for unit, active in current["services"].items():
        _transition(
            state,
            f"service:{unit}",
            prev_services.get(unit),
            active,
            "service-down",
            "service-up",
            f"Servicio {unit}.service",
            dry_run=dry_run,
        )

    # Sesion WAHA: solo avisar cuando cambia entre WORKING y no-WORKING.
    prev_session = previous.get("waha_session")
    now_session = current["waha_session"]
    if prev_session != now_session:
        was_working = prev_session == "WORKING"
        is_working = now_session == "WORKING"
        if was_working and not is_working:
            _notify(
                state,
                "waha-session-down",
                f"Sesion WhatsApp paso de WORKING a {now_session}",
                dry_run=dry_run,
            )
        elif not was_working and is_working:
            _notify(
                state,
                "waha-session-up",
                "Sesion WhatsApp volvio a WORKING",
                dry_run=dry_run,
            )

    # Reintentar eventos pendientes cuando ya hay Internet.
    if current["internet"] and state.get("pending"):
        remaining = []
        for item in state["pending"]:
            if dry_run:
                print(f"[monitor] DRY-RUN pendiente: {item}")
                remaining.append(item)
                continue
            results = send_message(
                item.get("event", "service-down"),
                detail=f"(pendiente) {item.get('detail', '')}",
            )
            if not any(result.get("ok") for result in results.values()):
                remaining.append(item)
        state["pending"] = remaining

    state.update(
        {
            "ts": current["ts"],
            "internet": current["internet"],
            "relay": current["relay"],
            "containers": current["containers"],
            "services": current["services"],
            "waha_session": current["waha_session"],
            "last_check": current["ts"],
        }
    )
    if not dry_run:
        save_state(state)
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor del host wazuh-waha")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--interval", type=int, default=0, help="segundos entre pasadas")
    args = parser.parse_args()

    if args.reset:
        for path in (STATE_FILE, LOCK_FILE):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        print("[monitor] estado borrado")
        return 0

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    lock_handle = LOCK_FILE.open("w")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("[monitor] otra ejecucion en curso, salgo")
        return 0

    try:
        while True:
            env = load_env()
            current = check(env)
            previous = load_state()
            process(current, previous, dry_run=args.dry_run)
            if args.interval <= 0:
                break
            time.sleep(args.interval)
    finally:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_UN)
        except Exception:
            pass
        lock_handle.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
