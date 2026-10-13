"""
telegram_bot.py — Cliente, persistencia y bot interactivo de Telegram para Wazuh-WAHA.

Funcionalidades:
1. Persistencia infalible de sesión en disco (/var/lib/wazuh-waha/telegram_session.json y .env)
   que resiste reinicios del servidor, systemd y cortes de energía.
2. Envío de alertas de seguridad y notificaciones de salud en español.
3. Bot interactivo con comandos de monitoreo en tiempo real:
   - /status    -> CPU Load, RAM, Disco, Uptime y Host
   - /servicios -> Estado de Wazuh Manager, Agent, WAHA, Dashboard y Relay
   - /red       -> Puertos del ecosistema (1514, 55000, 8765, 3001, 8001, 22), sockets y tráfico
   - /agentes   -> Lista de equipos/agentes Wazuh conectados (SO, IP, estado)
   - /agente <id> -> Diagnóstico detallado del agente (sockets, RX/TX MB, últimas alertas)
   - /alertas   -> Últimas alertas de seguridad registradas
   - /kpis      -> Métricas de despacho, supresión/deduplicación y latencia
   - /canales   -> Estado de WhatsApp, Telegram y Correo
   - /reglas    -> Lista de reglas de seguridad locales activas en Wazuh
   - /ping      -> Comprobación de disponibilidad y latencia
   - /ayuda     -> Menú interactivo con todos los comandos
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import time
from pathlib import Path
from typing import Any

import httpx

from ..config import ENV_FILE, settings
from ..common.traffic_stream import traffic_watcher
from ..domain.templates import _format_level_es, _translate_description_es, translate_full_log_es

log = logging.getLogger("wazuh-waha.telegram")

TELEGRAM_API_BASE = "https://api.telegram.org/bot"


# ─────────────────────────────────────────────────────────────
# 1. Persistencia Robusta de Sesión de Telegram
# ─────────────────────────────────────────────────────────────

def get_session_file() -> Path:
    """Devuelve la ruta al archivo de persistencia de sesión de Telegram."""
    try:
        lib_dir = Path(settings.relay_lib_dir)
        if lib_dir.exists() and os.access(lib_dir, os.W_OK):
            return lib_dir / "telegram_session.json"
    except Exception:
        pass

    # Fallback al directorio data dentro del repo
    data_dir = ENV_FILE.parent / "data"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / "telegram_session.json"
    except Exception:
        return Path("/tmp/telegram_session.json")


def save_telegram_session(
    token: str | None = None,
    chat_id: str | None = None,
    enabled: bool | None = None,
    min_level: int | None = None,
) -> bool:
    """Persiste la configuración de Telegram en disco de forma atómica y redundante.
    
    Escribe en:
    1. telegram_session.json (/var/lib/wazuh-waha/telegram_session.json)
    2. config_overrides.json (usado por config.py al arrancar)
    3. .env del repositorio (si el sistema de archivos lo permite)
    4. Sincroniza /etc/wazuh-waha/relay.env para systemd
    """
    session_file = get_session_file()
    current_data: dict[str, Any] = {}
    if session_file.exists():
        try:
            current_data = json.loads(session_file.read_text(encoding="utf-8"))
        except Exception:
            current_data = {}

    tk = token if token is not None else (getattr(settings, "telegram_bot_token", "") or current_data.get("token", ""))
    cid = chat_id if chat_id is not None else (getattr(settings, "telegram_chat_id", "") or current_data.get("chat_id", ""))
    en = enabled if enabled is not None else (getattr(settings, "telegram_enabled", False) if hasattr(settings, "telegram_enabled") else current_data.get("enabled", False))
    ml = min_level if min_level is not None else (getattr(settings, "telegram_min_level", 8) if hasattr(settings, "telegram_min_level") else current_data.get("min_level", 8))

    session_data = {
        "token": str(tk).strip(),
        "chat_id": str(cid).strip(),
        "enabled": bool(en),
        "min_level": int(ml),
        "updated_at": time.time(),
        "updated_at_str": time.strftime("%Y-%m-%d %H:%M:%S %z"),
    }

    # 1. Guardar en telegram_session.json
    try:
        session_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = session_file.with_suffix(".tmp")
        temp_file.write_text(json.dumps(session_data, indent=2), encoding="utf-8")
        temp_file.replace(session_file)
        try:
            os.chmod(session_file, 0o600)
        except Exception:
            pass
        log.info("telegram_session_saved file=%s chat_id=%s enabled=%s", session_file, cid, en)
    except Exception as e:
        log.warning("telegram_session_write_err file=%s err=%s", session_file, e)

    # 2. Guardar en config_overrides.json para que config.py lo lea al boot
    try:
        from ..config import load_overrides, save_overrides
        overrides = load_overrides()
        if tk:
            overrides["telegram_bot_token"] = str(tk).strip()
            overrides["TELEGRAM_BOT_TOKEN"] = str(tk).strip()
        if cid:
            overrides["telegram_chat_id"] = str(cid).strip()
            overrides["TELEGRAM_CHAT_ID"] = str(cid).strip()
        overrides["telegram_enabled"] = bool(en)
        overrides["TELEGRAM_ENABLED"] = bool(en)
        overrides["telegram_min_level"] = int(ml)
        overrides["TELEGRAM_MIN_LEVEL"] = int(ml)
        save_overrides(overrides)
    except Exception as e:
        log.warning("telegram_overrides_save_err err=%s", e)

    # 3. Reflejar en memoria en settings
    if tk:
        setattr(settings, "telegram_bot_token", str(tk).strip())
    if cid:
        setattr(settings, "telegram_chat_id", str(cid).strip())
    setattr(settings, "telegram_enabled", bool(en))
    setattr(settings, "telegram_min_level", int(ml))

    # 4. Actualizar .env si es posible
    env_updates: dict[str, str] = {
        "TELEGRAM_ENABLED": "true" if en else "false",
        "TELEGRAM_MIN_LEVEL": str(ml),
    }
    if tk:
        env_updates["TELEGRAM_BOT_TOKEN"] = str(tk).strip()
    if cid:
        env_updates["TELEGRAM_CHAT_ID"] = str(cid).strip()

    _save_to_env(env_updates)
    _sync_systemd_env()

    return True


def load_telegram_session() -> dict[str, Any]:
    """Carga y restaura la sesión de Telegram guardada en disco si los settings están vacíos."""
    session_file = get_session_file()
    data: dict[str, Any] = {}

    if session_file.exists():
        try:
            data = json.loads(session_file.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("telegram_session_read_err err=%s", e)

    if not data:
        try:
            from ..config import load_overrides
            ov = load_overrides()
            if ov.get("telegram_bot_token") or ov.get("TELEGRAM_BOT_TOKEN"):
                data = {
                    "token": ov.get("telegram_bot_token") or ov.get("TELEGRAM_BOT_TOKEN", ""),
                    "chat_id": ov.get("telegram_chat_id") or ov.get("TELEGRAM_CHAT_ID", ""),
                    "enabled": ov.get("telegram_enabled") if "telegram_enabled" in ov else ov.get("TELEGRAM_ENABLED", False),
                    "min_level": ov.get("telegram_min_level") or ov.get("TELEGRAM_MIN_LEVEL", 8),
                }
        except Exception:
            pass

    if data:
        token = data.get("token")
        chat_id = data.get("chat_id")
        enabled = data.get("enabled")
        min_level = data.get("min_level")

        if token and not getattr(settings, "telegram_bot_token", ""):
            setattr(settings, "telegram_bot_token", str(token).strip())
        if chat_id and not getattr(settings, "telegram_chat_id", ""):
            setattr(settings, "telegram_chat_id", str(chat_id).strip())
        if enabled is not None:
            setattr(settings, "telegram_enabled", bool(enabled))
        if min_level is not None:
            setattr(settings, "telegram_min_level", int(min_level))

        log.info(
            "telegram_session_loaded enabled=%s token_set=%s chat_id=%s",
            getattr(settings, "telegram_enabled", False),
            bool(getattr(settings, "telegram_bot_token", "")),
            getattr(settings, "telegram_chat_id", ""),
        )

    return data


def _save_to_env(updates: dict[str, str]) -> None:
    """Guarda claves en el archivo .env sin fallar si el filesystem es de solo lectura."""
    try:
        if not ENV_FILE.exists():
            return
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        handled = set()

        for line in lines:
            stripped = line.strip()
            matched = None
            for k in updates:
                if stripped.startswith(f"{k}=") or stripped.startswith(f"{k} "):
                    matched = k
                    break
            if matched:
                if matched not in handled:
                    new_lines.append(f"{matched}={updates[matched]}")
                    handled.add(matched)
                continue
            new_lines.append(line)

        for k, v in updates.items():
            if k not in handled:
                new_lines.append(f"{k}={v}")

        ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception as e:
        log.debug("telegram_env_write_ignored (posible read-only bajo systemd): %s", e)


def _sync_systemd_env() -> None:
    """Ejecuta sync_relay_env.sh si sudo lo permite sin contraseña."""
    try:
        script = ENV_FILE.parent / "scripts" / "sync_relay_env.sh"
        if script.exists():
            import subprocess
            subprocess.run(["sudo", "-n", str(script), "apply"], capture_output=True, timeout=10)
    except Exception:
        pass


# Cargar sesión guardada inmediatamente al importar el módulo
load_telegram_session()


# ─────────────────────────────────────────────────────────────
# 2. Cliente HTTP y Envío a Telegram
# ─────────────────────────────────────────────────────────────

def _bot_url(path: str, token: str | None = None) -> str:
    tk = token or settings.telegram_bot_token
    return f"{TELEGRAM_API_BASE}{tk}/{path.lstrip('/')}"


async def get_bot_info(token: str | None = None) -> dict[str, Any]:
    """Valida el token con getMe y devuelve info del bot."""
    tk = token or settings.telegram_bot_token
    if not tk:
        return {"ok": False, "error": "Token no proporcionado"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_bot_url("getMe", tk))
            data = resp.json()
            if resp.is_success and data.get("ok"):
                res = data.get("result", {})
                return {
                    "ok": True,
                    "id": res.get("id"),
                    "username": res.get("username", ""),
                    "first_name": res.get("first_name", ""),
                }
            return {"ok": False, "error": data.get("description", f"HTTP {resp.status_code}")}
    except Exception as e:
        log.warning("telegram_get_me_err err=%s", e)
        return {"ok": False, "error": str(e)}


async def send_message(
    text: str,
    chat_id: str | None = None,
    token: str | None = None,
    parse_mode: str = "Markdown",
) -> bool:
    """Envía un mensaje a Telegram. Si falla el markdown, reintenta en texto plano."""
    tk = token or settings.telegram_bot_token
    cid = chat_id or settings.telegram_chat_id
    if not tk or not cid:
        log.debug("telegram_send_skipped (token o chat_id vacio)")
        return False

    safe_text = text if len(text) <= 4000 else text[:3980] + "\n…[truncado]"

    payload: dict[str, Any] = {
        "chat_id": cid,
        "text": safe_text,
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode

    url = _bot_url("sendMessage", tk)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            if resp.is_success:
                return True

            if parse_mode and resp.status_code == 400:
                payload.pop("parse_mode", None)
                retry_resp = await client.post(url, json=payload)
                if retry_resp.is_success:
                    return True

            log.warning("telegram_send_fail status=%d body=%r", resp.status_code, resp.text[:200])
            return False
    except Exception as e:
        log.warning("telegram_send_err err=%s", e)
        return False


async def send_document(
    document_bytes: bytes,
    filename: str,
    caption: str = "",
    chat_id: str | None = None,
    token: str | None = None,
) -> bool:
    """Envía un archivo/documento (como reporte PDF) a Telegram."""
    tk = token or getattr(settings, "telegram_bot_token", "")
    cid = chat_id or getattr(settings, "telegram_chat_id", "")
    if not tk or not cid:
        log.debug("telegram_send_document_skipped (token o chat_id vacio)")
        return False

    url = _bot_url("sendDocument", tk)
    data: dict[str, Any] = {"chat_id": cid}
    if caption:
        data["caption"] = caption[:1024]
        data["parse_mode"] = "Markdown"

    files = {
        "document": (filename, document_bytes, "application/pdf")
    }

    try:
        async with httpx.AsyncClient(timeout=35) as client:
            resp = await client.post(url, data=data, files=files)
            if resp.is_success:
                return True
            log.warning("telegram_send_document_fail status=%d body=%r", resp.status_code, resp.text[:200])
            return False
    except Exception as e:
        log.warning("telegram_send_document_err err=%s", e)
        return False


async def get_updates(token: str | None = None, offset: int = 0, timeout: int = 5) -> list[dict]:
    """Lee updates pendientes vía long polling."""
    tk = token or settings.telegram_bot_token
    if not tk:
        return []
    url = _bot_url("getUpdates", tk)
    params = {"offset": offset, "timeout": timeout, "limit": 20}
    try:
        async with httpx.AsyncClient(timeout=timeout + 5) as client:
            resp = await client.get(url, params=params)
            if resp.is_success:
                data = resp.json()
                if data.get("ok"):
                    return data.get("result", [])
    except Exception as e:
        log.debug("telegram_get_updates_err err=%s", e)
    return []


async def pair_session(token: str | None = None, wait_seconds: int = 25) -> dict[str, Any]:
    """Empareja el bot con el usuario esperando que envíe /start."""
    tk = token or settings.telegram_bot_token
    bot_info = await get_bot_info(tk)
    if not bot_info.get("ok"):
        return {"ok": False, "error": bot_info.get("error", "Token inválido")}

    bot_username = bot_info.get("username", "")

    initial_updates = await get_updates(token=tk, offset=0, timeout=1)
    offset = 0
    if initial_updates:
        offset = initial_updates[-1].get("update_id", 0) + 1

    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        updates = await get_updates(token=tk, offset=offset, timeout=3)
        for u in updates:
            offset = u.get("update_id", 0) + 1
            msg = u.get("message") or u.get("edited_message")
            if msg and "chat" in msg:
                chat = msg["chat"]
                chat_id = str(chat.get("id"))
                first_name = chat.get("first_name", "Admin")
                username = chat.get("username", "")

                welcome_txt = (
                    f"✅ *¡Conexión establecida con éxito!*\n\n"
                    f"Hola *{first_name}*, tu cuenta ha sido vinculada al servidor *{platform.node()}*.\n"
                    f"Esta sesión persistirá aunque el servidor se reinicie o haya un corte eléctrico.\n\n"
                    f"Puedes enviar `/ayuda` para conocer todos los comandos de monitoreo."
                )
                await send_message(welcome_txt, chat_id=chat_id, token=tk)

                save_telegram_session(token=tk, chat_id=chat_id, enabled=True)

                return {
                    "ok": True,
                    "chat_id": chat_id,
                    "first_name": first_name,
                    "username": username,
                    "bot_username": bot_username,
                }
        await asyncio.sleep(1)

    return {
        "ok": False,
        "waiting": True,
        "bot_username": bot_username,
        "instructions": f"Abre Telegram y envía /start a @{bot_username}",
    }


async def send_alert(
    message_text: str,
    level: int = 0,
    rule_id: str = "0",
    agent_name: str = "?",
) -> bool:
    """Envía alerta de seguridad a Telegram si el canal está activo y supera el nivel mínimo."""
    if not getattr(settings, "telegram_enabled", False):
        return False
    if not getattr(settings, "telegram_bot_token", "") or not getattr(settings, "telegram_chat_id", ""):
        return False
    if level < getattr(settings, "telegram_min_level", 8):
        return False

    prefix = "🚨 *ALERTA WAZUH*" if level >= 10 else "⚠️ *AVISO DE SEGURIDAD*"
    formatted = f"{prefix}\n\n{message_text}"
    return await send_message(formatted)


async def send_health_notice(description: str, level: int = 15, **fields) -> bool:
    """Envía un evento de salud de la infraestructura a Telegram."""
    if not getattr(settings, "telegram_enabled", False):
        return False
    if not getattr(settings, "telegram_bot_token", "") or not getattr(settings, "telegram_chat_id", ""):
        return False

    emoji = "🔥" if level >= 15 else "⚠️"
    lines = [
        f"{emoji} *EVENTO DE SALUD - WAZUH-WAHA*",
        f"*Descripción:* {description}",
        f"*Nivel:* {level}",
        f"*Hora:* {time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    for k, v in fields.items():
        lines.append(f"• *{k}:* `{v}`")

    return await send_message("\n".join(lines))


# ─────────────────────────────────────────────────────────────
# 3. Métricas y Formateadores para Comandos de Monitoreo
# ─────────────────────────────────────────────────────────────

def _get_system_status() -> str:
    """Recolecta métricas del host del servidor."""
    try:
        load1, load5, load15 = os.getloadavg()
        load_str = f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    except Exception:
        load_str = "N/D"

    uptime_str = "N/D"
    try:
        with open("/proc/uptime", "r") as f:
            up_secs = float(f.readline().split()[0])
            days = int(up_secs // 86400)
            hours = int((up_secs % 86400) // 3600)
            minutes = int((up_secs % 3600) // 60)
            uptime_str = f"{days}d {hours}h {minutes}m"
    except Exception:
        pass

    ram_str = "N/D"
    try:
        with open("/proc/meminfo", "r") as f:
            mem = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].split()[0])
            total_mb = mem.get("MemTotal", 0) // 1024
            avail_mb = mem.get("MemAvailable", 0) // 1024
            used_mb = total_mb - avail_mb
            pct = (used_mb / total_mb * 100) if total_mb else 0
            ram_str = f"{used_mb}MB / {total_mb}MB ({pct:.1f}%)"
    except Exception:
        pass

    try:
        total, used, free = shutil.disk_usage("/")
        disk_total_gb = total // (1024**3)
        disk_used_gb = used // (1024**3)
        disk_pct = (used / total * 100) if total else 0
        disk_str = f"{disk_used_gb}GB / {disk_total_gb}GB ({disk_pct:.1f}%)"
    except Exception:
        disk_str = "N/D"

    return (
        f"📊 *ESTADO DEL SERVIDOR*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️ *Host:* `{platform.node()}`\n"
        f"⏱️ *Uptime:* {uptime_str}\n"
        f"⚡ *CPU Load (1m, 5m, 15m):* {load_str}\n"
        f"🧠 *Memoria RAM:* {ram_str}\n"
        f"💾 *Disco (/):* {disk_str}\n"
        f"⏰ *Hora local:* {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )


async def _get_services_status() -> str:
    """Verifica el estado de los servicios clave del ecosistema."""
    lines = [
        "🛠️ *ESTADO DE SERVICIOS*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]

    # Relay
    lines.append(f"• *Relay HTTP (puerto {settings.relay_port}):* 🟢 ACTIVO")

    # WAHA Docker
    waha_ok = False
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(
                f"{settings.waha_host}/api/server/version",
                headers={"X-Api-Key": settings.waha_api_key},
            )
            waha_ok = r.is_success
    except Exception:
        waha_ok = False
    lines.append(f"• *WAHA (WhatsApp API):* {'🟢 ACTIVO' if waha_ok else '🔴 INACTIVO / ERROR'}")

    # Manager Wazuh API
    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip
    mgr_ok = False
    try:
        async with httpx.AsyncClient(timeout=3, verify=False) as client:
            r = await client.get(f"https://{mgr_host}:{settings.wazuh_manager_api_port}")
            mgr_ok = r.status_code in (200, 401)
    except Exception:
        mgr_ok = False
    lines.append(f"• *Wazuh Manager ({mgr_host}):* {'🟢 RESPONDE' if mgr_ok else '🔴 NO RESPONDE'}")

    # Agente local
    agent_installed = os.path.isdir("/var/ossec")
    lines.append(f"• *Wazuh Agent Local:* {'🟢 INSTALADO' if agent_installed else '⚪ NO INSTALADO'}")

    # Ollama AI
    if getattr(settings, "ollama_enabled", False):
        ollama_ok = False
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                r = await client.get(f"{settings.ollama_host}/api/version")
                ollama_ok = r.is_success
        except Exception:
            ollama_ok = False
        lines.append(f"• *Ollama AI ({settings.ollama_model}):* {'🟢 ACTIVO' if ollama_ok else '🔴 NO RESPONDE'}")

    return "\n".join(lines)


async def _get_network_traffic_summary() -> str:
    """Genera diagnóstico del tráfico de red y puertos del ecosistema."""
    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip or "127.0.0.1"

    ports_to_test = [
        (1514, "Wazuh Agentes (Remoted)", mgr_host),
        (55000, "Wazuh API REST", mgr_host),
        (8765, "Relay wazuh-waha", "127.0.0.1"),
        (3001, "WAHA WhatsApp Gateway", "127.0.0.1"),
        (8001, "SOC Dashboard Web", "127.0.0.1"),
        (22, "SSH Acceso Remoto", mgr_host),
    ]

    async def _test_port(host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    results = await asyncio.gather(*[_test_port(h, p) for p, _, h in ports_to_test])

    lines = [
        "🌐 *MONITOREO DE RED Y PUERTOS*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🖥️ *Servidor Manager:* `{mgr_host}`",
        "",
        "🔌 *Puertos del Ecosistema:*",
    ]

    for (p, label, _), is_open in zip(ports_to_test, results):
        status_ico = "🟢 ACTIVO" if is_open else "🔴 CERRADO / DOWN"
        lines.append(f"• `{p}/TCP` ({label}): {status_ico}")

    # Obtener telemetría de sockets
    try:
        from ..api.telemetry import _fetch_agent_traffic_details
        details = await _fetch_agent_traffic_details("all")
        kpis = details.get("kpis", {})
        total_sock = kpis.get("total_sockets", 0)
        listen_sock = kpis.get("listening_sockets", 0)
        estab_sock = kpis.get("established_connections", 0)
        rx_mb = kpis.get("total_rx_mb", 0.0)
        tx_mb = kpis.get("total_tx_mb", 0.0)

        lines.extend([
            "",
            "📊 *Métricas de Sockets y Tráfico:*",
            f"• Sockets Totales Monitoreados: `{total_sock}`",
            f"• Puertos en Escucha: `{listen_sock}`",
            f"• Conexiones Establecidas: `{estab_sock}`",
            f"• Volumen de Datos de Agentes: `{rx_mb} MB RX / {tx_mb} MB TX`",
        ])

        # Destinos y sitios web detectados
        sites = details.get("sites_activity", [])
        if sites:
            lines.extend([
                "",
                "🌐 *Sitios y Destinos Web Detectados en la Red:*",
            ])
            for s in sites[:6]:
                lines.append(f"• *{s['site_name']}* (`{s['remote_ip']}:{s['remote_port']}`) vía `{s['process']}` en `[{s['agent_id']}]`")
    except Exception as e:
        log.debug("error getting socket details: %s", e)

    return "\n".join(lines)


async def _get_network_sites_summary() -> str:
    """Devuelve inventario detallado de sitios web y destinos navegados por los agentes."""
    try:
        from ..api.telemetry import _fetch_agent_traffic_details
        details = await _fetch_agent_traffic_details("all")
        sites = details.get("sites_activity", [])
    except Exception as e:
        return f"⚠️ Error consultando sitios de la red: {e}"

    if not sites:
        return "ℹ️ *No se registran destinos externos ni sitios activos en los agentes en este momento.*"

    lines = [
        "🌐 *SITIOS Y ACTIVIDAD WEB DE LOS AGENTES*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"• Total Sitios/Destinos: `{len(sites)}`",
        f"• Conexiones Web Activas: `{sum(1 for s in sites if s.get('is_web'))}`",
        "",
        "📡 *Destinos Detectados en la Red:*",
    ]

    for s in sites[:10]:
        state_ico = "🟢" if "estab" in s.get("state", "").lower() or "activa" in s.get("state_label", "").lower() else "🟡"
        is_web_tag = "🌐 [Web]" if s.get("is_web") else "🔌 [Servicio]"
        lines.append(
            f"{state_ico} *{s['site_name']}* ({s['domain']})\n"
            f"  {is_web_tag} `{s['remote_ip']}:{s['remote_port']}` ({s['protocol']}) | Proceso: `{s['process']}` | Equipo: `[{s['agent_id']}] {s['agent_name']}`"
        )

    return "\n\n".join(lines)


async def _get_agents_list_summary() -> str:
    """Devuelve listado de agentes/equipos conectados a Wazuh."""
    try:
        from ..api.telemetry import _fetch_network_agents_data
        agents = await _fetch_network_agents_data()
    except Exception as e:
        return f"⚠️ Error consultando agentes de Wazuh: {e}"

    if not agents:
        return "ℹ️ *No se encontraron agentes registrados en el Wazuh Manager.*"

    lines = [
        "👥 *EQUIPOS Y AGENTES REGISTRADOS*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]

    for ag in agents:
        ag_id = ag.get("id", "?")
        name = ag.get("name", "host")
        ip = ag.get("ip", "desconocida")
        status = str(ag.get("status", "desconocido")).lower()
        ico = "🟢 ACTIVO" if status in ("active", "activo") else "🔴 DESCONECTADO"
        os_info = ag.get("os", {})
        os_name = os_info.get("name", "Linux") if isinstance(os_info, dict) else "Linux"
        version = ag.get("version", "Wazuh v4.x")
        lines.append(f"• `[{ag_id}]` *{name}* ({ip})\n  Estado: {ico} | {os_name} · {version}")

    lines.append("\n_Tip: Usa `/agente <id>` para ver tráfico y sockets de un equipo específico._")
    return "\n".join(lines)


def _render_bar(pct: float, length: int = 8) -> str:
    """Genera una barra gráfica de progreso visual para Telegram / WhatsApp."""
    filled = int(round(max(0, min(100, pct)) / 100.0 * length))
    return "█" * filled + "░" * (length - filled)


async def _get_agent_detail_summary(agent_id: str, subcmd: str = "") -> str:
    """Devuelve diagnóstico profundo y forense de un agente con soporte para submódulos."""
    aid = str(agent_id).strip()
    sub = str(subcmd or "").strip().lower()

    try:
        from ..api.telemetry import _fetch_agent_full_profile
        profile = await _fetch_agent_full_profile(aid)
    except Exception as e:
        return f"⚠️ Error consultando perfil forense del agente {aid}: {e}"

    if not profile or not profile.get("ok"):
        return f"⚠️ No se encontró telemetría para el agente `{aid}`."

    name = profile.get("name", f"agente-{aid}")
    ip = profile.get("ip", "N/D")
    status = str(profile.get("status", "active")).upper()
    hw = profile.get("hardware", {})
    os_info = profile.get("os", {})
    net = profile.get("network", {})
    sca = profile.get("sca", {})
    fim = profile.get("fim", {})
    soft = profile.get("software", {})
    procs = profile.get("processes", {})
    sites = profile.get("active_sites", [])
    alerts = profile.get("recent_detections", [])

    # 1. Submódulo: Hardware
    if sub in ("hardware", "hw", "cpu", "ram"):
        ram_pct = hw.get("ram_usage_percent", 0.0)
        ram_bar = _render_bar(ram_pct)
        ram_tot_gb = round(hw.get("ram_total_mb", 0) / 1024, 2)
        ram_used_gb = round(hw.get("ram_used_mb", 0) / 1024, 2)
        ram_free_gb = round(hw.get("ram_free_mb", 0) / 1024, 2)

        return (
            f"💻 *ESPECIFICACIONES DE HARDWARE [{aid}] - {name}*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"• Procesador: `{hw.get('cpu_name', 'Desconocido')}`\n"
            f"• Núcleos / Hilos: `{hw.get('cpu_cores', 1)} núcleos` ({hw.get('cpu_mhz', 0)} MHz)\n"
            f"• Arquitectura: `{os_info.get('architecture', 'x86_64')}`\n"
            f"• Placa / Serial: `{hw.get('board_serial', '-')}`\n\n"
            "🧠 *Memoria RAM:*\n"
            f"• Uso: `[{ram_bar}] {ram_pct:.1f}%`\n"
            f"• Total: `{hw.get('ram_total_mb', 0)} MB` ({ram_tot_gb} GB)\n"
            f"• En Uso: `{hw.get('ram_used_mb', 0)} MB` ({ram_used_gb} GB)\n"
            f"• Libre: `{hw.get('ram_free_mb', 0)} MB` ({ram_free_gb} GB)\n\n"
            "🐧 *Sistema Operativo:*\n"
            f"• Distro: `{os_info.get('name', 'Linux')}` ({os_info.get('version', '-')})\n"
            f"• Kernel: `{os_info.get('kernel', '-')}`\n"
            f"• Hostname: `{os_info.get('hostname', name)}`"
        )

    # 2. Submódulo: Red & Adaptadores
    if sub in ("red", "net", "interfaces", "network"):
        ifaces = net.get("interfaces", [])
        lines = [
            f"📡 *INVENTARIO DE RED Y ADAPTADORES [{aid}] - {name}*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"• Tráfico Acumulado: `{net.get('total_rx_mb', 0.0)} MB RX` / `{net.get('total_tx_mb', 0.0)} MB TX`",
            "",
            "🔌 *Interfaces de Red Detectadas:*",
        ]
        for iface in ifaces:
            st = "🟢 ACTIVA" if iface.get("state") == "up" else "⚪ INACTIVA"
            rx = round(iface.get("rx_bytes", 0) / (1024 * 1024), 2)
            tx = round(iface.get("tx_bytes", 0) / (1024 * 1024), 2)
            mac = iface.get("mac", "-")
            ipv4 = iface.get("ipv4") or "-"
            lines.append(
                f"• `{iface.get('name')}` ({st}):\n"
                f"  MAC: `{mac}` | IPv4: `{ipv4}`\n"
                f"  Tráfico: `{rx} MB RX` / `{tx} MB TX` (Paquetes: {iface.get('rx_packets', 0)} RX / {iface.get('tx_packets', 0)} TX)"
            )
        return "\n".join(lines)

    # 3. Submódulo: SCA (CIS Benchmark)
    if sub in ("sca", "cis", "seguridad", "compliance"):
        score = sca.get("score", 0)
        sca_bar = _render_bar(score)
        failed_checks = sca.get("failed_checks", [])

        lines = [
            f"🔒 *POSTURA DE SEGURIDAD CIS BENCHMARK [{aid}] - {name}*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"• Evaluación: *{sca.get('name', 'CIS Benchmark')}*",
            f"• Política: `{sca.get('policy_id', 'cis')}`",
            f"• Puntuación de Seguridad: `[{sca_bar}] {score}%`",
            f"• Total Controles: `{sca.get('total_checks', 0)}`",
            f"• Aprobados: `✅ {sca.get('pass', 0)}` | Fallados: `❌ {sca.get('fail', 0)}`",
        ]
        if failed_checks:
            lines.append("\n🚨 *Principales Controles Fallados & Remediación:*")
            for idx, c in enumerate(failed_checks[:5], 1):
                lines.append(
                    f"{idx}. *{c.get('title')}*\n"
                    f"   _Motivo:_ {c.get('rationale')}\n"
                    f"   🔧 _Remediación:_ `{c.get('remediation')}`"
                )
        return "\n".join(lines)

    # 4. Submódulo: Procesos
    if sub in ("procesos", "ps", "process"):
        top_p = procs.get("top_processes", [])
        lines = [
            f"⚙️ *PROCESOS EN EJECUCIÓN [{aid}] - {name}*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"• Total Procesos: `{procs.get('total_count', len(top_p))}`",
            "",
            "📋 *Top Procesos Activos:*",
        ]
        for pr in top_p[:12]:
            u = pr.get("euser") or pr.get("user") or "root"
            pid = pr.get("pid", 0)
            pname = pr.get("name", "proceso")
            cmd = (pr.get("cmd") or "")[:50]
            cmd_snippet = f" (`{cmd}`)" if cmd and cmd != pname else ""
            lines.append(f"• `[PID {pid}]` *{pname}* (Usuario: `{u}`){cmd_snippet}")
        return "\n".join(lines)

    # 5. Submódulo: Software y Paquetes
    if sub in ("paquetes", "software", "pkg"):
        sample_pkg = soft.get("sample_packages", [])
        lines = [
            f"📦 *INVENTARIO DE SOFTWARE [{aid}] - {name}*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"• Total Paquetes Instalados: `{soft.get('total_packages', 0)}`",
            "",
            "📚 *Muestra de Paquetes:*",
        ]
        for p in sample_pkg[:10]:
            lines.append(f"• *{p.get('name')}* `{p.get('version')}` ({p.get('vendor', 'Linux')})")
        return "\n".join(lines)

    # 6. Submódulo: FIM (Syscheck)
    if sub in ("fim", "syscheck", "archivos"):
        recent_f = fim.get("recent_files", [])
        lines = [
            f"📁 *INTEGRIDAD DE ARCHIVOS FIM [{aid}] - {name}*",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"• Archivos Monitoreados: `{fim.get('total_monitored', 0)}`",
            "",
            "📄 *Archivos Auditados Recientes:*",
        ]
        for f in recent_f[:8]:
            sz = f.get("size", 0)
            lines.append(f"• `{f.get('file')}` ({sz} B, perm `{f.get('perm')}`, usuario `{f.get('uname')}`)")
        return "\n".join(lines)

    # 7. Resumen Ejecutivo Completo (Default)
    ram_pct = hw.get("ram_usage_percent", 0.0)
    ram_bar = _render_bar(ram_pct)
    sca_score = sca.get("score", 0)
    sca_bar = _render_bar(sca_score)
    status_ico = "🟢 ACTIVO" if "ACT" in status else "🔴 DESCONECTADO"

    lines = [
        f"🖥️ *FICHA FORENSE DEL AGENTE [{aid}] - {name}*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"• Estado: {status_ico} | IP: `{ip}`",
        f"• SO: `{os_info.get('name', 'Linux')}` ({os_info.get('version', '-')}) | Kernel: `{os_info.get('kernel', '-')}`",
        f"• Hardware: `{hw.get('cpu_name', 'CPU')}` ({hw.get('cpu_cores', 1)} núcleos)",
        f"• Memoria RAM: `[{ram_bar}] {ram_pct:.1f}%` ({hw.get('ram_used_mb', 0)} MB / {hw.get('ram_total_mb', 0)} MB)",
        f"• Postura CIS (SCA): `[{sca_bar}] {sca_score}%` (✅ {sca.get('pass', 0)} / ❌ {sca.get('fail', 0)})",
        f"• Tráfico Red: `{net.get('total_rx_mb', 0.0)} MB RX` / `{net.get('total_tx_mb', 0.0)} MB TX`",
        f"• Procesos: `{procs.get('total_count', 0)}` | Paquetes: `{soft.get('total_packages', 0)}`",
    ]

    # Sitios y destinos del agente
    if sites:
        lines.append("\n🌐 *Sitios y Conexiones Web Activas:*")
        for s in sites[:4]:
            lines.append(f"• *{s['site_name']}* (`{s['remote_ip']}:{s['remote_port']}`) por `{s['process']}`")

    # Alertas recientes
    if alerts:
        lines.append("\n🛡️ *Últimas Detecciones de Seguridad:*")
        for al in alerts[:3]:
            lvl = al.get("level", 0)
            desc = al.get("description", "Evento de seguridad")
            lines.append(f"• `[L{lvl}]` #{al.get('rule_id')}: {desc}")

    lines.append(
        "\n💡 *Subcomandos disponibles:*\n"
        f"`/agente {aid} hardware` · `/agente {aid} red` · `/agente {aid} sca`\n"
        f"`/agente {aid} procesos` · `/agente {aid} paquetes` · `/agente {aid} fim`"
    )

    return "\n".join(lines)


def _get_recent_alerts_summary(limit: int = 5) -> str:
    """Devuelve un resumen de las alertas recientes en español."""
    items = traffic_watcher.get_recent(limit=limit)
    if not items:
        return "ℹ️ *No hay alertas recientes en el buffer del relay.*"

    lines = [
        f"🚨 *ÚLTIMAS {len(items)} ALERTAS DE SEGURIDAD:*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]
    for a in reversed(items):
        lvl = a.get("level", 0)
        rule_id = a.get("rule_id", "0")
        desc = _translate_description_es(a.get("description", "Sin descripción"))
        agent = a.get("agent_name", "host")
        ts = a.get("timestamp", "")
        if "T" in ts:
            ts = ts.split("T")[-1][:8]

        emoji = "🔴" if lvl >= 12 else "🟠" if lvl >= 8 else "🟡"
        raw_log = a.get("full_log", "")
        log_snippet = f"\n  _{translate_full_log_es(raw_log)[:90]}_" if raw_log else ""

        lines.append(f"{emoji} `[L{lvl}]` *#{rule_id}* ({agent}) {ts}\n*{desc}*{log_snippet}")

    return "\n\n".join(lines)


async def _get_kpis_summary() -> str:
    """Devuelve métricas y KPIs de despacho del relay."""
    from ..common.telemetry import telemetry_store
    snap = await telemetry_store.snapshot()

    return (
        "📈 *MÉTRICAS Y KPIS DEL RELAY*",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"• Alertas (últimos 60s): `{snap.get('alerts_last_60s', 0)}`",
        f"• Alertas Totales Despachadas: `{snap.get('total_dispatched', 0)}`",
        f"• Alertas Suprimidas / Deduplicadas: `{snap.get('dedup_suppressed', 0)}`",
        f"• Latencia Promedio: `{snap.get('avg_dispatch_latency_ms', 0)} ms`",
        f"• Clientes SSE en Vivo: `{snap.get('sse_clients', 0)}`",
        "",
        "📡 *Canales Configurados:*",
        f"• WhatsApp: {'🟢 HABILITADO' if getattr(settings, 'whatsapp_enabled', True) else '🔴 DESHABILITADO'}",
        f"• Telegram: {'🟢 HABILITADO' if getattr(settings, 'telegram_enabled', False) else '🔴 DESHABILITADO'}",
        f"• Correo: {'🟢 HABILITADO' if getattr(settings, 'email_alerts_enabled', False) else '⚪ DESACTIVADO'}",
    )


def _get_channels_summary() -> str:
    """Devuelve estado y configuración de los canales de notificación."""
    wa_en = getattr(settings, "whatsapp_enabled", True)
    tg_en = getattr(settings, "telegram_enabled", False)
    em_en = getattr(settings, "email_alerts_enabled", False)

    return (
        "📣 *ESTADO DE CANALES DE NOTIFICACIÓN*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"• *WhatsApp (WAHA):* {'🟢 ACTIVO' if wa_en else '🔴 INACTIVO'}\n"
        f"  Destino: `{settings.admin_phone or 'No configurado'}`\n\n"
        f"• *Telegram:* {'🟢 ACTIVO' if tg_en else '🔴 INACTIVO'}\n"
        f"  Chat ID: `{getattr(settings, 'telegram_chat_id', 'No vinculado')}`\n"
        f"  Nivel mínimo: `L{getattr(settings, 'telegram_min_level', 8)}+`\n\n"
        f"• *Correo Electrónico:* {'🟢 ACTIVO' if em_en else '⚪ INACTIVO'}\n"
        f"  Proveedor: `{settings.email_provider}` | Destino: `{settings.admin_email or 'No configurado'}`"
    )


def _get_rules_summary() -> str:
    """Devuelve el listado de reglas locales personalizadas en Wazuh."""
    return (
        "🛡️ *REGLAS DE SEGURIDAD LOCALES ACTIVAS (local_rules.xml)*\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "• `57100` [L10] Login SSH exitoso\n"
        "• `57101` [L10] Login SSH con clave pública\n"
        "• `57102` [L12] Login SSH como ROOT (CRÍTICO)\n"
        "• `57103` [L10] Cambio de usuario (su) exitoso\n"
        "• `57104` [L8]  Comando sudo ejecutado con éxito\n"
        "• `57105` [L8]  Login local TTY/consola exitoso\n"
        "• `57106` [L3]  Logout / sesión cerrada\n"
        "• `57107-110` [L8] CVEs y Vulnerabilidades activas\n"
        "• `57120` [L12] Ataque de fuerza bruta SSH persistente\n"
        "• `57121` [L12] Ejecución remota sospechosa (curl/wget | sh)\n"
        "• `57122` [L11] Ejecución en directorios temporales (/tmp, /dev/shm)\n"
        "• `57123` [L11] Violación de sudoers (usuario no autorizado)\n"
        "• `57124` [L11] Fallos reiterados de acceso como ROOT por SSH\n"
        "• `57125` [L12] Modificación de archivos críticos (/etc/shadow, passwd)\n"
        "• `57126` [L10] Parada de servicio de seguridad (Wazuh, SSH)\n"
        "• `57127` [L10] Kernel OOM Killer (Memoria RAM crítica agotada)\n"
        "• `57128` [L10] Escaneo de puertos detectado por Firewall\n"
        "• `57129` [L11] Modificación en authorized_keys de SSH\n"
        "• `57130` [L9]  Contenedor Docker caído abruptamente\n"
        "• `57131` [L8]  Intento fallido de autenticación SSH (credenciales erróneas)\n"
        "• `57132` [L9]  Intento de login SSH con usuario inexistente\n"
        "• `57133` [L10] Escaneo/sondeo inseguro en puerto SSH (Probe scan)\n"
        "• `57134` [L10] Ráfaga de desconexiones preauth SSH (Port scan)\n"
        "• `57135` [L12] Escaneo masivo y agresivo detectado por Firewall\n"
        "• `57136` [L9]  Usuario o grupo eliminado del sistema\n"
        "• `57137` [L8]  Modificación de tareas programadas Crontab\n"
        "• `57138` [L13] Intento crítico de Reverse Shell o tubería de red\n"
        "• `57139` [L10] Herramienta de escaneo de red o captura ejecutada\n"
        "• `57140` [L12] Intento de manipulación de logs o parada de defensas\n"
        "• `999001`[L10] Evento de salud de la infraestructura WAHA"
    )


def _get_help_menu() -> str:
    """Menú de comandos de ayuda en español."""
    return (
        f"🛡️ *PANEL DE CONTROL Y MONITOREO WAZUH-WAHA*\n"
        f"Servidor: `{platform.node()}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📋 *Comandos de Monitoreo:*\n"
        f"• `/status` — CPU Load, RAM, Disco, Uptime\n"
        f"• `/servicios` — Estado de Wazuh, WAHA, Relay, Dashboard\n"
        f"• `/red` — Puertos del ecosistema y sockets activos\n"
        f"• `/sitios` — Sitios web y destinos navegados por los equipos\n"
        f"• `/agentes` — Lista de equipos conectados al SOC\n"
        f"• `/agente <id> [módulo]` — Ficha forense (hardware, red, sca, etc.)\n"
        f"• `/alertas [n]` — Últimas alertas de seguridad en español\n"
        f"• `/kpis` — Estadísticas de despacho, deduplicación y latencia\n"
        f"• `/canales` — Estado de WhatsApp, Telegram y Correo\n"
        f"• `/reglas` — Reglas de seguridad activas en Wazuh\n"
        f"• `/ping` — Prueba de disponibilidad y latencia\n\n"
        f"⚙️ *Comandos de Configuración y Reportes:*\n"
        f"• `/config` — Ver configuración activa del sistema\n"
        f"• `/set_nivel <8-15>` — Ajustar severidad mínima de alertas\n"
        f"• `/set_canal <whatsapp|telegram|email> <on|off>` — Activar o silenciar canal\n"
        f"• `/set_phone <numero>` — Actualizar móvil admin WhatsApp\n"
        f"• `/set_email <correo>` — Actualizar email destino de alertas\n"
        f"• `/reporte <id_agente>` — Generar y recibir PDF del agente en el chat\n"
        f"• `/reiniciar <waha|dashboard|relay>` — Reiniciar servicio"
    )


def _get_configuration_summary() -> str:
    from ..config import settings
    w_on = "🟢 ACTIVO" if getattr(settings, "whatsapp_enabled", True) else "🔴 INACTIVO"
    t_on = "🟢 ACTIVO" if getattr(settings, "telegram_enabled", False) else "🔴 INACTIVO"
    e_on = "🟢 ACTIVO" if getattr(settings, "email_alerts_enabled", False) else "🔴 INACTIVO"
    min_lvl = getattr(settings, "telegram_min_level", getattr(settings, "relay_min_level_unknown", 8))
    phone = getattr(settings, "admin_phone", "") or "No configurado"
    email = getattr(settings, "smtp_to", "") or getattr(settings, "admin_email", "") or "No configurado"
    mgr_ip = getattr(settings, "wazuh_server_ip", "") or getattr(settings, "wazuh_manager_host", "") or "127.0.0.1"
    ttl = getattr(settings, "relay_dedup_ttl", 300)

    return (
        f"⚙️ *CONFIGURACIÓN DEL SISTEMA WAZUH-WAHA*\n"
        f"Servidor: `{platform.node()}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔔 *Canales de Notificación:*\n"
        f"• WhatsApp: {w_on} (Admin: `{phone}`)\n"
        f"• Telegram: {t_on} (Chat ID: `{getattr(settings, 'telegram_chat_id', '-')}`)\n"
        f"• Correo SMTP: {e_on} (Destino: `{email}`)\n\n"
        f"🛡️ *Parámetros de Seguridad:*\n"
        f"• Nivel mínimo de alerta: `Nivel {min_lvl}`\n"
        f"• Ventana de deduplicación (TTL): `{ttl} seg`\n"
        f"• Wazuh Manager IP: `{mgr_ip}`\n"
        f"• Puerto Relay: `{getattr(settings, 'relay_port', 8765)}`\n"
        f"• Puerto Dashboard: `8001`\n\n"
        f"💡 *Comandos para Modificar Parámetros:*\n"
        f"• `/set_nivel <8-15>` — Cambiar severidad mínima\n"
        f"• `/set_canal <whatsapp|telegram|email> <on|off>`\n"
        f"• `/set_phone <numero>` — Actualizar móvil WhatsApp\n"
        f"• `/set_email <correo>` — Actualizar email de alertas\n"
        f"• `/reporte <agent_id>` — Generar y recibir PDF del equipo\n"
        f"• `/reiniciar <waha|dashboard|relay>` — Reiniciar servicio"
    )


def _set_alert_min_level(arg: str) -> str:
    try:
        val = int(arg)
        if not (1 <= val <= 15):
            return "⚠️ El nivel debe ser un número entero entre 1 y 15 (recomendado 8 a 12)."
        from ..config import settings, load_overrides, save_overrides
        setattr(settings, "telegram_min_level", val)
        setattr(settings, "relay_min_level_unknown", val)
        ov = load_overrides()
        ov["telegram_min_level"] = val
        ov["relay_min_level_unknown"] = val
        save_overrides(ov)
        _save_to_env({"RELAY_MIN_LEVEL_UNKNOWN": str(val), "TELEGRAM_MIN_LEVEL": str(val)})
        _sync_systemd_env()
        save_telegram_session(min_level=val)
        return f"✅ *Nivel mínimo de alertas actualizado:*\nNuevo umbral: `Nivel {val}`.\nSe notificarán únicamente eventos con severidad >= {val}."
    except ValueError:
        return "⚠️ Uso incorrecto. Ejemplo: `/set_nivel 10`"


def _set_channel_state(channel_arg: str, state_arg: str) -> str:
    ch = channel_arg.lower().strip()
    st = state_arg.lower().strip()
    enable = st in ("on", "1", "true", "activar", "activo", "si", "sí")
    disable = st in ("off", "0", "false", "desactivar", "inactivo", "no")
    if not (enable or disable):
        return "⚠️ Estado no válido. Usa `on` u `off`. Ejemplo: `/set_canal whatsapp on`"

    val = enable
    from ..config import settings, load_overrides, save_overrides
    ov = load_overrides()
    env_up = {}

    if "what" in ch:
        setattr(settings, "whatsapp_enabled", val)
        ov["whatsapp_enabled"] = val
        env_up["WHATSAPP_ENABLED"] = "true" if val else "false"
        nombre = "WhatsApp"
    elif "tele" in ch:
        setattr(settings, "telegram_enabled", val)
        ov["telegram_enabled"] = val
        env_up["TELEGRAM_ENABLED"] = "true" if val else "false"
        save_telegram_session(enabled=val)
        nombre = "Telegram"
    elif "mail" in ch or "corr" in ch:
        setattr(settings, "email_alerts_enabled", val)
        ov["email_alerts_enabled"] = val
        env_up["EMAIL_ALERTS_ENABLED"] = "true" if val else "false"
        nombre = "Correo Electrónico"
    else:
        return "⚠️ Canal no reconocido. Opciones: `whatsapp`, `telegram`, `email`."

    save_overrides(ov)
    _save_to_env(env_up)
    _sync_systemd_env()
    estado_str = "🟢 Activado" if val else "🔴 Desactivado"
    return f"✅ *Canal {nombre} actualizado:*\nEstado: {estado_str}."


def _set_admin_phone(phone_arg: str) -> str:
    clean = "".join(c for c in phone_arg if c.isdigit())
    if len(clean) < 10:
        return "⚠️ Número de teléfono inválido. Ingresa el número con código de país (ej: `5219991234567`)."
    from ..config import settings, load_overrides, save_overrides
    setattr(settings, "admin_phone", clean)
    ov = load_overrides()
    ov["admin_phone"] = clean
    save_overrides(ov)
    _save_to_env({"ADMIN_PHONE": clean})
    _sync_systemd_env()
    return f"✅ *Teléfono WhatsApp del Administrador actualizado:*\nNúmero: `{clean}`."


def _set_admin_email(email_arg: str) -> str:
    em = email_arg.strip()
    if "@" not in em or "." not in em:
        return "⚠️ Dirección de correo inválida. Ejemplo: `/set_email soc@empresa.com`"
    from ..config import settings, load_overrides, save_overrides
    setattr(settings, "admin_email", em)
    setattr(settings, "smtp_to", em)
    ov = load_overrides()
    ov["admin_email"] = em
    ov["smtp_to"] = em
    save_overrides(ov)
    _save_to_env({"ADMIN_EMAIL": em, "SMTP_TO": em})
    _sync_systemd_env()
    return f"✅ *Correo de alertas del Administrador actualizado:*\nEmail: `{em}`."


async def _generate_and_send_agent_report(agent_id: str, chat_id: str | None = None) -> str:
    aid = str(agent_id).strip()
    if not aid:
        return "ℹ️ Especifica el ID del agente. Ejemplo: `/reporte 001` o `/reporte 000`"
    try:
        from ..api.telemetry import _fetch_agent_full_profile
        from ..api.reports import _build_pdf

        profile = await _fetch_agent_full_profile(aid)
        ag_name = profile.get("agent_name", aid)
        pdf_bytes = _build_pdf(profile)
        now_str = time.strftime("%Y%m%d_%H%M%S")
        filename = f"reporte_agente_{aid}_{now_str}.pdf"

        caption = (
            f"📄 *Reporte Forense y Auditoría de Seguridad Wazuh*\n"
            f"• Agente: `{ag_name}` (ID: `{aid}`)\n"
            f"• Sistema: `{profile.get('os', {}).get('name', 'Linux')}`\n"
            f"• Fecha: `{time.strftime('%d/%m/%Y %H:%M:%S')}`\n"
            f"• Tamaño: `{round(len(pdf_bytes)/1024, 1)} KB`\n\n"
            f"_Generado por Wazuh-WAHA SOC Relay_"
        )

        ok = await send_document(
            document_bytes=pdf_bytes,
            filename=filename,
            caption=caption,
            chat_id=chat_id,
        )
        if ok:
            return f"✅ Reporte PDF del agente [{aid}] generado y enviado con éxito a tu chat."
        else:
            return f"⚠️ Se generó el PDF ({round(len(pdf_bytes)/1024, 1)} KB), pero falló el envío por Telegram."
    except Exception as e:
        log.exception("telegram_report_generate_err aid=%s", aid)
        return f"❌ Error generando reporte PDF del agente [{aid}]: {e}"


async def _restart_service(service_arg: str) -> str:
    svc = service_arg.lower().strip()
    import subprocess
    if svc in ("waha", "whatsapp"):
        cmd = "docker restart wazuh-waha"
        label = "Contenedor WAHA (WhatsApp)"
    elif svc in ("dashboard", "panel", "nginx"):
        cmd = "docker restart wazuh-waha-dashboard"
        label = "Contenedor Dashboard Web"
    elif svc in ("relay", "wazuh-waha"):
        cmd = "sudo systemctl restart wazuh-waha.service"
        label = "Servicio Relay (wazuh-waha)"
    elif svc in ("wazuh", "manager"):
        cmd = "sudo systemctl restart wazuh-manager.service"
        label = "Servicio Wazuh Manager"
    else:
        return "⚠️ Servicio no reconocido. Opciones: `waha`, `dashboard`, `relay`, `manager`."

    try:
        subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return f"🔄 Orden de reinicio enviada para *{label}* (`{cmd}`). Revisa en unos segundos con `/servicios`."
    except Exception as e:
        return f"❌ Error ejecutando reinicio: {e}"


# ─────────────────────────────────────────────────────────────
# 4. Procesador Central de Comandos (Telegram + WhatsApp)
# ─────────────────────────────────────────────────────────────

async def process_admin_command(text: str, source: str = "telegram", chat_id: str | None = None) -> str:
    """Ejecuta comandos de administración, configuración y monitoreo desde Telegram o WhatsApp."""
    clean = text.strip()
    if not clean:
        return _get_help_menu()

    parts = clean.split()
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("/start", "/help", "/ayuda", "/comandos"):
        return _get_help_menu()
    elif cmd in ("/status", "/estado"):
        return _get_system_status()
    elif cmd in ("/servicios", "/services"):
        return await _get_services_status()
    elif cmd in ("/red", "/trafico", "/traffic", "/puertos"):
        return await _get_network_traffic_summary()
    elif cmd in ("/sitios", "/sites", "/webs", "/destinos"):
        return await _get_network_sites_summary()
    elif cmd in ("/agentes", "/equipos", "/agents"):
        return await _get_agents_list_summary()
    elif cmd in ("/agente", "/equipo", "/agent"):
        if not arg:
            return "ℹ️ Por favor especifica el ID del agente. Ejemplo: `/agente 000` o `/agente 000 hardware`"
        sub_arg = parts[2].lower() if len(parts) > 2 else ""
        return await _get_agent_detail_summary(arg, subcmd=sub_arg)
    elif cmd in ("/alertas", "/alerts"):
        limit = 5
        if arg.isdigit():
            limit = min(max(int(arg), 1), 15)
        return _get_recent_alerts_summary(limit=limit)
    elif cmd in ("/kpis", "/metricas", "/metrics"):
        res = await _get_kpis_summary()
        return "\n".join(res) if isinstance(res, tuple) else str(res)
    elif cmd in ("/canales", "/channels"):
        return _get_channels_summary()
    elif cmd in ("/reglas", "/rules"):
        return _get_rules_summary()
    elif cmd in ("/config", "/configuracion", "/settings"):
        return _get_configuration_summary()
    elif cmd in ("/set_nivel", "/nivel"):
        if not arg:
            return "ℹ️ Especifica el nuevo nivel. Ejemplo: `/set_nivel 10`"
        return _set_alert_min_level(arg)
    elif cmd in ("/set_canal", "/canal"):
        if not arg or len(parts) < 3:
            return "ℹ️ Uso: `/set_canal <whatsapp|telegram|email> <on|off>`. Ejemplo: `/set_canal whatsapp on`"
        return _set_channel_state(arg, parts[2])
    elif cmd in ("/set_phone", "/phone", "/telefono"):
        if not arg:
            return "ℹ️ Especifica el número con código de país. Ejemplo: `/set_phone 5219991234567`"
        return _set_admin_phone(arg)
    elif cmd in ("/set_email", "/email", "/correo"):
        if not arg:
            return "ℹ️ Especifica el email. Ejemplo: `/set_email soc@empresa.com`"
        return _set_admin_email(arg)
    elif cmd in ("/reporte", "/report", "/pdf"):
        target_aid = arg if arg else "001"
        return await _generate_and_send_agent_report(target_aid, chat_id=chat_id)
    elif cmd in ("/reiniciar", "/restart"):
        if not arg:
            return "ℹ️ Especifica el servicio a reiniciar (`waha`, `dashboard`, `relay`, `manager`). Ejemplo: `/reiniciar waha`"
        return await _restart_service(arg)
    elif cmd in ("/ping",):
        t0 = time.time()
        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        return f"🏓 *Pong!*\nServidor `{platform.node()}` operativo.\nLatencia interna: `{elapsed_ms} ms`\nCPU load: `{load:.2f}`"
    else:
        return f"❓ Comando `{cmd}` no reconocido.\n\nEscribe `/ayuda` para ver la lista de comandos disponibles."


# ─────────────────────────────────────────────────────────────
# 5. Worker de Background para Telegram
# ─────────────────────────────────────────────────────────────

class TelegramBotWorker:
    """Worker en background que procesa comandos del administrador por Telegram."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False
        self._offset = 0

    def start(self) -> None:
        load_telegram_session()
        if not getattr(settings, "telegram_enabled", False) or not getattr(settings, "telegram_bot_token", ""):
            log.info("telegram_bot_disabled (enabled=False o token vacio)")
            return
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        log.info("telegram_bot_worker_started chat_id=%s", getattr(settings, "telegram_chat_id", ""))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        log.info("telegram_bot_worker_stopped")

    async def send_alert(
        self,
        message_text: str,
        level: int = 0,
        rule_id: str = "0",
        agent_name: str = "?",
    ) -> bool:
        return await send_alert(message_text, level=level, rule_id=rule_id, agent_name=agent_name)

    async def send_message(
        self,
        text: str,
        chat_id: str | None = None,
        token: str | None = None,
        parse_mode: str = "Markdown",
    ) -> bool:
        return await send_message(text, chat_id=chat_id, token=token, parse_mode=parse_mode)

    async def _poll_loop(self) -> None:
        try:
            init_updates = await get_updates(offset=0, timeout=1)
            if init_updates:
                self._offset = init_updates[-1].get("update_id", 0) + 1
        except Exception:
            pass

        while self._running:
            try:
                updates = await get_updates(offset=self._offset, timeout=10)
                for u in updates:
                    self._offset = u.get("update_id", 0) + 1
                    await self._handle_update(u)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("telegram_poll_loop_err err=%s", e)
                await asyncio.sleep(4)

    async def _handle_update(self, update: dict) -> None:
        msg = update.get("message")
        if not msg:
            return
        chat = msg.get("chat", {})
        chat_id = str(chat.get("id", ""))
        text = (msg.get("text") or "").strip()
        first_name = chat.get("first_name", "Usuario")

        if not text:
            return

        configured_chat = str(getattr(settings, "telegram_chat_id", "")).strip()

        # Si el chat_id no está configurado aún y envían /start, auto-emparejar y persistir
        if not configured_chat and text.startswith("/start"):
            save_telegram_session(chat_id=chat_id, enabled=True)
            welcome = (
                f"🎉 *¡Bot vinculado exitosamente!*\n\n"
                f"Bienvenido *{first_name}* (`chat_id`: `{chat_id}`).\n"
                f"Tu sesión ha quedado persistida en el servidor `{platform.node()}` y sobrevivirá a cualquier apagón o reinicio.\n\n"
                f"{_get_help_menu()}"
            )
            await send_message(welcome, chat_id=chat_id)
            return

        # Si no coincide con el chat configurado, rechazar
        if configured_chat and chat_id != configured_chat:
            log.warning("telegram_unauthorized_access chat_id=%s user=%s text=%r", chat_id, first_name, text)
            await send_message("⛔ *Acceso denegado.* Este bot es privado para el servidor Wazuh-WAHA.", chat_id=chat_id)
            return

        # Procesar comando y responder
        reply = await process_admin_command(text, source="telegram", chat_id=chat_id)
        if reply:
            await send_message(reply, chat_id=chat_id)


telegram_bot = TelegramBotWorker()
