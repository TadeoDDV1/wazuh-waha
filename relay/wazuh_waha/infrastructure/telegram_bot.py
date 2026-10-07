"""
telegram_bot.py — Cliente y bot interactivo de Telegram para Wazuh-WAHA.

Funcionalidades:
1. Enviar alertas de seguridad y eventos de salud (WAHA / Agente / Relay) a Telegram.
2. Bot interactivo para que el administrador monitoree el servidor por chat:
   - /status   -> CPU, RAM, Disco, Uptime y métricas
   - /servicios-> Estado de Wazuh Manager, Agent, WAHA, Dashboard y Relay
   - /alertas  -> Últimas 5 alertas de seguridad procesadas
   - /ping     -> Verificación de latencia y disponibilidad
   - /start    -> Menú de bienvenida / Emparejamiento de sesión
3. Flujo de inicio de sesión / emparejamiento automático por chat_id.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import time
from typing import Any

import httpx

from ..config import ENV_FILE, settings
from ..common.traffic_stream import traffic_watcher

log = logging.getLogger("wazuh-waha.telegram")

TELEGRAM_API_BASE = "https://api.telegram.org/bot"


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

    # Telegram limita mensajes a 4096 caracteres
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

            # Si falló por formato Markdown, reintentar sin parse_mode
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
    """
    Empareja el bot con el usuario esperando que envíe /start o cualquier mensaje.
    Retorna el chat_id detectado y envía confirmación.
    """
    tk = token or settings.telegram_bot_token
    bot_info = await get_bot_info(tk)
    if not bot_info.get("ok"):
        return {"ok": False, "error": bot_info.get("error", "Token inválido")}

    bot_username = bot_info.get("username", "")

    # Obtener updates iniciales para descartar viejos y encontrar el último offset
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

                # Enviar confirmación de bienvenida
                welcome_txt = (
                    f"✅ *¡Conexión establecida con éxito!*\n\n"
                    f"Hola *{first_name}*, tu cuenta ha sido vinculada al servidor *{platform.node()}*.\n"
                    f"A partir de ahora recibirás alertas de seguridad aquí y puedes usar `/status`, `/servicios` y `/alertas` para monitorear."
                )
                await send_message(welcome_txt, chat_id=chat_id, token=tk)

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


def _get_system_status() -> str:
    """Recolecta métricas del host del servidor."""
    # CPU Load
    try:
        load1, load5, load15 = os.getloadavg()
        load_str = f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
    except Exception:
        load_str = "N/D"

    # Uptime
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

    # RAM
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

    # Disco
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
        f"🖥️ *Host:* `{platform.node()}`\n"
        f"⏱️ *Uptime:* {uptime_str}\n"
        f"⚡ *CPU Load:* {load_str}\n"
        f"🧠 *Memoria:* {ram_str}\n"
        f"💾 *Disco (/):* {disk_str}\n"
        f"⏰ *Hora:* {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )


async def _get_services_status() -> str:
    """Verifica el estado de los servicios clave del ecosistema."""
    lines = ["🛠️ *ESTADO DE SERVICIOS*"]

    # 1. Relay wazuh-waha
    lines.append(f"• *Relay HTTP (puerto {settings.relay_port}):* 🟢 ACTIVO")

    # 2. WAHA Docker
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

    # 3. Manager Wazuh API
    mgr_host = settings.wazuh_manager_host or settings.wazuh_server_ip
    mgr_ok = False
    try:
        async with httpx.AsyncClient(timeout=3, verify=False) as client:
            r = await client.get(f"https://{mgr_host}:{settings.wazuh_manager_api_port}")
            mgr_ok = r.status_code in (200, 401)
    except Exception:
        mgr_ok = False
    lines.append(f"• *Wazuh Manager ({mgr_host}):* {'🟢 RESPONDE' if mgr_ok else '🔴 NO RESPONDE'}")

    # 4. Agente local (si existe /var/ossec)
    agent_installed = os.path.isdir("/var/ossec")
    lines.append(f"• *Wazuh Agent Local:* {'🟢 INSTALADO' if agent_installed else '⚪ NO INSTALADO'}")

    return "\n".join(lines)


def _get_recent_alerts_summary() -> str:
    """Devuelve un resumen de las alertas recientes."""
    items = traffic_watcher.get_recent(limit=5)
    if not items:
        return "ℹ️ *No hay alertas recientes en el buffer del relay.*"

    lines = ["🚨 *ÚLTIMAS ALERTAS DE SEGURIDAD:*"]
    for a in reversed(items):
        lvl = a.get("level", 0)
        rule_id = a.get("rule_id", "0")
        desc = a.get("description", "Sin descripción")
        agent = a.get("agent_name", "host")
        ts = a.get("timestamp", "")
        if "T" in ts:
            ts = ts.split("T")[-1][:8]

        emoji = "🔴" if lvl >= 12 else "🟠" if lvl >= 8 else "🟡"
        lines.append(f"{emoji} `[L{lvl}]` *#{rule_id}* ({agent}) {ts}\n_{desc}_")

    return "\n\n".join(lines)


async def send_alert(
    message_text: str,
    level: int = 0,
    rule_id: str = "0",
    agent_name: str = "?",
) -> bool:
    """Envía alerta de seguridad a Telegram si el canal está activo y supera el nivel mínimo."""
    if not settings.telegram_enabled:
        return False
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        return False
    if level < settings.telegram_min_level:
        return False

    prefix = "🚨 *ALERTA WAZUH*" if level >= 10 else "⚠️ *AVISO DE SEGURIDAD*"
    formatted = f"{prefix}\n\n{message_text}"
    return await send_message(formatted)


async def send_health_notice(description: str, level: int = 15, **fields) -> bool:
    """Envía un evento de salud de la infraestructura a Telegram."""
    if not settings.telegram_enabled or not settings.telegram_bot_token or not settings.telegram_chat_id:
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


class TelegramBotWorker:
    """Worker en background que procesa comandos del administrador por Telegram."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False
        self._offset = 0

    def start(self) -> None:
        if not settings.telegram_enabled or not settings.telegram_bot_token:
            log.info("telegram_bot_disabled (enabled=False o token vacio)")
            return
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        log.info("telegram_bot_worker_started")

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

    async def _poll_loop(self) -> None:
        # Obtener update_id más reciente al arrancar para no procesar mensajes antiguos
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
                await asyncio.sleep(5)

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

        configured_chat = str(settings.telegram_chat_id).strip()

        # Si el chat_id no está configurado aún y envían /start, auto-emparejar
        if not configured_chat and text.startswith("/start"):
            settings.telegram_chat_id = chat_id
            # Guardar en .env de forma segura
            _save_chat_id_to_env(chat_id)
            welcome = (
                f"🎉 *¡Bot vinculado exitosamente!*\n\n"
                f"Bienvenido *{first_name}* (`chat_id`: `{chat_id}`).\n"
                f"Tu usuario ha sido guardado como el administrador del servidor.\n\n"
                f"Comandos disponibles:\n"
                f"• `/status` - Estado del servidor (CPU/RAM/Disco)\n"
                f"• `/servicios` - Estado de Wazuh, WAHA y Relay\n"
                f"• `/alertas` - Últimas alertas registradas\n"
                f"• `/ping` - Prueba de respuesta"
            )
            await send_message(welcome, chat_id=chat_id)
            return

        # Si no coincide con el chat configurado, rechazar
        if configured_chat and chat_id != configured_chat:
            log.warning("telegram_unauthorized_access chat_id=%s user=%s text=%r", chat_id, first_name, text)
            await send_message("⛔ *Acceso denegado.* Este bot es privado para el servidor Wazuh-WAHA.", chat_id=chat_id)
            return

        # Procesar comandos del admin
        cmd = text.split()[0].lower()
        if cmd in ("/start", "/help", "/ayuda"):
            reply = (
                f"🛡️ *Panel de Control Wazuh-WAHA*\n"
                f"Servidor: `{platform.node()}`\n\n"
                f"*Comandos de Monitoreo:*\n"
                f"• `/status` o `/estado` : Muestra CPU, RAM, Disco y Uptime\n"
                f"• `/servicios`           : Estado de componentes del stack\n"
                f"• `/alertas`             : Últimas 5 alertas de seguridad\n"
                f"• `/ping`                : Prueba de latencia y disponibilidad\n\n"
                f"_Las alertas de seguridad de nivel >= {settings.telegram_min_level} llegarán automáticamente aquí._"
            )
            await send_message(reply, chat_id=chat_id)
        elif cmd in ("/status", "/estado"):
            status_txt = _get_system_status()
            await send_message(status_txt, chat_id=chat_id)
        elif cmd in ("/servicios", "/services"):
            services_txt = await _get_services_status()
            await send_message(services_txt, chat_id=chat_id)
        elif cmd in ("/alertas", "/alerts"):
            alerts_txt = _get_recent_alerts_summary()
            await send_message(alerts_txt, chat_id=chat_id)
        elif cmd in ("/ping",):
            await send_message("🏓 *Pong!* El servidor y el relay están operativos.", chat_id=chat_id)


def _save_chat_id_to_env(chat_id: str) -> None:
    """Persiste TELEGRAM_CHAT_ID al archivo .env."""
    try:
        if not ENV_FILE.exists():
            return
        lines = ENV_FILE.read_text().splitlines()
        found = False
        new_lines = []
        for l in lines:
            if l.startswith("TELEGRAM_CHAT_ID="):
                new_lines.append(f"TELEGRAM_CHAT_ID={chat_id}")
                found = True
            else:
                new_lines.append(l)
        if not found:
            new_lines.append(f"TELEGRAM_CHAT_ID={chat_id}")
        ENV_FILE.write_text("\n".join(new_lines) + "\n")
        log.info("telegram_chat_id_saved_to_env chat_id=%s", chat_id)
    except Exception as e:
        log.warning("telegram_save_env_err err=%s", e)


telegram_bot = TelegramBotWorker()
