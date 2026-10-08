"""
waha_webhook.py — Receptor de Webhooks de WAHA para monitoreo por comandos desde WhatsApp.

Permite al administrador enviar comandos (/status, /red, /servicios, /agentes, /alertas, etc.)
por WhatsApp y recibir las respuestas y diagnósticos del servidor directamente en su chat.
"""

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import settings
from ..infrastructure.waha_client import send_text
from ..infrastructure.telegram_bot import process_admin_command

log = logging.getLogger("wazuh-waha.waha_webhook")

router = APIRouter(tags=["waha_webhook"])


@router.post("/api/v1/waha/webhook")
async def waha_inbound_webhook(request: Request) -> JSONResponse:
    """Recibe webhooks de WAHA con mensajes entrantes de WhatsApp y ejecuta comandos si vienen del admin."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"ok": False, "error": "Invalid JSON"}, status_code=400)

    event = body.get("event", "")
    payload: dict[str, Any] = body.get("payload") or body.get("data") or body

    # Ignorar mensajes propios enviados por el bot/relay
    if payload.get("fromMe"):
        return JSONResponse(content={"ok": True, "skipped": "fromMe"})

    sender = str(payload.get("from") or payload.get("author") or "")
    text = str(payload.get("body") or "").strip()

    if not text or not text.startswith("/"):
        return JSONResponse(content={"ok": True, "skipped": "not_command"})

    # Verificar que el remitente coincida con el número de teléfono del administrador
    clean_sender = "".join(c for c in sender if c.isdigit())
    clean_admin = "".join(c for c in settings.admin_phone if c.isdigit())

    if not clean_admin or not clean_sender:
        return JSONResponse(content={"ok": True, "skipped": "no_admin_configured"})

    is_admin = clean_sender.endswith(clean_admin) or clean_admin.endswith(clean_sender)
    if not is_admin:
        log.warning("waha_webhook_unauthorized_sender sender=%s text=%r", sender, text)
        return JSONResponse(content={"ok": False, "error": "Unauthorized"}, status_code=403)

    log.info("waha_admin_command_received sender=%s command=%s", sender, text)

    # Ejecutar el comando central
    reply = await process_admin_command(text, source="whatsapp")

    # Enviar respuesta de vuelta al administrador por WhatsApp
    try:
        await send_text(reply)
        return JSONResponse(content={"ok": True, "executed": text})
    except Exception as e:
        log.error("waha_command_reply_error command=%s err=%s", text, e)
        return JSONResponse(content={"ok": False, "error": str(e)}, status_code=500)
