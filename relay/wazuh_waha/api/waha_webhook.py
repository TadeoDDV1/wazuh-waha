"""
waha_webhook.py — Receptor de Webhooks de WAHA para monitoreo por comandos desde WhatsApp.

Permite al administrador enviar comandos (/status, /red, /servicios, /agentes, /alertas, etc.)
por WhatsApp y recibir las respuestas y diagnósticos del servidor directamente en su chat.

Seguridad: este endpoint ejecuta comandos administrativos, por lo que exige
un token compartido (X-Api-Key, Authorization: Bearer o ?token=) y que el
remitente coincida EXACTAMENTE con ADMIN_PHONE. Sin token válido responde 401.
"""

import hmac
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import settings
from ..infrastructure.waha_client import send_text
from ..infrastructure.telegram_bot import process_admin_command

log = logging.getLogger("wazuh-waha.waha_webhook")

router = APIRouter(tags=["waha_webhook"])

_INSECURE_TOKENS = {"", "changeme", "cambiar", "cambiar_relay_api_key"}


def _expected_token() -> str:
    return (settings.waha_webhook_token or settings.waha_api_key or "").strip()


def _provided_token(request: Request) -> str:
    token = request.headers.get("x-api-key", "") or ""
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        token = request.query_params.get("token", "")
    return token.strip()


def _authorized(request: Request) -> bool:
    expected = _expected_token()
    # Fail-closed: una clave de fábrica no protege nada.
    if expected.lower() in _INSECURE_TOKENS:
        return False
    provided = _provided_token(request)
    return bool(provided) and hmac.compare_digest(provided, expected)


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


@router.post("/api/v1/waha/webhook")
async def waha_inbound_webhook(request: Request) -> JSONResponse:
    """Recibe webhooks de WAHA con mensajes entrantes de WhatsApp y ejecuta comandos si vienen del admin."""
    if not _authorized(request):
        log.warning("waha_webhook_unauthorized_token ip=%s", request.client.host if request.client else "?")
        return JSONResponse(content={"ok": False, "error": "Unauthorized"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"ok": False, "error": "Invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse(content={"ok": False, "error": "Invalid payload"}, status_code=400)

    payload: dict[str, Any] = body.get("payload") or body.get("data") or body
    if not isinstance(payload, dict):
        return JSONResponse(content={"ok": False, "error": "Invalid payload"}, status_code=400)

    # Ignorar mensajes propios enviados por el bot/relay
    if payload.get("fromMe"):
        return JSONResponse(content={"ok": True, "skipped": "fromMe"})

    sender = str(payload.get("from") or payload.get("author") or "")
    text = str(payload.get("body") or "").strip()

    if not text or not text.startswith("/"):
        return JSONResponse(content={"ok": True, "skipped": "not_command"})

    # El remitente debe coincidir COMPLETO con el número del administrador.
    # Un endswith() permitía a cualquier número que fuese sufijo del admin.
    clean_sender = _digits(sender)
    clean_admin = _digits(settings.admin_phone)

    if not clean_admin or not clean_sender:
        return JSONResponse(content={"ok": True, "skipped": "no_admin_configured"})

    if clean_sender != clean_admin:
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
        return JSONResponse(content={"ok": False, "error": "no se pudo enviar la respuesta"}, status_code=500)
