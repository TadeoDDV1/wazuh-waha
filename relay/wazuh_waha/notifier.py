"""
notifier.py - Notificacion de health events (WAHA session down/recovered).

Tres canales:
  1. Wazuh Manager API  (POST https://manager:55000/alerts)
     - Crea una alerta real en el SIEM con rule_id 999001
     - Vuelve a salir por el pipeline normal cuando WAHA vuelva
     - Es el canal principal

  2. SMTP email  (opcional, configurable via SMTP_*)
     - Canal backup, no depende de WAHA ni del pipeline
     - Si SMTP_HOST vacio, se desactiva

  3. Hyvor Relay API  (email API auto-hosteada, open-source)
     - Alternativa a SMTP directo
     - Usa REST API en vez de SMTP
     - Si HYVOR_BASE_URL vacio, se desactiva

El provider de email se elige via EMAIL_PROVIDER=smtp|hyvor_relay.

Todas las funciones son fire-and-forget: no bloquean al caller, no propagan
excepciones (los fallos de notificacion se loguean y nada mas).
"""
import asyncio
import logging
import smtplib
import ssl
import time
from email.message import EmailMessage

import httpx

from .config import settings

log = logging.getLogger("wazuh-waha.notifier")

# Rule id custom para health events (definido en manager/rules/local_rules.xml)
HEALTH_RULE_ID = 999001
HEALTH_AGENT_ID = "000"
HEALTH_AGENT_NAME = "wazuh-waha-relay"


# --- Cache de token JWT para no re-autenticar en cada notify ---
# El manager devuelve tokens con expiracion ~5min (TTL corto por seguridad).
# Cacheamos en memoria de proceso. Cada worker de uvicorn tiene su propio cache.
# Si la pass cambia, hace falta reiniciar el relay para invalidar caches viejos.
_cached_token: str = ""
_cached_token_expires_at: float = 0.0


async def _get_token(client: httpx.AsyncClient) -> str | None:
    """
    Devuelve un token JWT válido del manager Wazuh, cacheado hasta ~30s antes
    de expirar. Devuelve None si falla el login.
    """
    global _cached_token, _cached_token_expires_at
    now = time.time()
    if _cached_token and _cached_token_expires_at > now:
        return _cached_token

    if not settings.wazuh_manager_host or not settings.wazuh_manager_api_pass:
        return None

    base = f"https://{settings.wazuh_manager_host}:{settings.wazuh_manager_api_port}"
    try:
        r = await client.post(
            f"{base}/security/user/authenticate",
            json={
                "username": settings.wazuh_manager_api_user,
                "password": settings.wazuh_manager_api_pass,
            },
        )
    except Exception as e:
        log.warning("notify_wazuh_manager_login_err user=%s err=%s",
                    settings.wazuh_manager_api_user, e)
        return None

    if not r.is_success:
        log.warning("notify_wazuh_manager_login_failed user=%s status=%d body=%r",
                    settings.wazuh_manager_api_user, r.status_code, r.text[:200])
        return None

    data = r.json().get("data", {})
    token = data.get("token", "")
    if not token:
        return None

    # TTL: el manager suele dar 900s, pero guardamos 30s menos para margen.
    ttl = max(60, int(data.get("ttl", 900)) - 30)
    _cached_token = token
    _cached_token_expires_at = now + ttl
    log.debug("notify_wazuh_manager_token_refreshed ttl=%ds user=%s",
              ttl, settings.wazuh_manager_api_user)
    return token


def _build_alert_payload(description: str, level: int, **fields) -> dict:
    """Arma el body del POST al manager Wazuh."""
    return {
        "rule": {
            "id": str(HEALTH_RULE_ID),
            "level": level,
            "description": description,
        },
        "agent": {
            "id": HEALTH_AGENT_ID,
            "name": HEALTH_AGENT_NAME,
        },
        "data": fields,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "location": "wazuh-waha-relay",
        "groups": ["waha_health", "auto_recovery"],
    }


async def notify_wazuh_manager(description: str, level: int = 15, **fields) -> bool:
    """
    Postea una alerta al manager Wazuh via API REST.
    Devuelve True si se envio OK, False si fallo o si no hay config.
    No levanta excepciones.

    Auth flow: el manager quiere JWT Bearer, no Basic Auth.
      1) Cache de token (refresh proactivo via _get_token).
      2) POST /events con Bearer token.
      3) Cualquier 401 dispara invalidacion del cache + re-login una vez.
    """
    if not settings.wazuh_manager_host or not settings.wazuh_manager_api_pass:
        log.debug("notify_wazuh_manager disabled (no host/pass configured)")
        return False

    base = f"https://{settings.wazuh_manager_host}:{settings.wazuh_manager_api_port}"
    payload = _build_alert_payload(description, level, **fields)
    verify = settings.wazuh_manager_api_verify_tls

    try:
        async with httpx.AsyncClient(timeout=5, verify=verify) as client:
            token = await _get_token(client)
            if not token:
                return False
            headers = {"Authorization": f"Bearer {token}"}

            async def _post_once():
                return await client.post(f"{base}/events", json=payload, headers=headers)

            r = await _post_once()
            if r.status_code == 401:
                # Token expirado/rotado: invalidar cache y re-login
                global _cached_token, _cached_token_expires_at
                _cached_token = ""
                _cached_token_expires_at = 0.0
                log.info("notify_wazuh_manager_401_retry user=%s",
                         settings.wazuh_manager_api_user)
                token = await _get_token(client)
                if not token:
                    return False
                headers["Authorization"] = f"Bearer {token}"
                r = await _post_once()

            if r.is_success:
                log.info(
                    "notify_wazuh_manager_ok rule=%s level=%d status=%d desc=%r",
                    HEALTH_RULE_ID, level, r.status_code, description,
                )
                return True
            log.warning(
                "notify_wazuh_manager_failed rule=%s status=%d body=%r",
                HEALTH_RULE_ID, r.status_code, r.text[:300],
            )
            return False
    except Exception as e:
        log.warning("notify_wazuh_manager_error rule=%s err=%s", HEALTH_RULE_ID, e)
        return False


def notify_email(subject: str, body: str) -> bool:
    """
    Envia email via SMTP sincronico (corre en thread executor desde el caller).
    Devuelve True si OK, False si fallo o si SMTP no esta configurado.
    No levanta excepciones.
    """
    if not settings.smtp_host or not settings.smtp_to:
        log.debug("notify_email disabled (smtp_host or smtp_to empty)")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to
    msg.set_content(body)

    try:
        if settings.smtp_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as s:
                s.starttls(context=context)
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_pass)
                s.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as s:
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_pass)
                s.send_message(msg)
        log.info("notify_email_ok to=%s subject=%r", settings.smtp_to, subject)
        return True
    except Exception as e:
        log.warning("notify_email_error to=%s err=%s", settings.smtp_to, e)
        return False


async def notify_email_hyvor(subject: str, body_text: str) -> bool:
    """
    Envia email via Hyvor Relay REST API (self-hosted).
    POST /api/console/sends con API key Bearer token.
    Devuelve True si OK, False si fallo o si no esta configurado.
    No levanta excepciones.
    """
    if not settings.hyvor_base_url or not settings.hyvor_api_key or not settings.hyvor_to:
        log.debug("notify_email_hyvor disabled (base_url/api_key/to empty)")
        return False

    url = f"{settings.hyvor_base_url.rstrip('/')}/api/console/sends"
    headers = {
        "Authorization": f"Bearer {settings.hyvor_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": settings.hyvor_from,
        "to": settings.hyvor_to,
        "subject": subject,
        "body_text": body_text,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json=payload, headers=headers)
        if r.is_success:
            log.info(
                "notify_hyvor_ok to=%s subject=%r status=%d",
                settings.hyvor_to, subject, r.status_code,
            )
            return True
        log.warning(
            "notify_hyvor_failed to=%s status=%d body=%r",
            settings.hyvor_to, r.status_code, r.text[:300],
        )
        return False
    except Exception as e:
        log.warning("notify_hyvor_error to=%s err=%s", settings.hyvor_to, e)
        return False


async def notify_health(description: str, level: int = 15, **fields) -> None:
    """
    Envia el mismo health event por los dos canales (Wazuh API + email).
    Corre ambos en paralelo. No bloquea al caller (fire-and-forget en la practica).
    """
    subject = f"[wazuh-waha] {description}"
    body_lines = [
        f"WAHA Health Event",
        f"Description: {description}",
        f"Rule:        {HEALTH_RULE_ID}",
        f"Level:       {level}",
        f"Time:        {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
    ]
    for k, v in fields.items():
        body_lines.append(f"{k:12s} {v}")
    body = "\n".join(body_lines)

    email_tasks = []
    if settings.email_provider == "hyvor_relay":
        email_tasks.append(notify_email_hyvor(subject, body))
    else:
        email_tasks.append(asyncio.to_thread(notify_email, subject, body))

    await asyncio.gather(
        notify_wazuh_manager(description, level, **fields),
        *email_tasks,
    )