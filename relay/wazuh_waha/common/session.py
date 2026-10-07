"""
Sesiones firmadas para el BFF de autenticación.

La API key maestra NUNCA se sirve al browser: el usuario la ingresa una vez
en el login y el relay emite una cookie firmada (HttpOnly) que usan REST y
SSE (mismo origen vía nginx, EventSource manda cookies sin header extra).

Formato de la cookie:  <b64url(payload)>.<b64url(hmac-sha256)>
payload = {"exp": unix_ts, "scope": "full"|"read", "sid": hex}

Secreto de firma derivado de RELAY_API_KEY (estado sin servidor): válido en
todos los workers y sobrevive restarts. No reduce la seguridad: quien tiene
la key ya puede iniciar sesión.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from ..config import settings

COOKIE_NAME = "ww_session"
SCOPE_FULL = "full"
SCOPE_READ = "read"
_VALID_SCOPES = (SCOPE_FULL, SCOPE_READ)


def _signing_key() -> bytes:
    return hashlib.sha256(
        b"wazuh-waha-session-v1:" + settings.relay_api_key.encode("utf-8")
    ).digest()


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_session(scope: str, ttl_hours: int | None = None) -> tuple[str, int]:
    """Devuelve (token, exp_unix)."""
    if scope not in _VALID_SCOPES:
        raise ValueError(f"scope inválido: {scope}")
    ttl = ttl_hours if ttl_hours is not None else settings.session_ttl_hours
    exp = int(time.time()) + max(1, ttl) * 3600
    payload = {"exp": exp, "scope": scope, "sid": secrets.token_hex(16)}
    raw = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64e(hmac.new(_signing_key(), raw.encode("ascii"), hashlib.sha256).digest())
    return f"{raw}.{sig}", exp


def verify_session(token: str | None) -> dict | None:
    """Valida firma y expiración. Devuelve el payload o None."""
    if not token or "." not in token:
        return None
    raw, sig = token.split(".", 1)
    if not raw or not sig:
        return None
    expected = _b64e(
        hmac.new(_signing_key(), raw.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64d(raw))
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if not isinstance(payload.get("exp"), int) or payload["exp"] < time.time():
        return None
    if payload.get("scope") not in _VALID_SCOPES:
        return None
    if not isinstance(payload.get("sid"), str) or len(payload["sid"]) > 64:
        return None
    return payload


def cookie_kwargs(max_age: int) -> dict:
    """Kwargs para Response.set_cookie (HttpOnly: JS no puede leerla)."""
    return {
        "key": COOKIE_NAME,
        "max_age": max_age,
        "path": "/",
        "httponly": True,
        # False por defecto para red local http://; configurable a True para TLS/HTTPS
        "samesite": "strict",
        "secure": settings.session_cookie_secure,
    }
