import hmac

from fastapi import HTTPException, Request, status

from ..common.logging import log
from ..common.session import SCOPE_FULL, verify_session
from ..config import settings


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _auth_failed(request: Request) -> None:
    log.warning("auth_fail path=%s ip=%s", request.url.path, _client_ip(request))
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized"
    )


async def verify_api_key(request: Request) -> None:
    """Autentica y fija request.state.auth = {"scope", "sid"}.

    Acepta en orden:
      1. Cookie de sesión BFF (ww_session) — el browser normal del dashboard.
         EventSource manda cookies en mismo origen, así que SSE no necesita
         ?api_key= (ya no se acepta: quedaba en logs/historial).
      2. Header X-Api-Key — integración Wazuh, admin.sh, conectar.sh.
    """
    # 1) Cookie de sesión
    token = request.cookies.get("ww_session")
    payload = verify_session(token) if token else None
    if payload is not None:
        request.state.auth = {"scope": payload["scope"], "sid": payload["sid"]}
        return

    # 2) Header (REST / scripts). compare_digest en bytes: evita timing
    #    y TypeError (500) con valores no-ASCII.
    key = request.headers.get("x-api-key")
    if key and hmac.compare_digest(
        key.encode("utf-8", "replace"),
        settings.relay_api_key.encode("utf-8"),
    ):
        request.state.auth = {"scope": SCOPE_FULL, "sid": "apikey"}
        return

    _auth_failed(request)


async def verify_write(request: Request) -> None:
    """Como verify_api_key, pero exige scope completo (no sirve una sesión
    de solo lectura para mutar config/agents/módulos/telemetría)."""
    await verify_api_key(request)
    if request.state.auth.get("scope") != SCOPE_FULL:
        log.warning(
            "write_denied path=%s ip=%s scope=%s",
            request.url.path,
            _client_ip(request),
            request.state.auth.get("scope"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read-only session"
        )
