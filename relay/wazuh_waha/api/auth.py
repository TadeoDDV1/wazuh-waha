"""
BFF de autenticación: la API key maestra se ingresa UNA vez en el login y
el relay emite una cookie de sesión HttpOnly firmada. El browser nunca
almacena ni vuelve a enviar la key.

  POST /api/v1/auth/login     {api_key}  -> Set-Cookie: ww_session=...
  GET  /api/v1/auth/session   -> {authenticated, scope, expires_at}
  POST /api/v1/auth/logout    -> borra la cookie
"""

import hmac
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..common.audit import get_audit_log
from ..common.logging import log
from ..common.request import client_ip
from ..common.session import (
    COOKIE_NAME,
    SCOPE_FULL,
    SCOPE_READ,
    cookie_kwargs,
    issue_session,
    verify_session,
)
from ..config import settings
from .deps import verify_api_key

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    api_key: str = Field(..., min_length=8, max_length=256)


def _client_ip(request: Request) -> str:
    return client_ip(request)


def _auth_state(request: Request) -> dict:
    return getattr(request.state, "auth", {"scope": "-", "sid": "-"})


@router.post("/login")
async def login(body: LoginRequest, request: Request):
    provided = body.api_key.encode("utf-8", "replace")
    audit = get_audit_log()
    ip = _client_ip(request)

    scope: str | None = None
    if hmac.compare_digest(provided, settings.relay_api_key.encode("utf-8")):
        scope = SCOPE_FULL
    elif settings.relay_readonly_api_key and hmac.compare_digest(
        provided, settings.relay_readonly_api_key.encode("utf-8")
    ):
        scope = SCOPE_READ

    if scope is None:
        # Mismo mensaje para key inexistente o de solo lectura malformada:
        # sin enumeración de usuarios (no hay, pero sí de keys).
        log.warning("login_fail ip=%s", ip)
        audit.record(
            method="POST", path="/api/v1/auth/login", status=401, ip=ip,
            detail="bad_api_key",
        )
        return JSONResponse(status_code=401, content={"error": "invalid api key"})

    token, exp = issue_session(scope)
    ttl = max(1, settings.session_ttl_hours) * 3600
    log.info("login_ok ip=%s scope=%s exp=%s", ip, scope, exp)
    audit.record(
        method="POST", path="/api/v1/auth/login", status=200, ip=ip,
        scope=scope, detail="login",
    )
    resp = JSONResponse(
        content={
            "ok": True,
            "scope": scope,
            "expires_at": exp,
            "max_age": ttl,
        }
    )
    resp.set_cookie(**cookie_kwargs(ttl), value=token)
    return resp


@router.get("/session")
async def session_info(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    payload = verify_session(token)
    if payload is None:
        return JSONResponse(
            status_code=401, content={"authenticated": False, "reason": "no session"}
        )
    return {
        "authenticated": True,
        "scope": payload["scope"],
        "expires_at": payload["exp"],
        "sid": payload["sid"],
    }


@router.post("/logout")
async def logout(request: Request, _: None = Depends(verify_api_key)):
    st = _auth_state(request)
    audit = get_audit_log()
    audit.record(
        method="POST", path="/api/v1/auth/logout", status=200,
        ip=_client_ip(request), scope=st.get("scope", "-"),
        sid=st.get("sid", "-"), detail="logout",
    )
    resp = JSONResponse(content={"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp
