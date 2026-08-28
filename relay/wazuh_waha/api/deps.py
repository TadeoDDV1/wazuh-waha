from fastapi import HTTPException, Request, status

from ..common.logging import log
from ..config import settings


async def verify_api_key(request: Request) -> None:
    key = request.headers.get("X-Api-Key") or request.headers.get("x-api-key")
    log.info(f"API Key check: received='{key}', expected='{settings.relay_api_key}', match={key == settings.relay_api_key}")
    if not key or key != settings.relay_api_key:
        log.warning(
            "auth_fail path=%s ip=%s",
            request.url.path,
            request.client.host if request.client else "?",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized"
        )
