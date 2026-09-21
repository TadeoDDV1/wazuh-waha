from fastapi import HTTPException, Request, status

from ..common.logging import log
from ..config import settings


async def verify_api_key(request: Request) -> None:
    # Header (REST normal) o query param (SSE — EventSource no permite headers custom)
    key = (
        request.headers.get("X-Api-Key")
        or request.headers.get("x-api-key")
        or request.query_params.get("api_key")
    )
    if not key or key != settings.relay_api_key:
        log.warning(
            "auth_fail path=%s ip=%s",
            request.url.path,
            request.client.host if request.client else "?",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized"
        )
