"""Cliente centralizado para la API REST del Wazuh Manager.

Evita duplicar autenticación, timeouts y manejo de errores en dashboard.py,
telemetry.py, agent_analyzer.py y notifier.py. El token se cachea por proceso
y se refresca automáticamente ante un 401.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from ..common.logging import log
from ..config import settings


class WazuhAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class WazuhAPI:
    def __init__(self) -> None:
        self._token: str = ""
        self._token_exp: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def host(self) -> str:
        return settings.wazuh_manager_host or settings.wazuh_server_ip

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{settings.wazuh_manager_api_port}"

    @property
    def configured(self) -> bool:
        return bool(
            self.host
            and settings.wazuh_manager_api_user
            and settings.wazuh_manager_api_pass
        )

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        r = await client.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(settings.wazuh_manager_api_user, settings.wazuh_manager_api_pass),
        )
        if not r.is_success:
            raise WazuhAPIError(
                "No se pudo autenticar con la API de Wazuh",
                status_code=r.status_code,
                body=r.text[:300],
            )
        data = r.json().get("data", {})
        token = data.get("token", "")
        if not token:
            raise WazuhAPIError("La API de Wazuh no devolvió un token")
        ttl = max(60, int(data.get("ttl", 900)) - 30)
        self._token = token
        self._token_exp = time.time() + ttl
        return token

    async def token(self, client: httpx.AsyncClient) -> str:
        if not self.configured:
            raise WazuhAPIError("API de Wazuh no configurada (host/usuario/password)")
        if self._token and self._token_exp > time.time():
            return self._token
        async with self._lock:
            if self._token and self._token_exp > time.time():
                return self._token
            return await self._authenticate(client)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify: bool | None = None,
    ) -> httpx.Response:
        if not self.configured:
            raise WazuhAPIError("API de Wazuh no configurada (host/usuario/password)")

        verify_tls = settings.wazuh_manager_api_verify_tls if verify is None else verify
        url = path if path.startswith("http") else f"{self.base_url}{path}"

        async with httpx.AsyncClient(timeout=timeout, verify=verify_tls) as client:
            token = await self.token(client)
            req_headers = {"Authorization": f"Bearer {token}"}
            if headers:
                req_headers.update(headers)

            r = await client.request(
                method,
                url,
                params=params,
                json=json_body,
                content=content,
                headers=req_headers,
            )
            if r.status_code == 401:
                # Token revocado/expirado: refrescar una vez y reintentar.
                self._token = ""
                self._token_exp = 0.0
                token = await self.token(client)
                req_headers["Authorization"] = f"Bearer {token}"
                r = await client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    content=content,
                    headers=req_headers,
                )
            return r

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kwargs)

    async def json_or_error(
        self, method: str, path: str, **kwargs: Any
    ) -> dict[str, Any]:
        r = await self.request(method, path, **kwargs)
        if not r.is_success:
            raise WazuhAPIError(
                f"Wazuh API {method} {path} falló",
                status_code=r.status_code,
                body=r.text[:400],
            )
        try:
            return r.json()
        except Exception as exc:
            raise WazuhAPIError(f"Respuesta no JSON de Wazuh: {exc}") from exc

    async def affected_items(self, path: str, **kwargs: Any) -> list[dict[str, Any]]:
        data = await self.json_or_error("GET", path, **kwargs)
        return data.get("data", {}).get("affected_items", []) or []


wazuh_api = WazuhAPI()
