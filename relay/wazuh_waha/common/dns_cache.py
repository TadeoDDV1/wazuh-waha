"""Caché DNS compartida para telemetría de red.

Resuelve PTR (reverse DNS) con timeout acotado y permite inyectar nombres
descubiertos por otras fuentes (p. ej. captura DNS o /etc/hosts remoto).
"""

from __future__ import annotations

import asyncio
import socket
import time

from ..config import settings

_CACHE: dict[str, tuple[str, float]] = {}
_INFLIGHT: dict[str, asyncio.Task] = {}
_LOCK = asyncio.Lock()

_SKIP = {
    "",
    "-",
    "0.0.0.0",
    "::",
    "::0",
    "127.0.0.1",
    "::1",
    "localhost",
}


def _is_private(ip: str) -> bool:
    return (
        ip.startswith("192.168.")
        or ip.startswith("10.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
    )


async def resolve(ip: str) -> str:
    ip = str(ip or "").replace("::ffff:", "").strip()
    if ip in _SKIP:
        return ""

    now = time.time()
    cached = _CACHE.get(ip)
    if cached and cached[1] > now:
        return cached[0]

    # Nombres sintéticos solo para LAN sin PTR; nunca para IPs públicas.
    if _is_private(ip):
        val = f"lan-{ip.replace('.', '-')}.local"
        _CACHE[ip] = (val, now + settings.network_dns_cache_ttl)
        return val

    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0],
            ),
            timeout=1.2,
        )
        val = str(result).strip().lower()
    except Exception:
        val = ""

    _CACHE[ip] = (val, now + settings.network_dns_cache_ttl)
    return val


async def resolve_many(ips: set[str]) -> dict[str, str]:
    if not ips:
        return {}
    results = await asyncio.gather(*(resolve(ip) for ip in ips), return_exceptions=True)
    out: dict[str, str] = {}
    for ip, res in zip(ips, results):
        out[ip] = res if isinstance(res, str) else ""
    return out


def peek(ip: str) -> str:
    """Devuelve el hostname cacheado sin hacer ninguna consulta de red.

    Se usa en enrichers síncronos para no bloquear el pipeline.
    """
    ip = str(ip or "").replace("::ffff:", "").strip()
    if not ip:
        return ""
    cached = _CACHE.get(ip)
    if not cached:
        return ""
    value, expires_at = cached
    if expires_at <= time.time():
        _CACHE.pop(ip, None)
        return ""
    return value


def remember(ip: str, hostname: str) -> None:
    ip = str(ip or "").replace("::ffff:", "").strip()
    hostname = str(hostname or "").strip().lower()
    if ip and hostname:
        _CACHE[ip] = (hostname, time.time() + settings.network_dns_cache_ttl)


def clear() -> None:
    _CACHE.clear()
