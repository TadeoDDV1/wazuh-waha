"""Utilidades compartidas para resolver la IP real del cliente.

`X-Forwarded-For` solo se acepta cuando el peer inmediato está en
`TRUSTED_PROXIES`; de lo contrario cualquier cliente podría falsear su IP,
evadir el rate limit y ensuciar la auditoría.

Se centraliza aquí para que el middleware de rate-limit, el login y las
dependencias de autenticación usen exactamente la misma lógica.
"""

from __future__ import annotations

import ipaddress

from fastapi import Request

from ..config import settings


def _trusted_nets() -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for value in settings.trusted_proxies_list:
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return nets


def is_trusted_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _trusted_nets())


def client_ip(request: Request) -> str:
    """IP real del cliente, sin confiar en cabeceras de proxies no autorizados."""
    peer = request.client.host if request.client else "unknown"
    if not is_trusted_ip(peer):
        return peer
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        if not is_trusted_ip(hop):
            return hop
    return hops[0] if hops else peer
