"""Enricher de red: servicio, dirección, DNS y clasificación."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..catalogs import get_services
from ..context import EnrichmentContext
from ..models import NetworkInfo
from .base import SyncEnricher


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def _is_private_ip(value: str | None) -> bool | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    return any(addr in net for net in _PRIVATE_NETS if net.version == addr.version)


def _service_for(port: int | None, protocol: str) -> dict[str, Any] | None:
    if not port:
        return None
    services = get_services().get("services") or {}
    return services.get(f"{port}/{protocol.lower()}") or services.get(f"{port}/tcp")


def _direction(src_port: int | None, dst_port: int | None) -> str:
    if not src_port and not dst_port:
        return "unknown"
    src_known = bool(_service_for(src_port, "tcp"))
    dst_known = bool(_service_for(dst_port, "tcp"))
    if src_known and not dst_known:
        return "inbound"
    if dst_known and not src_known:
        return "outbound"
    if dst_known and src_known:
        return "connection"
    if src_port and dst_port:
        return "inbound" if src_port < dst_port else "outbound"
    return "unknown"


def _cached_hostname(ip: str | None) -> str:
    if not ip:
        return ""
    try:
        from ....common.dns_cache import peek

        return peek(ip)
    except Exception:
        return ""


class NetworkEnricher(SyncEnricher):
    name = "network"
    order = 20

    def enrich(self, ctx: EnrichmentContext) -> None:
        n = ctx.event.normalized
        raw = ctx.raw
        data = raw.get("data") or {}
        if not isinstance(data, dict):
            data = {}

        protocol = str(data.get("protocol") or data.get("proto") or "tcp").lower()
        src_ip = n.src_ip or None
        dst_ip = n.dst_ip or None
        src_port = n.src_port
        dst_port = n.dst_port

        direction = _direction(src_port, dst_port)
        service_info = _service_for(dst_port, protocol) if direction == "outbound" else _service_for(src_port, protocol)
        if service_info is None:
            service_info = _service_for(dst_port, protocol) or _service_for(src_port, protocol)

        hostname = (
            str(data.get("hostname") or data.get("domain") or data.get("dst_host") or "").strip()
            or _cached_hostname(src_ip)
            or _cached_hostname(dst_ip)
        )

        ctx.event.enrichment.network = NetworkInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol.upper(),
            service=(service_info or {}).get("name"),
            direction=direction,
            hostname=hostname or None,
            site_category=(service_info or {}).get("label"),
            is_private=_is_private_ip(src_ip) if src_ip else _is_private_ip(dst_ip),
        )
        ctx.add_source("catalog:services")
        if hostname:
            ctx.add_source("dns:cache")
