"""Enricher de indicadores de compromiso (IoCs)."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from ..context import EnrichmentContext
from ..models import Ioc
from .base import SyncEnricher

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

_MAX_IOCS = 50


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _defang(value: str, kind: str) -> str:
    if kind == "ip" or kind == "domain":
        return value.replace(".", "[.]")
    if kind == "url":
        return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    return value


def _add(
    items: list[Ioc],
    seen: set[tuple[str, str]],
    kind: str,
    value: str,
    confidence: float,
) -> None:
    value = str(value or "").strip()
    if not value:
        return
    key = (kind, value.lower())
    if key in seen:
        return
    seen.add(key)
    items.append(
        Ioc(
            type=kind,  # type: ignore[arg-type]
            value=value,
            defanged=_defang(value, kind),
            confidence=max(0.0, min(1.0, confidence)),
        )
    )


def _iter_matches(pattern: re.Pattern[str], text: str) -> Iterable[str]:
    for match in pattern.finditer(text or ""):
        yield match.group(0).rstrip(".,;:)]}")


class IocEnricher(SyncEnricher):
    name = "ioc"
    order = 70

    def enrich(self, ctx: EnrichmentContext) -> None:
        n = ctx.event.normalized
        raw_log = str(ctx.raw.get("full_log") or "")
        data = ctx.raw.get("data") or {}
        if not isinstance(data, dict):
            data = {}

        items: list[Ioc] = []
        seen: set[tuple[str, str]] = set()

        for ip in (n.src_ip, n.dst_ip, data.get("srcip"), data.get("dstip")):
            if ip and _valid_ip(str(ip)):
                _add(items, seen, "ip", str(ip), 0.9)

        if n.user and n.user not in ("No especificado", "unknown", "-"):
            _add(items, seen, "user", n.user, 0.8)
        if n.process and n.process.lower() not in ("sistema", "system", "unknown", "no especificado", "-"):
            _add(items, seen, "process", n.process, 0.7)

        for ip in _iter_matches(_IPV4, raw_log):
            if _valid_ip(ip):
                _add(items, seen, "ip", ip, 0.6)

        for url in _iter_matches(_URL, raw_log):
            _add(items, seen, "url", url, 0.7)

        for domain in _iter_matches(_DOMAIN, raw_log):
            if domain.lower().endswith((".local", ".internal")):
                continue
            _add(items, seen, "domain", domain, 0.55)

        for digest in _iter_matches(_HASH, raw_log):
            _add(items, seen, "hash", digest, 0.65)

        ctx.event.enrichment.iocs = items[:_MAX_IOCS]
        if items:
            ctx.add_source("ioc:regex")
