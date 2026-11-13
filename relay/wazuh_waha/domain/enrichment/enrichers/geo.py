"""Enricher geográfico opcional.

Si existe una base GeoLite2 y el paquete ``maxminddb`` está instalado, se usa.
Si no, se intenta un catálogo JSON local (``catalog/geoip.json``). Si no hay
ninguna fuente, el enricher no hace nada: el evento sigue siendo válido.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

from ....config import settings
from ..catalogs import _catalog_path
from ..context import EnrichmentContext
from .base import SyncEnricher

log = logging.getLogger("wazuh-waha.enrichment.geo")

_reader: Any = None
_asn_reader: Any = None
_reader_checked = False
_json_networks: list[tuple[Any, dict[str, Any]]] | None = None


def _load_readers() -> None:
    global _reader, _asn_reader, _reader_checked
    if _reader_checked:
        return
    _reader_checked = True

    raw_path = (settings.enrich_geoip_db or "").strip()
    if not raw_path:
        return
    db_path = Path(raw_path)
    if not db_path.is_file():
        return
    try:
        import maxminddb  # type: ignore

        _reader = maxminddb.open_database(str(db_path))
        asn_path = db_path.with_name("GeoLite2-ASN.mmdb")
        if asn_path.exists():
            _asn_reader = maxminddb.open_database(str(asn_path))
        log.info("geoip_loaded path=%s asn=%s", db_path, bool(_asn_reader))
    except Exception as exc:
        log.warning("geoip_unavailable path=%s err=%s", db_path, exc)


def _load_json_networks() -> list[tuple[Any, dict[str, Any]]]:
    global _json_networks
    if _json_networks is not None:
        return _json_networks
    _json_networks = []
    path = _catalog_path("geoip.json")
    if not path.exists():
        return _json_networks
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for cidr, info in (data.get("networks") or {}).items():
            try:
                _json_networks.append((ipaddress.ip_network(cidr, strict=False), info))
            except ValueError:
                continue
    except Exception as exc:
        log.warning("geoip_json_error path=%s err=%s", path, exc)
    return _json_networks


def _lookup_json(ip: str) -> dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    for network, info in _load_json_networks():
        if addr in network:
            return info
    return {}


def _lookup_mmdb(ip: str) -> dict[str, Any]:
    _load_readers()
    if _reader is None:
        return {}
    try:
        record = _reader.get(ip) or {}
    except Exception:
        return {}

    country = ((record.get("country") or {}).get("names") or {}).get("es") or \
              ((record.get("country") or {}).get("names") or {}).get("en") or \
              (record.get("country") or {}).get("iso_code")
    city = ((record.get("city") or {}).get("names") or {}).get("es") or \
           ((record.get("city") or {}).get("names") or {}).get("en")

    asn = ""
    if _asn_reader is not None:
        try:
            asn_record = _asn_reader.get(ip) or {}
            org = asn_record.get("autonomous_system_organization")
            number = asn_record.get("autonomous_system_number")
            if org and number:
                asn = f"AS{number} {org}"
            elif org:
                asn = str(org)
            elif number:
                asn = f"AS{number}"
        except Exception:
            pass

    return {"country": country, "city": city, "asn": asn}


class GeoEnricher(SyncEnricher):
    name = "geo"
    order = 30

    def enrich(self, ctx: EnrichmentContext) -> None:
        network = ctx.event.enrichment.network
        if network is None:
            return
        ip = network.src_ip or network.dst_ip
        if not ip or network.is_private:
            return

        info = _lookup_mmdb(ip) or _lookup_json(ip)
        if not info:
            return

        network.country = info.get("country") or network.country
        network.city = info.get("city") or network.city
        network.asn = info.get("asn") or network.asn
        ctx.add_source("geoip:local")
