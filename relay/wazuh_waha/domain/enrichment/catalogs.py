"""Carga de catálogos de enriquecimiento.

Los catálogos incluidos son JSON para no añadir dependencias obligatorias.
El archivo de activos del usuario puede ser JSON o YAML (si PyYAML está
instalado); si no lo está, se usa JSON.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

from ...config import settings

log = logging.getLogger("wazuh-waha.enrichment.catalogs")

_BUNDLED_DIR = Path(__file__).resolve().parent / "catalog"


def _catalog_path(name: str) -> Path:
    override = (settings.enrich_catalog_dir or "").strip()
    if override:
        candidate = Path(override) / name
        if candidate.exists():
            return candidate
    return _BUNDLED_DIR / name


def _read_structured(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("catalog_read_error path=%s err=%s", path, exc)
        return {}

    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            log.warning("catalog_yaml_error path=%s err=%s (se intenta JSON)", path, exc)

    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError as exc:
        log.warning("catalog_json_error path=%s err=%s", path, exc)
        return {}


@lru_cache(maxsize=1)
def get_assets() -> dict[str, Any]:
    base = _read_structured(_catalog_path("assets.json"))
    user_file = (settings.enrich_assets_file or "").strip()
    if user_file:
        user = _read_structured(Path(user_file))
        if user:
            merged = dict(base)
            merged["defaults"] = {**(base.get("defaults") or {}), **(user.get("defaults") or {})}
            merged["assets"] = {**(base.get("assets") or {}), **(user.get("assets") or {})}
            merged["version"] = user.get("version") or base.get("version")
            return merged
    return base


@lru_cache(maxsize=1)
def get_services() -> dict[str, Any]:
    return _read_structured(_catalog_path("services.json"))


@lru_cache(maxsize=1)
def get_glossary() -> dict[str, Any]:
    return _read_structured(_catalog_path("glossary.json"))


@lru_cache(maxsize=1)
def get_rules() -> dict[str, Any]:
    return _read_structured(_catalog_path("rules_es.json"))


@lru_cache(maxsize=1)
def get_mitre() -> dict[str, Any]:
    return _read_structured(_catalog_path("mitre.json"))


def get_catalog_version() -> str:
    for data in (get_rules(), get_assets(), get_services(), get_mitre()):
        version = data.get("version") if isinstance(data, dict) else None
        if version:
            return str(version)
    return "unknown"


def clear_catalog_cache() -> None:
    get_assets.cache_clear()
    get_services.cache_clear()
    get_glossary.cache_clear()
    get_rules.cache_clear()
    get_mitre.cache_clear()
