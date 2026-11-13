"""Construcción del evento canónico a partir de la normalización existente."""

from __future__ import annotations

from typing import Any

from .models import CanonicalEvent, Enrichment, NormalizedEvent, TranslationInfo


def _to_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _source(value: Any) -> str:
    source = str(value or "wazuh").lower()
    if source in ("simulate", "manual", "test"):
        return "manual"
    return "wazuh"


def build_canonical_event(raw: dict[str, Any], normalized: dict[str, Any]) -> CanonicalEvent:
    description = str(normalized.get("description") or "Evento de seguridad")
    event = CanonicalEvent(
        id=str(normalized.get("id") or ""),
        timestamp=str(normalized.get("timestamp") or ""),
        source=_source(normalized.get("source")),  # type: ignore[arg-type]
        raw={},
        normalized=NormalizedEvent(
            rule_id=str(normalized.get("rule_id") or "0"),
            level=int(normalized.get("level") or 0),
            agent_id=str(normalized.get("agent_id") or "000"),
            agent_name=str(normalized.get("agent_name") or "Agente"),
            description=description,
            description_raw=str(normalized.get("description_raw") or description),
            src_ip=str(normalized.get("src_ip") or "") or None,
            dst_ip=str(normalized.get("dst_ip") or "") or None,
            src_port=_to_int(normalized.get("src_port")),
            dst_port=_to_int(normalized.get("dst_port")),
            user=str(normalized.get("src_user") or normalized.get("user") or "") or None,
            process=str(normalized.get("process") or "") or None,
            mitre_ids=[str(x) for x in (normalized.get("mitre_ids") or [])],
            groups=[str(x) for x in (normalized.get("groups") or [])],
        ),
        enrichment=Enrichment(
            translations=TranslationInfo(description_es=description),
        ),
    )
    return event
