"""Enricher de activo/agente."""

from __future__ import annotations

from ..catalogs import get_assets
from ..context import EnrichmentContext
from ..models import AssetInfo
from .base import SyncEnricher

_VALID_CRITICALITY = {"low", "medium", "high", "critical"}


class AssetEnricher(SyncEnricher):
    name = "asset"
    order = 10

    def enrich(self, ctx: EnrichmentContext) -> None:
        data = get_assets()
        assets = data.get("assets") or {}
        defaults = data.get("defaults") or {}

        normalized = ctx.event.normalized
        aid = str(normalized.agent_id or "000")
        name = str(normalized.agent_name or "Agente")

        info = assets.get(aid) or assets.get(name) or {}
        criticality = str(info.get("criticality") or defaults.get("criticality") or "medium").lower()
        if criticality not in _VALID_CRITICALITY:
            criticality = "medium"

        tags = info.get("tags")
        if not isinstance(tags, list):
            tags = []

        ctx.event.enrichment.asset = AssetInfo(
            agent_id=aid,
            name=str(info.get("name") or name),
            os=info.get("os"),
            ip=info.get("ip"),
            criticality=criticality,  # type: ignore[arg-type]
            owner=info.get("owner") or defaults.get("owner"),
            location=info.get("location") or defaults.get("location"),
            tags=[str(t) for t in tags],
        )
        ctx.add_source("catalog:assets")
