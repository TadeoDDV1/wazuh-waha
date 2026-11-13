"""Pipeline de enriquecimiento determinista."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ...config import settings
from .cache import EnrichmentCache
from .catalogs import get_catalog_version
from .context import EnrichmentContext
from .enrichers import (
    AssetEnricher,
    GeoEnricher,
    IocEnricher,
    MitreEnricher,
    NetworkEnricher,
    RemediationEnricher,
    TranslationEnricher,
)
from .enrichers.base import SyncEnricher
from .models import CanonicalEvent, Enrichment


def _default_enrichers() -> list[SyncEnricher]:
    return [
        AssetEnricher(),
        NetworkEnricher(),
        GeoEnricher(),
        MitreEnricher(),
        TranslationEnricher(),
        RemediationEnricher(),
        IocEnricher(),
    ]


def _cache_key(raw: dict[str, Any], event: CanonicalEvent) -> str:
    n = event.normalized
    full_log = str(raw.get("full_log") or "")[:300]
    seed = "|".join(
        [
            str(n.rule_id),
            str(n.agent_id),
            str(n.src_ip or ""),
            str(n.dst_ip or ""),
            str(n.dst_port or ""),
            str(n.description or ""),
            full_log,
            get_catalog_version(),
        ]
    )
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()


def _confidence(event: CanonicalEvent) -> float:
    values: list[float] = [event.enrichment.translations.confidence]
    if event.enrichment.asset:
        values.append(0.9)
    if event.enrichment.network:
        values.append(0.8)
    if event.enrichment.remediation:
        values.append(0.9)
    if event.enrichment.iocs:
        values.append(0.7)
    return round(sum(values) / len(values), 3) if values else 0.5


class EnrichmentPipeline:
    def __init__(
        self,
        enrichers: list[SyncEnricher] | None = None,
        cache: EnrichmentCache | None = None,
    ) -> None:
        self.enrichers = sorted(enrichers or _default_enrichers(), key=lambda e: e.order)
        self.cache = cache

    def enrich(self, raw: dict[str, Any], event: CanonicalEvent) -> CanonicalEvent:
        if not settings.enrich_enabled:
            return event

        started = time.perf_counter()
        key = _cache_key(raw, event) if self.cache else ""
        if self.cache and key:
            cached = self.cache.get(key)
            if isinstance(cached, dict):
                try:
                    event.enrichment = Enrichment.model_validate(cached)
                    event.enrichment.elapsed_ms = (time.perf_counter() - started) * 1000
                    event.catalog_version = get_catalog_version()
                    return event
                except Exception:
                    pass

        ctx = EnrichmentContext(raw=raw, event=event, cache=self.cache)
        for enricher in self.enrichers:
            try:
                enricher.enrich(ctx)
            except Exception as exc:
                ctx.fail(enricher.name, exc)

        event.enrichment.errors.extend(ctx.errors)
        event.enrichment.degraded = bool(ctx.errors)
        event.enrichment.confidence = _confidence(event)
        event.enrichment.elapsed_ms = (time.perf_counter() - started) * 1000
        event.catalog_version = get_catalog_version()

        if self.cache and key and not ctx.errors:
            try:
                self.cache.set(key, "enrichment", event.enrichment.model_dump(mode="json"))
            except Exception:
                pass
        return event


_pipeline: EnrichmentPipeline | None = None


def get_enrichment_pipeline() -> EnrichmentPipeline:
    global _pipeline
    if _pipeline is None:
        cache = EnrichmentCache() if settings.enrich_cache_enabled else None
        _pipeline = EnrichmentPipeline(cache=cache)
    return _pipeline


def reset_enrichment_pipeline() -> None:
    """Reinicia el singleton (útil en tests y al recargar configuración)."""
    global _pipeline
    _pipeline = None
