"""Interfaz base de los enrichers deterministas."""

from __future__ import annotations

from ..context import EnrichmentContext


class SyncEnricher:
    name: str = "sync"
    order: int = 100

    def enrich(self, ctx: EnrichmentContext) -> None:  # pragma: no cover - interfaz
        raise NotImplementedError
