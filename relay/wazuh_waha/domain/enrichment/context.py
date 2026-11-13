"""Contexto compartido por los enrichers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .cache import EnrichmentCache
from .models import CanonicalEvent


@dataclass
class EnrichmentContext:
    raw: dict[str, Any]
    event: CanonicalEvent
    cache: EnrichmentCache | None = None
    errors: list[str] = field(default_factory=list)

    def add_source(self, name: str) -> None:
        if name and name not in self.event.enrichment.sources:
            self.event.enrichment.sources.append(name)

    def fail(self, enricher: str, exc: Exception | str) -> None:
        self.errors.append(f"{enricher}: {exc}")
