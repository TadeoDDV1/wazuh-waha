"""Enricher de traducción al español (determinista)."""

from __future__ import annotations

import re

from ....config import settings
from ... import templates
from ..catalogs import get_rules
from ..context import EnrichmentContext
from ..models import TranslationInfo
from .base import SyncEnricher

_SECRET_PATTERNS = [
    (
        re.compile(r"(?i)(password|passwd|pwd|token|api[_-]?key|secret)\s*[=:]\s*([^\s,;]+)"),
        r"\1=<redactado>",
    ),
    (
        re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)([^\s]+)"),
        r"\1<redactado>",
    ),
]


def _redact(text: str) -> str:
    if not text or not settings.enrich_redact_pii:
        return text
    result = text
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _clip(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + " …[truncado]"


def _summary(rule_entry: dict, description_es: str, agent_name: str) -> str:
    template = str(rule_entry.get("summary") or "").strip()
    if template:
        return template
    if description_es:
        return f"{description_es} en {agent_name}."
    return f"Evento de seguridad registrado en {agent_name}."


class TranslationEnricher(SyncEnricher):
    name = "translation"
    order = 50

    def enrich(self, ctx: EnrichmentContext) -> None:
        n = ctx.event.normalized
        raw_desc = n.description_raw or n.description or ""
        raw_log = str(ctx.raw.get("full_log") or "")

        description_es = templates._translate_description_es(raw_desc)
        full_log_es = templates.translate_full_log_es(raw_log) if raw_log else ""

        rules = get_rules().get("rules") or {}
        rule_entry = rules.get(str(n.rule_id)) or {}
        if rule_entry.get("title"):
            description_es = str(rule_entry["title"])

        description_es = _redact(description_es)
        full_log_es = _redact(_clip(full_log_es))
        summary_es = _redact(_summary(rule_entry, description_es, n.agent_name))

        if rule_entry:
            method = "catalog"
            confidence = 0.95
            source = "catalog:rules_es"
        elif full_log_es and full_log_es != raw_log:
            method = "regex"
            confidence = 0.75
            source = "templates:regex"
        elif description_es and description_es != raw_desc:
            method = "regex"
            confidence = 0.7
            source = "templates:regex"
        else:
            method = "raw"
            confidence = 0.4
            source = "raw"

        ctx.event.enrichment.translations = TranslationInfo(
            description_es=description_es or "Evento de seguridad sin descripción",
            full_log_es=full_log_es,
            summary_es=summary_es,
            method=method,  # type: ignore[arg-type]
            confidence=confidence,
        )
        ctx.add_source(source)
