"""Enricher MITRE ATT&CK."""

from __future__ import annotations

from typing import Any

from ..catalogs import get_mitre, get_rules
from ..context import EnrichmentContext
from .base import SyncEnricher

_TACTIC_ES = {
    "reconnaissance": "Reconocimiento",
    "resource development": "Desarrollo de recursos",
    "initial access": "Acceso inicial",
    "execution": "Ejecución",
    "persistence": "Persistencia",
    "privilege escalation": "Escalada de privilegios",
    "defense evasion": "Evasión de defensas",
    "credential access": "Acceso a credenciales",
    "discovery": "Descubrimiento",
    "lateral movement": "Movimiento lateral",
    "collection": "Recolección",
    "command and control": "Comando y control",
    "exfiltration": "Exfiltración",
    "impact": "Impacto",
}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    if isinstance(value, str) and value:
        return [value]
    return []


class MitreEnricher(SyncEnricher):
    name = "mitre"
    order = 40

    def enrich(self, ctx: EnrichmentContext) -> None:
        rule = ctx.raw.get("rule") or {}
        mitre = rule.get("mitre") or {}
        if not isinstance(mitre, dict):
            mitre = {}

        technique_ids = _as_list(mitre.get("id"))
        tactics_raw = _as_list(mitre.get("tactic"))
        techniques_raw = _as_list(mitre.get("technique"))

        catalog = get_mitre().get("techniques") or {}
        techniques: list[str] = []
        tactics: list[str] = []

        for tid in technique_ids:
            entry = catalog.get(tid) or {}
            name = entry.get("name")
            techniques.append(f"{tid} — {name}" if name else tid)
            tactic = entry.get("tactic")
            if tactic and tactic not in tactics:
                tactics.append(str(tactic))

        for tactic in tactics_raw:
            translated = _TACTIC_ES.get(tactic.strip().lower(), tactic)
            if translated not in tactics:
                tactics.append(translated)

        if not techniques and techniques_raw:
            techniques = techniques_raw

        # Fallback: catálogo de reglas propio.
        if not techniques or not tactics:
            rule_id = str(ctx.event.normalized.rule_id)
            rule_entry = (get_rules().get("rules") or {}).get(rule_id) or {}
            rule_mitre = rule_entry.get("mitre") or {}
            if not tactics:
                tactics = [str(t) for t in _as_list(rule_mitre.get("tactics"))]
            if not techniques:
                for tid in _as_list(rule_mitre.get("techniques")):
                    entry = catalog.get(tid) or {}
                    name = entry.get("name")
                    techniques.append(f"{tid} — {name}" if name else tid)

        ctx.event.enrichment.risk.mitre_tactics = tactics
        ctx.event.enrichment.risk.mitre_techniques = techniques
        if tactics:
            ctx.event.enrichment.risk.kill_chain_phase = tactics[0]
        if tactics or techniques:
            ctx.add_source("catalog:mitre")
