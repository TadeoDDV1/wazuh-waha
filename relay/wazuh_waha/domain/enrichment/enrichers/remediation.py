"""Enricher de remediación accionable."""

from __future__ import annotations

from typing import Any

from ... import cis_translator, wazuh_breakdown
from ..catalogs import get_rules
from ..context import EnrichmentContext
from ..models import RemediationStep
from .base import SyncEnricher

_SEVERITY_BY_LEVEL = [
    (12, "critical", "Crítico — actuar ahora", "Inmediato"),
    (8, "high", "Alto — revisar hoy", "24 horas"),
    (4, "medium", "Medio — revisar esta semana", "7 días"),
    (0, "low", "Bajo — solo informativo", "Sin SLA"),
]

_RISK_BY_SEVERITY = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "low",
    "info": "low",
}


def _severity(level: int) -> tuple[str, str, str]:
    for threshold, severity, plain, sla in _SEVERITY_BY_LEVEL:
        if level >= threshold:
            return severity, plain, sla
    return "info", "Informativo", "Sin SLA"


def _format(text: str, ctx: EnrichmentContext) -> str:
    if not text:
        return ""
    data = ctx.raw.get("data") or {}
    if not isinstance(data, dict):
        data = {}
    syscheck = ctx.raw.get("syscheck") or {}
    if not isinstance(syscheck, dict):
        syscheck = {}
    values = {
        "src_ip": ctx.event.normalized.src_ip or "",
        "dst_ip": ctx.event.normalized.dst_ip or "",
        "agent_name": ctx.event.normalized.agent_name or "",
        "agent_id": ctx.event.normalized.agent_id or "",
        "user": ctx.event.normalized.user or "",
        "process": ctx.event.normalized.process or "",
        "file": data.get("file") or syscheck.get("path") or "",
        "pid": data.get("pid") or "",
    }
    try:
        return text.format(**values)
    except (KeyError, IndexError, ValueError):
        return text


def _from_catalog(entry: dict[str, Any], ctx: EnrichmentContext) -> list[RemediationStep]:
    steps: list[RemediationStep] = []
    for idx, item in enumerate(entry.get("remediation") or [], start=1):
        if not isinstance(item, dict):
            continue
        action = _format(str(item.get("action") or "").strip(), ctx)
        if not action:
            continue
        steps.append(
            RemediationStep(
                order=idx,
                action=action,
                why=_format(str(item.get("why") or "").strip(), ctx),
                command=_format(str(item.get("command") or "").strip(), ctx) or None,
                reference=item.get("reference"),
                risk=str(item.get("risk") or "low"),  # type: ignore[arg-type]
            )
        )
    return steps


def _from_cis(ctx: EnrichmentContext) -> list[RemediationStep]:
    data = ctx.raw.get("data") or {}
    if not isinstance(data, dict):
        data = {}
    check = ctx.raw.get("check") or ctx.raw.get("sca") or data.get("check")
    if not isinstance(check, dict):
        return []
    title = str(check.get("title") or check.get("name") or "")
    if not title:
        return []
    localized = cis_translator.localize_cis_check(check)
    return [
        RemediationStep(
            order=1,
            action=str(localized.get("title") or title),
            why=str(localized.get("rationale") or ""),
            command=str(localized.get("remediation") or "") or None,
            risk="medium",
        )
    ]


def _from_network(ctx: EnrichmentContext) -> list[RemediationStep]:
    network = ctx.event.enrichment.network
    if network is None:
        return []
    port = network.dst_port or network.src_port
    if not port:
        return []
    info = wazuh_breakdown.explain_network_port_risk(
        port, network.protocol or "tcp", network.service or ""
    )
    severity = str(info.get("severity") or "")
    risk = "high" if "CRÍTICO" in severity else "medium" if "ALTO" in severity else "low"
    return [
        RemediationStep(
            order=1,
            action=str(info.get("advice") or "Revisar si el servicio es necesario."),
            why=f"Servicio detectado: {info.get('service_name', port)}.",
            risk=risk,  # type: ignore[arg-type]
        )
    ]


def _generic(level: int) -> list[RemediationStep]:
    if level >= 12:
        return [
            RemediationStep(
                order=1,
                action="Aislar el equipo y revisar el evento de inmediato",
                why="La severidad es crítica y requiere contención.",
                risk="medium",
            )
        ]
    if level >= 8:
        return [
            RemediationStep(
                order=1,
                action="Investigar el origen del evento y aplicar la acción recomendada",
                why="La severidad es alta y conviene revisarla hoy.",
                risk="low",
            )
        ]
    return [
        RemediationStep(
            order=1,
            action="Verificar si el evento es esperado y registrarlo",
            why="No requiere acción urgente, pero debe quedar trazabilidad.",
            risk="low",
        )
    ]


class RemediationEnricher(SyncEnricher):
    name = "remediation"
    order = 60

    def enrich(self, ctx: EnrichmentContext) -> None:
        n = ctx.event.normalized
        level = int(n.level or 0)
        rule_entry = (get_rules().get("rules") or {}).get(str(n.rule_id)) or {}

        severity, plain, sla = _severity(level)
        catalog_severity = str(rule_entry.get("severity") or "").lower()
        if catalog_severity in {"info", "low", "medium", "high", "critical"}:
            severity = catalog_severity
            plain = {
                "critical": "Crítico — actuar ahora",
                "high": "Alto — revisar hoy",
                "medium": "Medio — revisar esta semana",
                "low": "Bajo — solo informativo",
                "info": "Informativo",
            }[severity]
            sla = {
                "critical": "Inmediato",
                "high": "24 horas",
                "medium": "7 días",
                "low": "Sin SLA",
                "info": "Sin SLA",
            }[severity]

        steps = _from_catalog(rule_entry, ctx)
        source = "catalog:rules_es"
        if not steps:
            steps = _from_cis(ctx)
            source = "cis_translator"
        if not steps:
            steps = _from_network(ctx)
            source = "network:ports"
        if not steps:
            explained = wazuh_breakdown.explain_wazuh_rule(
                n.rule_id, level, n.description, n.groups
            )
            steps = [
                RemediationStep(
                    order=1,
                    action=str(explained.get("remediation") or "Revisar el evento."),
                    why=str(explained.get("risk") or ""),
                    risk=_RISK_BY_SEVERITY.get(severity, "low"),  # type: ignore[arg-type]
                )
            ]
            source = "wazuh_breakdown"
        if not steps:
            steps = _generic(level)
            source = "generic"

        ctx.event.enrichment.remediation = steps
        ctx.event.enrichment.risk.technical_severity = severity  # type: ignore[assignment]
        ctx.event.enrichment.risk.plain_severity = plain
        ctx.event.enrichment.risk.sla = sla
        if rule_entry.get("business_impact"):
            ctx.event.enrichment.risk.business_impact = str(rule_entry["business_impact"])
        elif rule_entry.get("risk"):
            ctx.event.enrichment.risk.business_impact = str(rule_entry["risk"])
        elif not ctx.event.enrichment.risk.business_impact:
            ctx.event.enrichment.risk.business_impact = (
                "Evento de seguridad que requiere revisión del equipo SOC."
            )
        ctx.add_source(source)
