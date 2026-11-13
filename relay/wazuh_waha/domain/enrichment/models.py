"""Modelo canónico de eventos enriquecidos.

Todos los enrichers escriben sobre :class:`Enrichment`; el resto del sistema
(dashboard, Telegram, WhatsApp, PDF, API) consume el mismo contrato.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AssetInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_id: str
    name: str
    os: str | None = None
    ip: str | None = None
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    owner: str | None = None
    location: str | None = None
    tags: list[str] = Field(default_factory=list)


class NetworkInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    direction: str | None = None
    hostname: str | None = None
    asn: str | None = None
    country: str | None = None
    city: str | None = None
    site_category: str | None = None
    is_private: bool | None = None


class RiskInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    technical_severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    plain_severity: str = "Informativo"
    business_impact: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phase: str | None = None
    sla: str | None = None


class TranslationInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    description_es: str
    full_log_es: str = ""
    summary_es: str | None = None
    method: Literal["catalog", "regex", "template", "raw"] = "raw"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class RemediationStep(BaseModel):
    model_config = ConfigDict(extra="ignore")

    order: int = 1
    action: str
    why: str = ""
    command: str | None = None
    reference: str | None = None
    risk: Literal["low", "medium", "high"] = "low"


class Ioc(BaseModel):
    model_config = ConfigDict(extra="ignore")

    type: Literal["ip", "domain", "url", "hash", "user", "process", "file"]
    value: str
    defanged: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class Enrichment(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asset: AssetInfo | None = None
    network: NetworkInfo | None = None
    risk: RiskInfo = Field(default_factory=RiskInfo)
    translations: TranslationInfo
    remediation: list[RemediationStep] = Field(default_factory=list)
    iocs: list[Ioc] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    elapsed_ms: float = 0.0
    degraded: bool = False
    errors: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    rule_id: str
    level: int
    agent_id: str
    agent_name: str
    description: str
    description_raw: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    user: str | None = None
    process: str | None = None
    mitre_ids: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    catalog_version: str = "2026.11"
    id: str
    timestamp: str
    source: Literal["wazuh", "network", "manual"] = "wazuh"
    raw: dict = Field(default_factory=dict)
    normalized: NormalizedEvent
    enrichment: Enrichment
