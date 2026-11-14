"""Tests del enriquecimiento determinista."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from wazuh_waha.common.traffic_stream import normalize_wazuh_event
from wazuh_waha.config import settings
from wazuh_waha.domain.enrichment import (
    build_canonical_event,
    clear_catalog_cache,
    get_enrichment_pipeline,
    reset_enrichment_pipeline,
)
from wazuh_waha.main import app


@pytest.fixture(autouse=True)
def _isolate_enrichment(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "enrich_enabled", True)
    monkeypatch.setattr(settings, "enrich_cache_enabled", True)
    monkeypatch.setattr(settings, "enrich_cache_path", str(tmp_path / "enrichment.sqlite3"))
    monkeypatch.setattr(settings, "enrich_assets_file", "")
    monkeypatch.setattr(settings, "enrich_geoip_db", "")
    monkeypatch.setattr(settings, "enrich_redact_pii", True)
    clear_catalog_cache()
    reset_enrichment_pipeline()
    yield
    reset_enrichment_pipeline()
    clear_catalog_cache()


def _alert(rule_id: str = "5710", level: int = 10, **overrides):
    alert = {
        "id": f"evt-{rule_id}",
        "timestamp": "2026-11-13T17:00:00.000+0000",
        "rule": {
            "id": rule_id,
            "level": level,
            "description": "sshd: Authentication failed.",
            "groups": ["authentication_failed"],
        },
        "agent": {"id": "001", "name": "srv-linux"},
        "data": {"srcip": "203.0.113.45", "srcport": "22"},
        "full_log": "Failed password for root from 203.0.113.45 port 22 ssh2 password=secreto",
    }
    alert.update(overrides)
    return alert


def _normalized(alert: dict) -> dict:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    return {
        "id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule_id": str(rule.get("id", "0")),
        "level": int(rule.get("level", 0)),
        "description": "Fallo de autenticación por SSH",
        "description_raw": rule.get("description", ""),
        "agent_id": str(agent.get("id", "000")),
        "agent_name": agent.get("name", "Agente"),
        "src_ip": data.get("srcip", ""),
        "src_port": data.get("srcport", ""),
        "src_user": "root",
        "process": "sshd",
        "groups": rule.get("groups") or [],
        "source": "relay",
    }


def test_pipeline_enriches_known_rule():
    alert = _alert()
    event = build_canonical_event(alert, _normalized(alert))
    event = get_enrichment_pipeline().enrich(alert, event)

    assert event.enrichment.translations.description_es == "Fallo de autenticación por SSH"
    assert event.enrichment.translations.method == "catalog"
    assert event.enrichment.risk.plain_severity.startswith("Alto")
    assert event.enrichment.risk.mitre_techniques
    assert event.enrichment.remediation
    assert event.enrichment.remediation[0].command == "ufw deny from 203.0.113.45"
    assert event.enrichment.network is not None
    assert event.enrichment.network.service == "ssh"
    assert event.enrichment.network.direction == "inbound"
    assert event.enrichment.iocs[0].type == "ip"
    assert event.enrichment.iocs[0].defanged == "203[.]0[.]113[.]45"
    assert event.enrichment.degraded is False


def test_pipeline_redacts_secrets():
    alert = _alert()
    event = build_canonical_event(alert, _normalized(alert))
    event = get_enrichment_pipeline().enrich(alert, event)
    assert "secreto" not in event.enrichment.translations.full_log_es
    assert "<redactado>" in event.enrichment.translations.full_log_es


def test_pipeline_unknown_rule_falls_back():
    alert = _alert(rule_id="999999", level=5)
    alert["rule"]["description"] = "Evento personalizado del SOC"
    alert["full_log"] = "evento sin traduccion conocida"
    event = build_canonical_event(alert, _normalized(alert))
    event = get_enrichment_pipeline().enrich(alert, event)

    assert event.enrichment.translations.description_es
    assert event.enrichment.remediation
    assert event.enrichment.risk.plain_severity
    assert event.enrichment.confidence > 0


def test_pipeline_private_ip_is_not_geo():
    alert = _alert()
    alert["data"] = {"srcip": "10.0.0.5", "srcport": "22"}
    event = build_canonical_event(alert, _normalized(alert))
    event = get_enrichment_pipeline().enrich(alert, event)
    assert event.enrichment.network is not None
    assert event.enrichment.network.is_private is True
    assert event.enrichment.network.country is None


def test_normalize_wazuh_event_includes_enrichment():
    out = normalize_wazuh_event(_alert())
    assert out["rule_id"] == "5710"
    assert out["enrichment"]["translations"]["description_es"]
    assert out["enrichment"]["risk"]["plain_severity"]
    assert out["enrichment"]["remediation"]
    assert out["schema_version"] == "1.0"


def test_cache_reuses_enrichment():
    alert = _alert()
    pipeline = get_enrichment_pipeline()
    event1 = pipeline.enrich(alert, build_canonical_event(alert, _normalized(alert)))
    event2 = pipeline.enrich(alert, build_canonical_event(alert, _normalized(alert)))
    assert event1.enrichment.translations.description_es == event2.enrichment.translations.description_es
    stats = pipeline.cache.stats() if pipeline.cache else {}
    assert stats.get("enabled") is True


def test_enrichment_api_endpoints():
    client = TestClient(app)
    headers = {"X-Api-Key": settings.relay_api_key}

    glossary = client.get("/api/v1/telemetry/enrichment/glossary", headers=headers)
    assert glossary.status_code == 200
    assert "MITRE" in glossary.json()["terms"]

    catalogs = client.get("/api/v1/telemetry/enrichment/catalogs/status", headers=headers)
    assert catalogs.status_code == 200
    assert catalogs.json()["rules"] > 0

    metrics = client.get("/api/v1/telemetry/enrichment/metrics", headers=headers)
    assert metrics.status_code == 200
    assert "cache" in metrics.json()


def test_catalog_read_permission_denied(monkeypatch, tmp_path):
    """Un catálogo de usuario inaccesible no debe romper el enriquecimiento.

    ``Path.exists()`` propaga ``PermissionError`` cuando el directorio
    contenedor no es accesible; debe tratarse como catálogo ausente.
    """
    from pathlib import Path

    from wazuh_waha.domain.enrichment import catalogs

    target = tmp_path / "blocked" / "assets.json"
    real_exists = Path.exists

    def fake_exists(self):
        if self == target:
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    assert catalogs._read_structured(target) == {}
