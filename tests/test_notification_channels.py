import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from wazuh_waha.main import app
from wazuh_waha.config import settings
from wazuh_waha.domain import templates


@pytest.fixture
def client():
    return TestClient(app)


def test_spanish_alert_formatting():
    """Verifica que las alertas por defecto y específicas se formateen 100% en español."""
    alert = {
        "timestamp": "2026-10-07T19:30:00Z",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Authentication failed.",
        },
        "agent": {"id": "001", "name": "servidor-linux"},
        "data": {
            "srcip": "192.168.1.100",
            "dstuser": "root",
        },
    }
    # Template específico
    rendered = templates.render("5710", alert)
    assert rendered is not None
    assert "SSH fallido" in rendered
    assert "Agente:" in rendered
    assert "Origen:" in rendered

    # Template general
    rendered_default = templates.render_default(alert)
    assert "ALERTA DE SEGURIDAD WAZUH" in rendered_default
    assert "Nivel:" in rendered_default
    assert "Fallo de autenticación por SSH" in rendered_default
    assert "Equipo / Agente:" in rendered_default
    assert "IP Origen:" in rendered_default


@pytest.mark.anyio
async def test_update_notification_channels_endpoint(client):
    """Verifica el endpoint para activar/desactivar canales de notificación."""
    # Auth header
    headers = {"X-Api-Key": settings.relay_api_key}

    payload = {
        "whatsapp_enabled": True,
        "telegram_enabled": False,
        "email_alerts_enabled": True,
    }
    response = client.post("/api/v1/dashboard/notifications/channels", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["channels"]["whatsapp_enabled"] is True
    assert data["channels"]["telegram_enabled"] is False
    assert data["channels"]["email_alerts_enabled"] is True

    assert settings.whatsapp_enabled is True
    assert settings.telegram_enabled is False
    assert settings.email_alerts_enabled is True


@pytest.mark.anyio
async def test_network_summary_endpoint(client):
    """Verifica que el endpoint de resumen de red responde con puertos y agentes."""
    headers = {"X-Api-Key": settings.relay_api_key}
    response = client.get("/api/v1/telemetry/network/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "services_ports" in data
    assert "agents" in data
    assert isinstance(data["services_ports"], list)
    assert isinstance(data["agents"], list)


@pytest.mark.anyio
async def test_network_probe_endpoint(client):
    """Verifica que el endpoint de sonda de red sondea los equipos."""
    headers = {"X-Api-Key": settings.relay_api_key}
    response = client.post("/api/v1/telemetry/network/probe", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "probed_count" in data
    assert "results" in data


@pytest.mark.anyio
async def test_agent_traffic_details_endpoint(client):
    """Verifica el endpoint de telemetria detallada por agente (sockets, interfaces, alertas)."""
    headers = {"X-Api-Key": settings.relay_api_key}
    response = client.get("/api/v1/telemetry/agents/001/traffic", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["agent_id"] == "001"
    assert "ports" in data
    assert "ifaces" in data
    assert "processes" in data
    assert "wazuh_detections" in data
    assert "kpis" in data
    assert "total_sockets" in data["kpis"]
    assert "total_wazuh_alerts" in data["kpis"]
