import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from relay.wazuh_waha.infrastructure.agent_analyzer import (
    _render_progress_bar,
    format_hardening_report,
    trigger_wazuh_scans,
    AgentConnectionWatcher,
    _LAST_AGENT_STATUSES,
    _LAST_ANALYSIS_TS,
)
from relay.wazuh_waha.main import app


def test_render_progress_bar():
    assert _render_progress_bar(0) == "░░░░░░░░░░"
    assert _render_progress_bar(50) == "█████░░░░░"
    assert _render_progress_bar(100) == "██████████"
    assert _render_progress_bar(80) == "████████░░"


def test_cis_translator_catalog_and_heuristic():
    from relay.wazuh_waha.domain.cis_translator import localize_cis_check

    check1 = {
        "title": "Ensure unused filesystems kernel modules are not available.",
        "rationale": "While loadable filesystem kernel modules are a convenient method of modifying the running kernel, this can be abused by attackers.",
        "remediation": "- IF - the module is available in the running kernel: - Unload the filesystem kernel module from the kernel",
    }
    loc1 = localize_cis_check(check1)
    assert "Deshabilitar módulos de kernel" in loc1["title"]
    assert "superficie de ataque" in loc1["rationale"]
    assert "modprobe.d" in loc1["remediation"]

    check2 = {
        "title": "Ensure telnet is not installed",
        "rationale": "The telnet protocol transmits passwords in cleartext.",
        "remediation": "apt-get purge telnet",
    }
    loc2 = localize_cis_check(check2)
    assert "Desinstalar software no requerido: telnet" in loc2["title"]



def test_format_hardening_report_with_failures():
    profile = {
        "name": "srv-db-prod",
        "ip": "192.168.122.50",
        "os": {
            "name": "Ubuntu",
            "version": "22.04 LTS",
            "architecture": "x86_64",
            "kernel": "5.15.0-generic",
        },
        "sca": {
            "name": "CIS Benchmark for Ubuntu 22.04",
            "policy_id": "cis_ubuntu22-04",
            "score": 62.5,
            "total_checks": 80,
            "pass": 50,
            "fail": 30,
            "failed_checks": [
                {
                    "title": "Ensure permissions on /etc/shadow are configured",
                    "rationale": "The /etc/shadow file contains user password hashes and should only be readable by root.",
                    "remediation": "chmod 0000 /etc/shadow && chown root:root /etc/shadow",
                },
                {
                    "title": "Ensure SSH PermitRootLogin is disabled",
                    "rationale": "Permitting root login over SSH increases the surface of brute-force attacks.",
                    "remediation": "echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart ssh",
                },
            ],
        },
        "recent_detections": [
            {"description": "Vulnerability CVE-2023-4911 detected in glibc"},
        ],
    }

    report = format_hardening_report(profile, "002", trigger_reason="conexión de agente")
    assert "AGENTE CONECTADO • ANÁLISIS DE SEGURIDAD SOC" in report
    assert "srv-db-prod" in report
    assert "192.168.122.50" in report
    assert "62.5%" in report
    assert "PLAN DE MEJORAS & HARDENING RECOMENDADO" in report
    assert "chmod 0000 /etc/shadow" in report
    assert "PermitRootLogin no" in report
    assert "/reporte 002" in report
    assert "⚠️ 1 eventos detectados" in report


def test_format_hardening_report_full_compliance():
    profile = {
        "name": "srv-hardened",
        "ip": "192.168.122.99",
        "os": {"name": "Debian", "version": "12", "architecture": "x86_64", "kernel": "6.1.0"},
        "sca": {
            "name": "CIS Benchmark for Debian 12",
            "policy_id": "cis_debian12",
            "score": 100.0,
            "total_checks": 60,
            "pass": 60,
            "fail": 0,
            "failed_checks": [],
        },
    }

    report = format_hardening_report(profile, "005")
    assert "100.0%" in report
    assert "No se detectaron fallos críticos de configuración CIS" in report


@pytest.mark.anyio
async def test_trigger_wazuh_scans_missing_credentials():
    with patch("relay.wazuh_waha.config.settings.wazuh_server_ip", ""):
        with patch("relay.wazuh_waha.config.settings.wazuh_manager_host", ""):
            res = await trigger_wazuh_scans("001")
            assert res["ok"] is False
            assert "Credenciales" in res["error"]


@pytest.mark.anyio
async def test_agent_connection_watcher_transition():
    watcher = AgentConnectionWatcher(check_interval=1.0)
    _LAST_AGENT_STATUSES.clear()
    _LAST_ANALYSIS_TS.clear()

    # Precondición: agente 001 está disconnected
    _LAST_AGENT_STATUSES["001"] = "disconnected"

    mock_auth_resp = MagicMock()
    mock_auth_resp.status_code = 200
    mock_auth_resp.json.return_value = {"data": {"token": "test-token"}}

    mock_agents_resp = MagicMock()
    mock_agents_resp.status_code = 200
    mock_agents_resp.json.return_value = {
        "data": {
            "affected_items": [
                {"id": "001", "name": "srv-web", "status": "active"},
                {"id": "002", "name": "srv-db", "status": "disconnected"},
            ]
        }
    }

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_auth_resp
    mock_client.get.return_value = mock_agents_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None

    with patch("relay.wazuh_waha.config.settings.wazuh_server_ip", "127.0.0.1"), \
         patch("relay.wazuh_waha.config.settings.wazuh_manager_api_pass", "secret"), \
         patch("httpx.AsyncClient", return_value=mock_client), \
         patch("relay.wazuh_waha.infrastructure.agent_analyzer.analyze_and_notify_agent", new_callable=AsyncMock) as mock_analyze:

        await watcher._check_agents_state()

        # Agente 001 cambió de disconnected a active -> debe disparar análisis
        assert mock_analyze.call_count == 1
        call_args = mock_analyze.call_args[0]
        assert call_args[0] == "001"

        # Segunda llamada inmediata -> no debe disparar de nuevo por cooldown
        await watcher._check_agents_state()
        assert mock_analyze.call_count == 1


@pytest.mark.anyio
async def test_alert_pipeline_triggers_analysis_on_connection_rule():
    import time
    from relay.wazuh_waha.config import settings

    unique_aid = f"99_{int(time.time() * 1000)}"
    client = TestClient(app)

    with patch("relay.wazuh_waha.domain.dedup.deduper.is_duplicate", return_value=False), \
         patch("relay.wazuh_waha.infrastructure.agent_analyzer.analyze_and_notify_agent", new_callable=AsyncMock) as mock_analyze:
        payload = {
            "rule": {
                "id": "57150",
                "level": 10,
                "description": "Wazuh Agent conectado al ecosistema",
            },
            "agent": {"id": unique_aid, "name": "srv-ubuntu"},
            "timestamp": "2026-10-15T12:00:00.000Z",
        }
        resp = client.post(
            "/alerts",
            headers={"X-Api-Key": settings.relay_api_key},
            json=payload,
        )
        assert resp.status_code == 200
        assert mock_analyze.call_count == 1
        assert mock_analyze.call_args[0][0] == unique_aid


@pytest.mark.anyio
async def test_telegram_analizar_agente_command():
    from relay.wazuh_waha.infrastructure import telegram_bot

    with patch("relay.wazuh_waha.infrastructure.agent_analyzer.analyze_and_notify_agent", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = "🟢 [AGENTE CONECTADO • ANÁLISIS DE SEGURIDAD SOC]"
        res = await telegram_bot.process_admin_command("/analizar_agente 000")
        assert "ANÁLISIS DE SEGURIDAD SOC" in res
        mock_analyze.assert_called_once_with("000", reason="solicitud manual")

