import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from wazuh_waha.main import app
from wazuh_waha.config import settings
from wazuh_waha.infrastructure import telegram_bot

AUTH_HEADER = {"X-Api-Key": settings.relay_api_key}


class TestTelegramIntegration:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        self.client = TestClient(app)

    def test_telegram_status_endpoint(self):
        resp = self.client.get("/api/v1/dashboard/telegram/status", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert "enabled" in data
        assert "configured" in data
        assert "chat_id" in data
        assert "min_level" in data

    def test_telegram_test_fails_when_unconfigured(self):
        old_token = settings.telegram_bot_token
        old_chat = settings.telegram_chat_id
        try:
            settings.telegram_bot_token = ""
            settings.telegram_chat_id = ""
            resp = self.client.post("/api/v1/dashboard/telegram/test", headers=AUTH_HEADER)
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is False
            assert "no configurados" in data["detail"].lower()
        finally:
            settings.telegram_bot_token = old_token
            settings.telegram_chat_id = old_chat

    @pytest.mark.anyio
    async def test_system_status_formatter(self):
        txt = telegram_bot._get_system_status()
        assert "ESTADO DEL SERVIDOR" in txt
        assert "CPU Load" in txt
        assert "Memoria" in txt
        assert "Disco" in txt

    @pytest.mark.anyio
    async def test_services_status_formatter(self):
        txt = await telegram_bot._get_services_status()
        assert "ESTADO DE SERVICIOS" in txt
        assert "Relay HTTP" in txt
        assert "WAHA" in txt

    @pytest.mark.anyio
    async def test_send_alert_skipped_when_disabled(self):
        old_enabled = settings.telegram_enabled
        try:
            settings.telegram_enabled = False
            res = await telegram_bot.send_alert("Test alert", level=12)
            assert res is False
        finally:
            settings.telegram_enabled = old_enabled

    @pytest.mark.anyio
    async def test_send_alert_skipped_when_below_min_level(self):
        old_enabled = settings.telegram_enabled
        old_token = settings.telegram_bot_token
        old_chat = settings.telegram_chat_id
        old_min = settings.telegram_min_level
        try:
            settings.telegram_enabled = True
            settings.telegram_bot_token = "123:abc"
            settings.telegram_chat_id = "999"
            settings.telegram_min_level = 10
            # Level 5 is below min level 10
            res = await telegram_bot.send_alert("Low alert", level=5)
            assert res is False
        finally:
            settings.telegram_enabled = old_enabled
            settings.telegram_bot_token = old_token
            settings.telegram_chat_id = old_chat
            settings.telegram_min_level = old_min

    def test_telegram_session_persistence(self, tmp_path):
        with patch.object(telegram_bot, "get_session_file", return_value=tmp_path / "telegram_session.json"):
            # Guardar sesión
            ok = telegram_bot.save_telegram_session(
                token="test-token-123",
                chat_id="test-chat-456",
                enabled=True,
                min_level=9,
            )
            assert ok is True
            assert (tmp_path / "telegram_session.json").exists()

            # Resetear memoria
            settings.telegram_bot_token = ""
            settings.telegram_chat_id = ""

            # Cargar sesión persistida
            loaded = telegram_bot.load_telegram_session()
            assert loaded["token"] == "test-token-123"
            assert loaded["chat_id"] == "test-chat-456"
            assert loaded["enabled"] is True
            assert loaded["min_level"] == 9
            assert settings.telegram_bot_token == "test-token-123"
            assert settings.telegram_chat_id == "test-chat-456"

    @pytest.mark.anyio
    async def test_process_admin_commands(self):
        # /ayuda
        res_help = await telegram_bot.process_admin_command("/ayuda")
        assert "PANEL DE CONTROL" in res_help
        assert "/status" in res_help

        # /status
        res_status = await telegram_bot.process_admin_command("/status")
        assert "ESTADO DEL SERVIDOR" in res_status

        # /servicios
        res_serv = await telegram_bot.process_admin_command("/servicios")
        assert "ESTADO DE SERVICIOS" in res_serv

        # /red
        res_net = await telegram_bot.process_admin_command("/red")
        assert "MONITOREO DE RED" in res_net
        assert "1514/TCP" in res_net

        # /agentes
        res_ag = await telegram_bot.process_admin_command("/agentes")
        assert "EQUIPOS Y AGENTES" in res_ag

        # /reglas
        res_rules = await telegram_bot.process_admin_command("/reglas")
        assert "REGLAS DE SEGURIDAD" in res_rules
        assert "57100" in res_rules
        assert "57120" in res_rules

        # /canales
        res_ch = await telegram_bot.process_admin_command("/canales")
        assert "ESTADO DE CANALES" in res_ch

        # /ping
        res_ping = await telegram_bot.process_admin_command("/ping")
        assert "Pong" in res_ping

        # /comandos (catálogo general)
        res_cmd = await telegram_bot.process_admin_command("/comandos")
        assert "CATÁLOGO MAESTRO" in res_cmd
        assert "/comandos agentes" in res_cmd
        assert "/comandos reportes" in res_cmd
        assert "Comandos Disponibles" in res_cmd

        # /comandos por categorías
        res_cmd_ag = await telegram_bot.process_admin_command("/comandos agentes")
        assert "GESTIÓN DE AGENTES" in res_cmd_ag
        assert "/agente <id>" in res_cmd_ag
        assert "/analizar_agente <id>" in res_cmd_ag

        res_cmd_rep = await telegram_bot.process_admin_command("/comandos reportes")
        assert "REPORTES EJECUTIVOS FORENSES" in res_cmd_rep
        assert "/reporte <agent_id>" in res_cmd_rep

        res_cmd_all = await telegram_bot.process_admin_command("/comandos todos")
        assert "GESTIÓN DE AGENTES" in res_cmd_all
        assert "REPORTES EJECUTIVOS" in res_cmd_all
        assert "ALERTAS Y REGLAS" in res_cmd_all

        # /sync_comandos
        with patch.object(telegram_bot, "register_bot_commands", return_value=True):
            res_sync = await telegram_bot.process_admin_command("/sync_comandos")
            assert "Comandos sincronizados con éxito" in res_sync

    def test_waha_webhook_command_processing(self):
        old_admin = settings.admin_phone
        try:
            settings.admin_phone = "5219991234567"

            # Mensaje no autorizado
            unauth_payload = {
                "event": "message",
                "payload": {
                    "from": "5215559999999@c.us",
                    "fromMe": False,
                    "body": "/status",
                }
            }
            res_unauth = self.client.post("/api/v1/waha/webhook", json=unauth_payload)
            assert res_unauth.status_code == 403

            # Mensaje no comando
            plain_payload = {
                "event": "message",
                "payload": {
                    "from": "5219991234567@c.us",
                    "fromMe": False,
                    "body": "Hola buen día",
                }
            }
            res_plain = self.client.post("/api/v1/waha/webhook", json=plain_payload)
            assert res_plain.status_code == 200
            assert res_plain.json()["skipped"] == "not_command"

            # Mensaje comando del admin (con mock de send_text)
            cmd_payload = {
                "event": "message",
                "payload": {
                    "from": "5219991234567@c.us",
                    "fromMe": False,
                    "body": "/status",
                }
            }
            with patch("wazuh_waha.api.waha_webhook.send_text", new_callable=AsyncMock) as mock_send:
                res_cmd = self.client.post("/api/v1/waha/webhook", json=cmd_payload)
                assert res_cmd.status_code == 200
                assert res_cmd.json()["ok"] is True
                assert res_cmd.json()["executed"] == "/status"
                mock_send.assert_awaited_once()
        finally:
            settings.admin_phone = old_admin
