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
