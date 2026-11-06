"""Tests de endurecimiento: webhook WAHA, .env, HTML, dedup y validación Wazuh."""

from __future__ import annotations

import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from wazuh_waha.api import dashboard as dashboard_mod
from wazuh_waha.api import waha_webhook as webhook_mod
from wazuh_waha.config import settings
from wazuh_waha.domain import templates
from wazuh_waha.domain.dedup import Deduper
from wazuh_waha.infrastructure.wazuh_control import (
    WazuhControlError,
    _agent_conf_path,
    _validate_scope,
    apply_agent_module,
)
from wazuh_waha.main import app


@pytest.fixture()
def client():
    return TestClient(app)


def _body(sender: str = "5219991234567", text: str = "/status") -> dict:
    return {"event": "message", "payload": {"from": sender, "body": text, "fromMe": False}}


class TestWahaWebhookAuth:
    def test_rejects_missing_token(self, client, monkeypatch):
        monkeypatch.setattr(settings, "waha_api_key", "s3cret-token")
        monkeypatch.setattr(settings, "waha_webhook_token", "")
        monkeypatch.setattr(settings, "admin_phone", "5219991234567")
        r = client.post("/api/v1/waha/webhook", json=_body())
        assert r.status_code == 401

    def test_rejects_factory_token(self, client, monkeypatch):
        monkeypatch.setattr(settings, "waha_api_key", "changeme")
        monkeypatch.setattr(settings, "waha_webhook_token", "")
        r = client.post("/api/v1/waha/webhook", json=_body(), headers={"X-Api-Key": "changeme"})
        assert r.status_code == 401

    def test_rejects_sender_suffix(self, client, monkeypatch):
        monkeypatch.setattr(settings, "waha_api_key", "s3cret-token")
        monkeypatch.setattr(settings, "waha_webhook_token", "")
        monkeypatch.setattr(settings, "admin_phone", "5219991234567")
        # Antes un sufijo del número admin era aceptado.
        r = client.post(
            "/api/v1/waha/webhook",
            json=_body(sender="9991234567"),
            headers={"X-Api-Key": "s3cret-token"},
        )
        assert r.status_code == 403

    def test_executes_command_for_exact_admin(self, client, monkeypatch):
        monkeypatch.setattr(settings, "waha_api_key", "s3cret-token")
        monkeypatch.setattr(settings, "waha_webhook_token", "")
        monkeypatch.setattr(settings, "admin_phone", "5219991234567")
        with patch.object(webhook_mod, "process_admin_command", new=AsyncMock(return_value="ok")) as cmd, \
             patch.object(webhook_mod, "send_text", new=AsyncMock(return_value={"ok": True})):
            r = client.post(
                "/api/v1/waha/webhook",
                json=_body(),
                headers={"X-Api-Key": "s3cret-token"},
            )
        assert r.status_code == 200, r.text
        cmd.assert_awaited_once()

    def test_accepts_query_token(self, client, monkeypatch):
        monkeypatch.setattr(settings, "waha_api_key", "s3cret-token")
        monkeypatch.setattr(settings, "waha_webhook_token", "")
        monkeypatch.setattr(settings, "admin_phone", "5219991234567")
        with patch.object(webhook_mod, "process_admin_command", new=AsyncMock(return_value="ok")), \
             patch.object(webhook_mod, "send_text", new=AsyncMock(return_value={"ok": True})):
            r = client.post(
                "/api/v1/waha/webhook?token=s3cret-token",
                json=_body(),
            )
        assert r.status_code == 200, r.text


class TestEnvWriteSanitization:
    def _env(self, tmp_path: Path) -> Path:
        env = tmp_path / ".env"
        env.write_text("FOO=bar\nRELAY_API_KEY=original\n")
        return env

    def test_rejects_newline_injection(self, tmp_path, monkeypatch):
        env = self._env(tmp_path)
        monkeypatch.setattr(dashboard_mod, "ENV_FILE", env)
        before = env.read_text()
        assert dashboard_mod._write_env_batch({"FOO": "x\nRELAY_API_KEY=hacked"}) is False
        assert env.read_text() == before

    def test_rejects_bad_key(self, tmp_path, monkeypatch):
        env = self._env(tmp_path)
        monkeypatch.setattr(dashboard_mod, "ENV_FILE", env)
        assert dashboard_mod._write_env_batch({"BAD KEY": "x"}) is False

    def test_atomic_update(self, tmp_path, monkeypatch):
        env = self._env(tmp_path)
        monkeypatch.setattr(dashboard_mod, "ENV_FILE", env)
        assert dashboard_mod._write_env_batch({"FOO": "baz", "NEW": "1"}) is True
        text = env.read_text()
        assert "FOO=baz" in text
        assert "NEW=1" in text
        assert "RELAY_API_KEY=original" in text
        # No quedan temporales
        assert not list(tmp_path.glob(".env.tmp.*"))


class TestHtmlEscaping:
    def test_dynamic_values_are_escaped(self):
        alert = {
            "rule": {"id": "5710", "level": 10, "description": "<script>alert(1)</script>"},
            "agent": {"name": "<img src=x onerror=alert(1)>", "id": "001"},
            "full_log": "user <b>root</b> & co",
        }
        html = templates.render_soc_alert_html(alert)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert "<img src=x" not in html
        assert "&lt;img" in html
        assert "&amp; co" in html


class TestDedupAtomicity:
    def test_claim_is_exclusive_and_releasable(self, tmp_path):
        d = Deduper(ttl=300, state_file=tmp_path / "dedup.json")
        assert d.claim("5710", "001", "1.2.3.4") is True
        assert d.claim("5710", "001", "1.2.3.4") is False
        d.release("5710", "001", "1.2.3.4")
        assert d.claim("5710", "001", "1.2.3.4") is True

    def test_concurrent_claims_only_one_wins(self, tmp_path):
        d = Deduper(ttl=300, state_file=tmp_path / "dedup.json")
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: d.claim("5710", "001", "1.2.3.4"), range(40)))
        assert results.count(True) == 1


class TestWazuhInputValidation:
    def test_group_path_traversal_rejected(self):
        with pytest.raises(WazuhControlError):
            _agent_conf_path("../../etc")

    def test_group_shell_chars_rejected(self):
        with pytest.raises(WazuhControlError):
            _agent_conf_path("default; rm -rf /")

    def test_scope_injection_rejected(self):
        with pytest.raises(WazuhControlError):
            _validate_scope("001; rm -rf /")

    def test_apply_module_rejects_bad_scope(self):
        with pytest.raises(WazuhControlError):
            apply_agent_module("<agent_config/>", "../x", "sca", True)

    def test_valid_group_and_scope(self):
        assert _agent_conf_path("default").endswith("/default/agent.conf")
        assert _validate_scope("001") == "001"
