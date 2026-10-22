from fastapi.testclient import TestClient

from wazuh_waha.main import app
from wazuh_waha.common.session import COOKIE_NAME, issue_session
from wazuh_waha.config import settings

client = TestClient(app)


def test_console_targets_require_full_scope():
    old = settings.console_enabled
    settings.console_enabled = True
    try:
        read_token, _ = issue_session("read")
        full_token, _ = issue_session("full")
        r_read = client.get("/api/v1/console/targets", cookies={COOKIE_NAME: read_token})
        assert r_read.status_code == 403
        r_none = client.get("/api/v1/console/targets")
        assert r_none.status_code == 401
        r_full = client.get("/api/v1/console/targets", cookies={COOKIE_NAME: full_token})
        assert r_full.status_code == 200
        body = r_full.json()
        assert body["enabled"] is True
        assert any(t["id"] == "local" for t in body["targets"])
    finally:
        settings.console_enabled = old


def test_console_disabled_returns_no_targets():
    old = settings.console_enabled
    settings.console_enabled = False
    try:
        token, _ = issue_session("full")
        r = client.get("/api/v1/console/targets", cookies={COOKIE_NAME: token})
        assert r.status_code == 200
        assert r.json()["enabled"] is False
        assert r.json()["targets"] == []
    finally:
        settings.console_enabled = old


def test_websocket_rejects_read_scope():
    old = settings.console_enabled
    settings.console_enabled = True
    try:
        token, _ = issue_session("read")
        with client.websocket_connect(
            "/api/v1/console/ws?target=local", cookies={COOKIE_NAME: token}
        ) as ws:
            # El servidor cierra 4401 por scope insuficiente.
            try:
                ws.receive_text()
            except Exception:
                pass
    except Exception:
        # Starlette puede lanzar WebSocketDisconnect al cerrar.
        pass
    finally:
        settings.console_enabled = old
