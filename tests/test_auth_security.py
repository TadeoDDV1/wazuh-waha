"""Tests de seguridad: autenticación BFF (sesión/cookie), /debug/*, RBAC."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from fastapi import Request
from fastapi.testclient import TestClient

from wazuh_waha import main as main_mod
from wazuh_waha.common import audit as audit_mod
from wazuh_waha.common.audit import AuditLog
from wazuh_waha.common.session import COOKIE_NAME, issue_session, verify_session
from wazuh_waha.config import settings


def _make_request(headers: list[tuple[bytes, bytes]], peer: str = "127.0.0.1") -> Request:
    scope = {
        "type": "http",
        "headers": headers,
        "client": (peer, 12345),
        "method": "GET",
        "path": "/x",
        "query_string": b"",
        "scheme": "http",
        "server": ("test", 80),
    }
    async def receive() -> dict:  # pragma: no cover - no usado
        return {"type": "http.request", "body": b""}
    return Request(scope, receive)


class BaseAuthTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_audit = audit_mod._audit
        audit_mod._audit = AuditLog(Path(self._tmp.name) / "audit.jsonl")
        main_mod._RATE_LIMITS.clear()
        self.client = TestClient(main_mod.app)

    def tearDown(self):
        audit_mod._audit = self._old_audit
        main_mod._RATE_LIMITS.clear()
        self._tmp.cleanup()

    def login(self, key: str | None = None, client: TestClient | None = None) -> TestClient:
        c = client or self.client
        r = c.post("/api/v1/auth/login", json={"api_key": key or settings.relay_api_key})
        self.assertEqual(r.status_code, 200, r.text)
        return c

    def cookie_for(self, scope: str = "full", ttl_hours: int = 8) -> str:
        token, _ = issue_session(scope, ttl_hours=ttl_hours)
        return token


class TestDebugAuth(BaseAuthTest):
    def test_recent_requires_auth(self):
        self.assertEqual(self.client.get("/debug/recent").status_code, 401)

    def test_workers_requires_auth(self):
        self.assertEqual(self.client.get("/debug/workers").status_code, 401)

    def test_backups_requires_auth(self):
        self.assertEqual(self.client.get("/debug/backups").status_code, 401)

    def test_debug_ok_with_header(self):
        r = self.client.get("/debug/recent", headers={"X-Api-Key": settings.relay_api_key})
        self.assertEqual(r.status_code, 200)

    def test_debug_ok_with_session(self):
        self.login()
        self.assertEqual(self.client.get("/debug/recent").status_code, 200)

    def test_health_is_public_but_minimal(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        # No exponer datos de recon (PID/worker)
        self.assertNotIn("worker_id", body)


class TestLoginSession(BaseAuthTest):
    def test_login_sets_httponly_strict_cookie(self):
        r = self.client.post("/api/v1/auth/login", json={"api_key": settings.relay_api_key})
        self.assertEqual(r.status_code, 200)
        sc = r.headers.get("set-cookie", "").lower()
        self.assertIn("ww_session=", sc)
        self.assertIn("httponly", sc)
        self.assertIn("samesite=strict", sc)

    def test_login_bad_key(self):
        r = self.client.post("/api/v1/auth/login", json={"api_key": "k" * 48})
        self.assertEqual(r.status_code, 401)

    def test_login_short_key_validation(self):
        r = self.client.post("/api/v1/auth/login", json={"api_key": "corto"})
        self.assertEqual(r.status_code, 422)

    def test_login_rate_limited(self):
        status = None
        for _ in range(7):
            r = self.client.post(
                "/api/v1/auth/login", json={"api_key": "k" * 48}
            )
            status = r.status_code
        self.assertEqual(status, 429)

    def test_session_endpoint_and_logout(self):
        self.login()
        r = self.client.get("/api/v1/auth/session")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["authenticated"])
        self.assertEqual(r.json()["scope"], "full")

        r = self.client.post("/api/v1/auth/logout")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/api/v1/auth/session").status_code, 401)

    def test_forged_cookie_rejected(self):
        self.client.cookies.set(COOKIE_NAME, "aaaa.bbbb")
        self.assertEqual(self.client.get("/api/v1/telemetry/snapshot").status_code, 401)
        self.client.cookies.delete(COOKIE_NAME)

    def test_tampered_payload_rejected(self):
        token = self.cookie_for()
        raw, sig = token.split(".")
        # Voltear un carácter de la firma
        bad_sig = ("b" if sig[0] != "b" else "c") + sig[1:]
        self.client.cookies.set(COOKIE_NAME, f"{raw}.{bad_sig}")
        self.assertEqual(self.client.get("/api/v1/telemetry/snapshot").status_code, 401)
        self.client.cookies.delete(COOKIE_NAME)

    def test_expired_session_rejected(self):
        # Token firmado correctamente pero con exp en el pasado
        import base64
        import hashlib
        import hmac as hmac_mod
        import json as json_mod

        payload = {
            "exp": int(time.time()) - 60,
            "scope": "full",
            "sid": "deadbeef" * 4,
        }
        raw = base64.urlsafe_b64encode(
            json_mod.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        key = hashlib.sha256(
            b"wazuh-waha-session-v1:" + settings.relay_api_key.encode()
        ).digest()
        sig = base64.urlsafe_b64encode(
            hmac_mod.new(key, raw.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()

        self.assertIsNone(verify_session(f"{raw}.{sig}"))
        self.client.cookies.set(COOKIE_NAME, f"{raw}.{sig}")
        self.assertEqual(self.client.get("/api/v1/telemetry/snapshot").status_code, 401)
        self.client.cookies.delete(COOKIE_NAME)


class TestKeyHandling(BaseAuthTest):
    def test_query_param_api_key_rejected(self):
        # ?api_key= quedaba en logs/historial: ya no autentica
        r = self.client.get(
            f"/api/v1/telemetry/snapshot?api_key={settings.relay_api_key}"
        )
        self.assertEqual(r.status_code, 401)

    def test_header_still_works_for_services(self):
        r = self.client.get(
            "/api/v1/telemetry/snapshot", headers={"X-Api-Key": settings.relay_api_key}
        )
        self.assertEqual(r.status_code, 200)

    def test_non_ascii_key_returns_401_not_500(self):
        r = self.client.get("/api/v1/telemetry/snapshot?api_key=ñññññññññññ")
        self.assertEqual(r.status_code, 401)


class TestRBAC(BaseAuthTest):
    def test_readonly_session_can_read(self):
        token = self.cookie_for(scope="read")
        self.client.cookies.set(COOKIE_NAME, token)
        self.assertEqual(self.client.get("/api/v1/telemetry/snapshot").status_code, 200)
        self.assertEqual(self.client.get("/debug/recent").status_code, 200)
        self.client.cookies.delete(COOKIE_NAME)

    def test_readonly_session_cannot_write(self):
        token = self.cookie_for(scope="read")
        self.client.cookies.set(COOKIE_NAME, token)
        r = self.client.post("/api/v1/telemetry/traffic/simulate", json={"level": 5})
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/api/v1/dashboard/toggle", json={})
        self.assertEqual(r.status_code, 403)
        self.client.cookies.delete(COOKIE_NAME)

    def test_full_session_can_write(self):
        token = self.cookie_for(scope="full")
        self.client.cookies.set(COOKIE_NAME, token)
        r = self.client.post("/api/v1/telemetry/traffic/simulate", json={"level": 5})
        self.assertEqual(r.status_code, 200)
        self.client.cookies.delete(COOKIE_NAME)


class TestRateLimitIdentity(unittest.TestCase):
    def test_xff_ignored_from_untrusted_peer(self):
        req = _make_request(
            [(b"x-forwarded-for", b"1.2.3.4")], peer="8.8.8.8"
        )
        # 8.8.8.8 no está en TRUSTED_PROXIES → se queda con el peer real
        self.assertEqual(main_mod._client_ip(req), "8.8.8.8")

    def test_xff_honored_from_trusted_proxy(self):
        req = _make_request(
            [(b"x-forwarded-for", b"1.2.3.4")], peer="127.0.0.1"
        )
        self.assertEqual(main_mod._client_ip(req), "1.2.3.4")

    def test_xff_chain_takes_first_untrusted_hop(self):
        # Cadena: cliente real → proxy confiable → peer
        req = _make_request(
            [(b"x-forwarded-for", b"1.2.3.4, 172.17.0.1")], peer="127.0.0.1"
        )
        self.assertEqual(main_mod._client_ip(req), "1.2.3.4")

    def test_sweep_prunes_empty_buckets(self):
        main_mod._RATE_LIMITS.clear()
        main_mod._last_sweep = time.monotonic() - 120  # forzar sweep
        old = time.monotonic() - 120
        main_mod._RATE_LIMITS["tel:1.1.1.1"].append(old)
        main_mod._rate_allow("tel:2.2.2.2", 10)
        self.assertNotIn("tel:1.1.1.1", main_mod._RATE_LIMITS)
        main_mod._RATE_LIMITS.clear()


class TestDocsDisabled(unittest.TestCase):
    def test_openapi_and_docs_disabled(self):
        client = TestClient(main_mod.app)
        self.assertEqual(client.get("/docs").status_code, 404)
        self.assertEqual(client.get("/openapi.json").status_code, 404)


if __name__ == "__main__":
    unittest.main()
