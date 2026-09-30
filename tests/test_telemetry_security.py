"""Tests de seguridad de la telemetría en vivo: validación, caps SSE, body limit."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from wazuh_waha import main as main_mod
from wazuh_waha.api import telemetry as tel_mod
from wazuh_waha.common import audit as audit_mod, traffic_journal as tj_mod
from wazuh_waha.common.audit import AuditLog
from wazuh_waha.common.session import COOKIE_NAME, issue_session
from wazuh_waha.common.traffic_journal import TrafficJournal
from wazuh_waha.common.traffic_stream import TrafficStreamWatcher, normalize_wazuh_event
from wazuh_waha.config import settings

AUTH = {"X-Api-Key": settings.relay_api_key}


class BaseTelTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self._old_audit = audit_mod._audit
        self._old_journal = tj_mod._journal
        audit_mod._audit = AuditLog(tmp / "audit.jsonl")
        tj_mod._journal = TrafficJournal(tmp / "traffic.jsonl")
        main_mod._RATE_LIMITS.clear()
        self.client = TestClient(main_mod.app)

    def tearDown(self):
        audit_mod._audit = self._old_audit
        tj_mod._journal = self._old_journal
        main_mod._RATE_LIMITS.clear()
        self._tmp.cleanup()


class TestSimulateValidation(BaseTelTest):
    URL = "/api/v1/telemetry/traffic/simulate"

    def test_ok(self):
        r = self.client.post(self.URL, json={"level": 5}, headers=AUTH)
        self.assertEqual(r.status_code, 200)

    def test_requires_auth(self):
        r = self.client.post(self.URL, json={"level": 5})
        self.assertEqual(r.status_code, 401)

    def test_level_out_of_range(self):
        r = self.client.post(self.URL, json={"level": 99}, headers=AUTH)
        self.assertEqual(r.status_code, 422)

    def test_level_not_int(self):
        r = self.client.post(self.URL, json={"level": "abc"}, headers=AUTH)
        self.assertEqual(r.status_code, 422)

    def test_description_too_long(self):
        r = self.client.post(
            self.URL, json={"description": "x" * 10_000}, headers=AUTH
        )
        self.assertEqual(r.status_code, 422)

    def test_rule_id_must_be_numeric(self):
        r = self.client.post(
            self.URL, json={"rule_id": "DROP TABLE; --"}, headers=AUTH
        )
        self.assertEqual(r.status_code, 422)

    def test_src_ip_length_capped(self):
        r = self.client.post(
            self.URL, json={"src_ip": "9" * 100}, headers=AUTH
        )
        self.assertEqual(r.status_code, 422)

    def test_missing_body_uses_defaults(self):
        r = self.client.post(self.URL, content=b"no-json", headers=AUTH)
        # body inválido no es 500: FastAPI responde 422 o usa defaults
        self.assertIn(r.status_code, (200, 422))


class TestTrafficTailLimit(BaseTelTest):
    def test_limit_clamped(self):
        r = self.client.get(
            "/api/v1/telemetry/traffic/tail?limit=999999999", headers=AUTH
        )
        self.assertEqual(r.status_code, 200)
        self.assertLessEqual(r.json()["count"], 400)

    def test_limit_zero_clamped(self):
        r = self.client.get("/api/v1/telemetry/traffic/tail?limit=0", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json()["count"], 0)


class TestSSECaps(BaseTelTest):
    def test_snapshot_stream_cap_returns_503(self):
        old = tel_mod._sse_client_count
        tel_mod._sse_client_count = tel_mod._SSE_MAX_CLIENTS
        try:
            r = self.client.get("/api/v1/telemetry/stream", headers=AUTH)
            self.assertEqual(r.status_code, 503)
        finally:
            tel_mod._sse_client_count = old

    def test_traffic_stream_cap_returns_503(self):
        old = tel_mod._traffic_sse_count
        tel_mod._traffic_sse_count = tel_mod._TRAFFIC_SSE_MAX
        try:
            r = self.client.get("/api/v1/telemetry/traffic/stream", headers=AUTH)
            self.assertEqual(r.status_code, 503)
        finally:
            tel_mod._traffic_sse_count = old

    def test_traffic_stream_requires_auth(self):
        r = self.client.get("/api/v1/telemetry/traffic/stream")
        self.assertEqual(r.status_code, 401)


class TestBodyLimit(BaseTelTest):
    def test_oversized_content_length_413(self):
        payload = b"x" * (settings.max_body_bytes + 1)
        r = self.client.post("/alerts", content=payload, headers=AUTH)
        self.assertEqual(r.status_code, 413)

    def test_small_body_not_413(self):
        payload = b'{"rule": {"id": "1"}}'
        r = self.client.post("/alerts", content=payload, headers=AUTH)
        self.assertNotEqual(r.status_code, 413)

    def test_chunked_oversized_413(self):
        # Sin Content-Length: el límite sigue aplicando byte a byte
        chunk = b"y" * 65536
        n = (settings.max_body_bytes // len(chunk)) + 2
        r = self.client.post(
            "/alerts",
            content=(chunk for _ in range(n)),
            headers={**AUTH, "Content-Type": "application/json"},
        )
        self.assertEqual(r.status_code, 413)


class TestAuditTrail(BaseTelTest):
    def test_mutation_writes_audit_line(self):
        token, _ = issue_session("full")
        self.client.cookies.set(COOKIE_NAME, token)
        r = self.client.post(
            "/api/v1/telemetry/traffic/simulate", json={"level": 7}
        )
        self.assertEqual(r.status_code, 200)

        lines = (Path(self._tmp.name) / "audit.jsonl").read_text().splitlines()
        entries = [json.loads(l) for l in lines if l.strip()]
        match = [e for e in entries if e["path"] == "/api/v1/telemetry/traffic/simulate"]
        self.assertTrue(match, entries)
        self.assertEqual(match[-1]["status"], 200)
        self.assertEqual(match[-1]["scope"], "full")
        self.assertNotEqual(match[-1]["sid"], "-")

    def test_login_failure_writes_audit_line(self):
        r = self.client.post("/api/v1/auth/login", json={"api_key": "k" * 48})
        self.assertEqual(r.status_code, 401)
        lines = (Path(self._tmp.name) / "audit.jsonl").read_text().splitlines()
        entries = [json.loads(l) for l in lines if l.strip()]
        self.assertTrue(
            any(
                e["path"] == "/api/v1/auth/login" and e["status"] == 401
                for e in entries
            ),
            entries,
        )


class TestDataMinimization(unittest.TestCase):
    def test_full_log_clipped(self):
        ev = normalize_wazuh_event({"full_log": "A" * 100_000})
        self.assertLessEqual(len(ev["full_log"]), 2100)
        self.assertIn("truncado", ev["full_log"])

    def test_raw_json_bounded(self):
        raw = {
            "rule": {"id": "550", "level": 12, "description": "huge"},
            "full_log": "Z" * 500_000,
            "other": "B" * 100_000,
        }
        ev = normalize_wazuh_event(raw)
        size = len(json.dumps(ev["raw_json"], ensure_ascii=False, default=str))
        self.assertLessEqual(size, 8 * 1024 + 512)

    def test_original_dict_not_mutated(self):
        raw = {"full_log": "A" * 10_000}
        normalize_wazuh_event(raw)
        self.assertEqual(len(raw["full_log"]), 10_000)

    def test_small_event_keeps_fields(self):
        raw = {
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "full_log": "Failed password",
            "agent": {"id": "001", "name": "web-01"},
        }
        ev = normalize_wazuh_event(raw)
        self.assertEqual(ev["raw_json"]["rule"]["id"], "5712")
        self.assertEqual(ev["full_log"], "Failed password")


class TestSSHStrictHostKey(unittest.TestCase):
    def _cmd(self, strict_value: str) -> list[str]:
        watcher = TrafficStreamWatcher.__new__(TrafficStreamWatcher)
        with mock.patch.object(settings, "wazuh_vm_ssh_strict_host_key", strict_value):
            return watcher._ssh_base_cmd()

    def test_strict_yes(self):
        cmd = self._cmd("yes")
        self.assertIn("StrictHostKeyChecking=yes", cmd)

    def test_invalid_value_falls_back_to_accept_new(self):
        cmd = self._cmd("yes; rm -rf /")
        self.assertIn("StrictHostKeyChecking=accept-new", cmd)

    def test_batch_mode_always_on(self):
        cmd = self._cmd("accept-new")
        self.assertIn("BatchMode=yes", cmd)


if __name__ == "__main__":
    unittest.main()
