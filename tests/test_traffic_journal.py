"""Tests unitarios: journal de tráfico + normalización de eventos Wazuh."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from wazuh_waha.common.traffic_journal import TrafficJournal
from wazuh_waha.common.traffic_stream import normalize_wazuh_event


class TestNormalizeWazuhEvent(unittest.TestCase):
    def test_basic_fields(self):
        raw = {
            "timestamp": "2026-09-22T10:00:00.000+0000",
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "SSH brute force",
                "groups": ["sshd", "authentication_failed"],
                "mitre": {"id": ["T1110"], "technique": ["Brute Force"]},
            },
            "agent": {"id": "001", "name": "web-01"},
            "data": {"srcip": "10.0.0.5", "srcport": "44321", "user": "root"},
            "full_log": "Failed password for root from 10.0.0.5",
            "location": "/var/log/secure",
        }
        ev = normalize_wazuh_event(raw)
        self.assertEqual(ev["rule_id"], "5712")
        self.assertEqual(ev["level"], 10)
        self.assertEqual(ev["agent_name"], "web-01")
        self.assertEqual(ev["src_ip"], "10.0.0.5")
        self.assertEqual(ev["src_user"], "root")
        self.assertIn("T1110", ev["mitre_ids"])
        self.assertTrue(ev["id"])

    def test_safe_defaults(self):
        ev = normalize_wazuh_event({})
        self.assertEqual(ev["rule_id"], "0")
        self.assertEqual(ev["level"], 0)
        self.assertEqual(ev["agent_id"], "000")
        self.assertIsInstance(ev["mitre_ids"], list)


class TestTrafficJournal(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "traffic.jsonl"
        self.journal = TrafficJournal(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_append_and_tail(self):
        for i in range(5):
            self.journal.append({"id": f"e{i}", "level": i, "rule_id": str(100 + i)})
        items = self.journal.tail(limit=3)
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["id"], "e2")
        self.assertEqual(items[-1]["id"], "e4")

    def test_tail_empty_missing_file(self):
        j = TrafficJournal(Path(self._tmp.name) / "nope.jsonl")
        self.assertEqual(j.tail(10), [])

    def test_tail_skips_partial_lines(self):
        self.journal.append({"id": "full"})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write('{"id": "partial"')  # sin newline → incompleto
        items = self.journal.tail(10)
        ids = [i["id"] for i in items]
        self.assertIn("full", ids)
        self.assertNotIn("partial", ids)

    def test_read_new_lines_offset(self):
        self.journal.append({"id": "a"})
        fd, offset = self.journal.open_for_follow()
        try:
            # sin cambios
            off2, lines = TrafficJournal.read_new_lines(fd, offset)
            self.assertEqual(lines, [])
            self.journal.append({"id": "b"})
            off3, lines2 = TrafficJournal.read_new_lines(fd, off2)
            self.assertEqual(len(lines2), 1)
            self.assertEqual(json.loads(lines2[0])["id"], "b")
        finally:
            fd.close()


if __name__ == "__main__":
    unittest.main()
