import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from wazuh_waha.main import app
from wazuh_waha.config import settings


class TestAlertsBackup(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.client = TestClient(app)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("wazuh_waha.infrastructure.waha_client.send_text", new_callable=AsyncMock)
    def test_alert_saves_backup(self, mock_send):
        mock_send.return_value = {"id": {"id": "waha-msg-12345"}}

        with patch("wazuh_waha.common.backup.get_backup_dir", return_value=Path(self.test_dir)):
            # Unique agent per test run to avoid TTL dedup
            agent_id = f"test_{int(time.time() * 1000)}"
            payload = {
                "rule": {"id": "5710", "level": 5, "description": "SSH failed"},
                "agent": {"id": agent_id, "name": "arch-pc"},
                "timestamp": "2026-09-07T22:45:00.000Z",
            }
            resp = self.client.post(
                "/alerts",
                headers={"X-Api-Key": settings.relay_api_key},
                json=payload,
            )
            self.assertEqual(resp.status_code, 200)

            # Check that backup file was created
            backup_files = list(Path(self.test_dir).glob("alerts-*.jsonl"))
            self.assertEqual(len(backup_files), 1)

            with open(backup_files[0], "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1)

            record = json.loads(lines[0])
            self.assertEqual(record["rule_id"], "5710")
            self.assertEqual(record["agent_name"], "arch-pc")
            self.assertEqual(record["result"], "sent")
            self.assertEqual(record["raw_alert"]["rule"]["id"], "5710")


if __name__ == "__main__":
    unittest.main()
