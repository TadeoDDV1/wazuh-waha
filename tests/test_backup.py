import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wazuh_waha.common.backup import get_backup_dir, list_backups, save_alert_backup


class TestBackup(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_list_backup(self):
        with patch("wazuh_waha.common.backup.get_backup_dir", return_value=Path(self.test_dir)):
            record = {
                "rule_id": "5710",
                "level": 5,
                "agent_id": "001",
                "agent_name": "test-agent",
                "description": "sshd: Attempt to login using a non-existent user",
                "result": "sent",
                "decision": "rule_id:5710",
            }
            raw_alert = {"rule": {"id": "5710"}, "agent": {"id": "001"}}

            saved_path = save_alert_backup(record, raw_alert)
            self.assertIsNotNone(saved_path)
            self.assertTrue(saved_path.exists())

            # Read back
            with open(saved_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 1)

            data = json.loads(lines[0])
            self.assertEqual(data["rule_id"], "5710")
            self.assertEqual(data["raw_alert"], raw_alert)
            self.assertIn("backup_ts", data)

            # Test list_backups
            summary = list_backups(limit_files=5)
            self.assertEqual(summary["total_files"], 1)
            self.assertEqual(summary["files"][0]["total_records"], 1)
            self.assertEqual(summary["files"][0]["recent_samples"][0]["rule_id"], "5710")


if __name__ == "__main__":
    unittest.main()
