"""Tests para el motor de clasificación de sitios web, dominios y destinos de red por agente."""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from wazuh_waha import main as main_mod
from wazuh_waha.api import telemetry as tel_mod
from wazuh_waha.config import settings

AUTH = {"X-Api-Key": settings.relay_api_key}


class TestNetworkSiteClassification(unittest.TestCase):
    def test_classify_google_dns(self):
        res = tel_mod._classify_network_site("8.8.8.8", 53, "dns.google", "NetworkManager")
        self.assertEqual(res["category"], "dns")
        self.assertIn("Google", res["site_name"])
        self.assertFalse(res["is_web"])

    def test_classify_google_web(self):
        res = tel_mod._classify_network_site("142.250.190.46", 443, "mad08s04-in-f14.1e100.net", "firefox")
        self.assertEqual(res["category"], "web")
        self.assertIn("Google", res["site_name"])
        self.assertTrue(res["is_web"])

    def test_classify_github(self):
        res = tel_mod._classify_network_site("140.82.121.4", 443, "github.com", "git")
        self.assertEqual(res["category"], "web")
        self.assertIn("GitHub", res["site_name"])
        self.assertTrue(res["is_web"])

    def test_classify_telegram(self):
        res = tel_mod._classify_network_site("149.154.166.110", 443, "", "python3")
        self.assertEqual(res["category"], "messaging")
        self.assertIn("Telegram", res["site_name"])

    def test_classify_wazuh_remoted(self):
        res = tel_mod._classify_network_site("192.168.122.142", 1514, "wazuh-manager.local", "wazuh-agentd")
        self.assertEqual(res["category"], "sync")
        self.assertIn("Wazuh", res["site_name"])

    def test_classify_ssh(self):
        res = tel_mod._classify_network_site("192.168.122.1", 22, "gateway.local", "sshd")
        self.assertEqual(res["category"], "ssh")

    def test_classify_youtube_cdn_subnet(self):
        res = tel_mod._classify_network_site("142.251.153.4", 443, "", "chrome")
        self.assertEqual(res["category"], "web")
        self.assertIn("YouTube", res["site_name"])
        self.assertTrue(res["is_web"])

    def test_classify_youtube_video_stream(self):
        res = tel_mod._classify_network_site("192.178.56.86", 443, "", "chrome")
        self.assertEqual(res["category"], "web")
        self.assertIn("YouTube", res["site_name"])
        self.assertTrue(res["is_web"])


class TestNetworkSitesEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main_mod.app)

    def test_sites_endpoint_auth_required(self):
        r = self.client.get("/api/v1/telemetry/network/sites")
        self.assertEqual(r.status_code, 401)

    def test_sites_endpoint_success_and_no_localhost(self):
        r = self.client.get("/api/v1/telemetry/network/sites?agent_id=all", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data.get("ok"))
        self.assertIn("sites", data)
        self.assertIn("lan_devices", data)
        self.assertIn("total_sites", data)
        self.assertIn("web_sites_count", data)

        # Verificar que ningún sitio en sites_activity sea localhost o servicio interno
        for s in data["sites"]:
            self.assertNotEqual(s.get("category"), "local", f"Sitio no debe ser local: {s}")
            self.assertNotIn(s.get("remote_ip"), ("127.0.0.1", "::1", "localhost", "::0", "0.0.0.0"))

    def test_agent_traffic_endpoint_contains_sites(self):
        r = self.client.get("/api/v1/telemetry/agents/000/traffic", headers=AUTH)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data.get("ok"))
        self.assertIn("sites_activity", data)
        self.assertIn("ports", data)
        self.assertIn("kpis", data)

    def test_network_stream_auth_and_cap(self):
        r_unauth = self.client.get("/api/v1/telemetry/network/stream")
        self.assertEqual(r_unauth.status_code, 401)

        old = tel_mod._network_sse_count
        tel_mod._network_sse_count = tel_mod._NETWORK_SSE_MAX
        try:
            r_cap = self.client.get("/api/v1/telemetry/network/stream", headers=AUTH)
            self.assertEqual(r_cap.status_code, 503)
        finally:
            tel_mod._network_sse_count = old


class TestTelegramBotSitesCommand(unittest.IsolatedAsyncioTestCase):
    async def test_sitios_command(self):
        from wazuh_waha.infrastructure.telegram_bot import process_admin_command
        res = await process_admin_command("/sitios")
        self.assertTrue("SITIOS Y ACTIVIDAD WEB" in res or "No se registran destinos externos" in res)


if __name__ == "__main__":
    unittest.main()
