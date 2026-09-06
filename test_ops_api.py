# test_ops_api.py
import unittest
import json
from sentinel_api import app, rbac_engine


class TestOpsApiEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        # Garante perfil admin para permissões
        rbac_engine.switch_profile("admin")

    def test_health_telemetry_mode(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "ONLINE")
        self.assertIn("telemetry_mode", data)
        self.assertIn("privilege_status", data)
        self.assertIn("is_degraded", data)

    def test_sysmon_installer_status_endpoint(self):
        res = self.client.get("/api/sysmon/installer-status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("diagnostic", data)
        diag = data["diagnostic"]
        self.assertIn("platform_windows", diag)
        self.assertIn("recommendation", diag)

    def test_soc_export_audit_endpoint(self):
        res = self.client.get("/api/soc/export-audit?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("package_id", data)
        self.assertIn("pqc_signature", data)
        self.assertIn("chain_root_hash", data)

    def test_soc_export_audit_ship_and_history(self):
        # Ship
        res = self.client.post("/api/soc/export-audit/ship", json={"limit": 50})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertIn("WORM-AUDIT-", data["package_id"])

        # History
        hist_res = self.client.get("/api/soc/export-audit/history")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.get_json()
        self.assertEqual(hist_data.get("status"), "success")
        self.assertGreaterEqual(hist_data.get("total_archives", 0), 1)
        self.assertTrue(hist_data["chain_integrity"]["valid"])


if __name__ == "__main__":
    unittest.main()
