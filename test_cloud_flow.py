# test_cloud_flow.py
import json
import unittest
from api.index import app, init_db
from sentinel_core.machine_identity import load_or_create_identity

class TestCloudFlow(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()
        self.ident = load_or_create_identity()

    def test_full_cloud_auth_pairing_sync(self):
        # 1. Registro de usuário com vinculação do HWID da máquina
        email = "analista@sentinela.gov"
        pwd = "SenhaForteDefesa2026@"
        comp_id = self.ident["computer_id"]

        reg_res = self.client.post("/api/cloud/auth/register", json={
            "email": email,
            "password": pwd,
            "computer_id": comp_id
        })
        self.assertIn(reg_res.status_code, [200, 409])
        
        # 2. Login
        login_res = self.client.post("/api/cloud/auth/login", json={
            "email": email,
            "password": pwd
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.get_json()
        token = login_data["token"]
        self.assertTrue(token)
        
        # 3. Verifica dispositivos vinculados
        devs_res = self.client.get("/api/cloud/devices", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(devs_res.status_code, 200)
        devices = devs_res.get_json()["devices"]
        self.assertTrue(any(d["computer_id"] == comp_id for d in devices))
        sync_token = next(d["sync_token"] for d in devices if d["computer_id"] == comp_id)

        # 4. Ingestão de telemetria (Agente -> Nuvem)
        telemetry_payload = {
            "computer_id": comp_id,
            "hostname": self.ident["hostname"],
            "os": self.ident["os"],
            "health": {
                "status": "ONLINE",
                "cpu_percent": 14.5,
                "memory_percent": 42.1,
                "active_modules": 53
            },
            "stats": {
                "blocked_attacks": 7,
                "threat_score": 98
            },
            "recent_events": [
                {"type": "RANSOMWARE_BLOCK", "severity": "CRITICAL", "description": "Tentativa de injeção DLL bloqueada no LSASS"}
            ]
        }
        push_res = self.client.post(
            "/api/cloud/sync/push",
            json=telemetry_payload,
            headers={"X-Sentinel-Sync-Token": sync_token}
        )
        self.assertEqual(push_res.status_code, 200)

        # 5. Dashboard busca telemetria sincronizada da nuvem
        pull_res = self.client.get(
            f"/api/cloud/sync/pull?computer_id={comp_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(pull_res.status_code, 200)
        pull_data = pull_res.get_json()
        self.assertEqual(pull_data["status"], "success")
        self.assertEqual(pull_data["data"]["health"]["cpu_percent"], 14.5)
        self.assertEqual(pull_data["data"]["stats"]["blocked_attacks"], 7)
        print("[OK] Fluxo Cloud completo (Registro, HWID Pairing, Ingestao & Pull) VALIDADO com sucesso!")

if __name__ == "__main__":
    unittest.main()
