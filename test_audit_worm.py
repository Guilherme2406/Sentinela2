# test_audit_worm.py
import os
import shutil
import sqlite3
import tempfile
import unittest
from sentinel_core.audit_log import AuditLogger
from sentinel_core.post_quantum_shield import PostQuantumShield


class TestAuditWORMAndHashChain(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="sentinel_audit_test_")
        self.db_path = os.path.join(self.tmp_dir, "test_audit.db")
        self.logger = AuditLogger(db_path=self.db_path)
        self.logger.worm_dir = os.path.join(self.tmp_dir, "worm_exports")
        os.makedirs(self.logger.worm_dir, exist_ok=True)
        self.pqc = PostQuantumShield(agent_id="TEST_AUDIT_AGENT")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_hash_chain_creation_and_integrity(self):
        # Registra 5 ações sequenciais
        id1 = self.logger.log_action("analyst1", "QUARANTINE_FILE", "malware.exe")
        id2 = self.logger.log_action("analyst2", "KILL_PROCESS", "cmd.exe", details={"pid": 1234})
        id3 = self.logger.log_action("analyst1", "BAN_IP", "198.51.100.22")
        id4 = self.logger.log_action("soc_lead", "ZTNA_LOCKDOWN", "HOST-A")
        id5 = self.logger.log_action("soc_lead", "RESOLVE_ALERT", "ALERT-101")

        self.assertEqual(id5, 5)

        # Verifica integridade da cadeia
        integrity = self.logger.verify_chain_integrity()
        self.assertTrue(integrity["valid"], f"Cadeia inválida: {integrity}")
        self.assertEqual(integrity["total_records"], 5)
        self.assertIsNotNone(integrity["latest_root_hash"])
        self.assertNotEqual(integrity["latest_root_hash"], "0" * 64)

    def test_tampering_detection(self):
        # Cria registros
        self.logger.log_action("user1", "ACTION_A", "target1")
        self.logger.log_action("user2", "ACTION_B", "target2")
        self.logger.log_action("user3", "ACTION_C", "target3")

        # Simula adulteração maliciosa diretamente no banco SQLite (sem usar a API)
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE audit_actions SET target = 'forged_target' WHERE id = 2")
        conn.commit()
        conn.close()

        # O verificador DEVE detectar a quebra criptográfica
        integrity = self.logger.verify_chain_integrity()
        self.assertFalse(integrity["valid"])
        self.assertEqual(integrity.get("tampered_id"), 2)

    def test_worm_package_export_with_pqc_seal(self):
        self.logger.log_action("analyst_alpha", "ISOLATE_NETWORK", "10.0.0.5")
        self.logger.log_action("analyst_beta", "EXPORT_FORENSICS", "MEM_DUMP_1")

        res = self.logger.export_worm_package(pqc_shield=self.pqc)
        self.assertEqual(res["status"], "success")
        self.assertTrue(os.path.exists(res["file_path"]))
        self.assertIn("WORM-AUDIT-", res["package_id"])
        self.assertEqual(res["records_exported"], 2)

        # Verifica assinatura PQC
        sig = res["pqc_signature"]
        self.assertIsNotNone(sig)
        self.assertTrue(sig.startswith("PQC_MLDSA87_V1:") or sig.startswith("PQC_DILITHIUM_V1:"))

        # Verifica listagem de arquivos WORM
        archives = self.logger.list_worm_archives()
        self.assertEqual(len(archives), 1)
        self.assertTrue(archives[0]["pqc_sealed"])
        self.assertEqual(archives[0]["record_count"], 2)


if __name__ == "__main__":
    unittest.main()
