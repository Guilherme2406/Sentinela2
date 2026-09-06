# test_soc_ops.py
"""
Testes da camada SOC/Operações:
  - Fila de alertas com ciclo NEW -> ASSIGNED -> INVESTIGATING -> CONTAINED -> CLOSED
  - SLAs por severidade; detecção de SLA breached
  - Métricas MTTA/MTTR
  - Auditoria global de ações (quem/quando/o quê/ip)
Executar:  python test_soc_ops.py
"""
import os
import tempfile
import time
import unittest

from sentinel_core.soc_ops import SOCAlertQueue, SOC_SLA_MINUTES
from sentinel_core.audit_log import AuditLogger


class TestSOCAlertQueue(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.queue = SOCAlertQueue(db_path=os.path.join(self.tmpdir, "soc_alerts.db"))

    def test_01_create_alert_with_sla(self):
        alert = self.queue.create_alert(
            title="Possível exfiltração de dados", severity="CRITICAL",
            description="MTP de 40MB para IP externo desconhecido",
            ioc="203.0.113.50",
        )
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["status"], "NEW")
        self.assertAlmostEqual(
            alert["sla_deadline"] - alert["created_at"],
            SOC_SLA_MINUTES["CRITICAL"] * 60, delta=2,
        )

    def test_02_lifecycle_full(self):
        alert = self.queue.create_alert(title="Injeção remota", severity="HIGH")
        self.assertEqual(alert["status"], "NEW")

        assigned = self.queue.assign_alert(alert["id"], "ana.soc")
        self.assertEqual(assigned["status"], "ASSIGNED")
        self.assertEqual(assigned["assignee"], "ana.soc")
        self.assertIsNotNone(assigned["assigned_at"])

        investing = self.queue.set_status(alert["id"], "INVESTIGATING")
        self.assertEqual(investing["status"], "INVESTIGATING")

        contained = self.queue.set_status(alert["id"], "CONTAINED")
        self.assertEqual(contained["status"], "CONTAINED")
        self.assertIsNotNone(contained["contained_at"])

        closed = self.queue.close_alert(alert["id"], resolution="Isolado e revertido.")
        self.assertEqual(closed["status"], "CLOSED")
        self.assertIsNotNone(closed["closed_at"])
        self.assertEqual(closed["details"]["resolution"], "Isolado e revertido.")

    def test_03_invalid_status_rejected(self):
        alert = self.queue.create_alert(title="T", severity="LOW")
        with self.assertRaises(ValueError):
            self.queue.set_status(alert["id"], "NOT_A_STATUS")

    def test_04_expired_sla_detection(self):
        alert = self.queue.create_alert(title="Lento de responder", severity="MEDIUM")
        with self.queue._connect() as conn:
            conn.execute(
                "UPDATE soc_alerts SET created_at = ?, sla_deadline = ? WHERE id = ?",
                (time.time() - 100_000, time.time() - 10, alert["id"]),
            )
        breached = self.queue.sla_breached_alerts()
        ids = [a["id"] for a in breached]
        self.assertIn(alert["id"], ids)

    def test_05_metrics_mttr(self):
        a1 = self.queue.create_alert(title="A1", severity="MEDIUM")
        self.queue.close_alert(a1["id"])
        a2 = self.queue.create_alert(title="A2", severity="CRITICAL")
        self.queue.close_alert(a2["id"])

        m = self.queue.metrics()
        self.assertEqual(m["total_alerts"], 2)
        self.assertEqual(m["by_status"]["CLOSED"], 2)
        self.assertGreaterEqual(m["mttr_avg_seconds"], 0)
        self.assertIn("mtta_avg_seconds", m)
        self.assertIn("sla_breached_count", m)

    def test_06_list_filters(self):
        self.queue.create_alert(title="X1", severity="CRITICAL")
        self.queue.create_alert(title="X2", severity="LOW")
        crit = self.queue.list_alerts(severity="CRITICAL")
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "CRITICAL")


class TestAuditLogger(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.audit = AuditLogger(db_path=os.path.join(self.tmpdir, "audit_actions.db"))

    def test_01_log_and_list(self):
        aid = self.audit.log_action(
            user="admin", action="QUARANTINE", target="C:\\temp\\eicar.com",
            ip="127.0.0.1", details={"rule": "EICAR"},
            request_path="/api/quarantine", request_method="POST",
        )
        self.assertGreater(aid, 0)
        self.audit.log_action(user="admin", action="KILL_PROCESS", target="pid:4120", ip="127.0.0.1")
        rows = self.audit.list_actions()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["action"], "KILL_PROCESS")  # ordem DESC

    def test_02_stats(self):
        self.audit.log_action(user="ana", action="ASSIGN_ALERT", target="1")
        self.audit.log_action(user="ana", action="CLOSE_CASE", target="1")
        stats = self.audit.stats()
        self.assertEqual(stats["total_actions"], 2)
        self.assertEqual(stats["by_user"]["ana"], 2)
        self.assertIn("CLOSE_CASE", stats["by_action"])

    def test_03_filter_by_user_and_action(self):
        self.audit.log_action(user="bob", action="CONTAIN", target="3")
        self.audit.log_action(user="alice", action="CONTAIN", target="4")
        only_bob = self.audit.list_actions(user="bob")
        self.assertEqual(len(only_bob), 1)
        contain = self.audit.list_actions(action="CONTAIN")
        self.assertEqual(len(contain), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)