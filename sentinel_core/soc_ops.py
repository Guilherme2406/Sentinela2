# sentinel_core/soc_ops.py
"""
Fila de Alertas SOC com SLAs por severidade.

Ciclo de vida:  NEW -> ASSIGNED -> INVESTIGATING -> CONTAINED -> CLOSED
  - SLA (deadline) por severidade: CRITICAL=15min, HIGH=60min, MEDIUM=240min, LOW=1440min.
  - Atribuição, transições com timestamps, violação de SLA e métricas MTTA/MTTR.
Persistência: SQLite (`sentinel_vault/soc_alerts.db`), thread-safe.
"""
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

SOC_ALERT_STATUS = ("NEW", "ASSIGNED", "INVESTIGATING", "CONTAINED", "CLOSED")
SOC_ALERT_PRIORITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SOC_SLA_MINUTES = {"LOW": 1440, "MEDIUM": 240, "HIGH": 60, "CRITICAL": 15}


class SOCAlertQueue:
    """Fila de alertas SOC com SLAs e métricas (MTTA/MTTR)."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            vault_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "sentinel_vault",
            )
            os.makedirs(vault_dir, exist_ok=True)
            db_path = os.path.join(vault_dir, "soc_alerts.db")
        self.db_path = db_path
        self._lock = threading.RLock()
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS soc_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        description TEXT,
                        severity TEXT NOT NULL DEFAULT 'MEDIUM',
                        status TEXT NOT NULL DEFAULT 'NEW',
                        source TEXT,
                        assignee TEXT,
                        playbook_id TEXT,
                        ioc TEXT,
                        details TEXT,
                        created_at REAL,
                        assigned_at REAL,
                        contained_at REAL,
                        closed_at REAL,
                        sla_deadline REAL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_soc_status ON soc_alerts(status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_soc_severity ON soc_alerts(severity)")
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------ create
    def create_alert(self, title: str, severity: str = "MEDIUM",
                     description: str = "", source: str = "manual",
                     ioc: Optional[str] = None,
                     details: Optional[Dict[str, Any]] = None,
                     assignee: Optional[str] = None) -> Dict[str, Any]:
        """Cria um alerta na fila com SLA calculado pela severidade."""
        severity = severity.upper() if severity.upper() in SOC_ALERT_PRIORITIES else "MEDIUM"
        now = time.time()
        sla_deadline = now + (SOC_SLA_MINUTES.get(severity, 240) * 60)
        status = "ASSIGNED" if assignee else "NEW"
        details_json = json.dumps(details, ensure_ascii=False) if details is not None else None
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO soc_alerts "
                    "(title, description, severity, status, source, assignee, ioc, details, "
                    "created_at, assigned_at, sla_deadline) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (title, description, severity, status, source, assignee, ioc,
                     details_json, now, now if assignee else None, sla_deadline),
                )
                alert_id = cur.lastrowid
                conn.commit()
            finally:
                conn.close()
        return self.get_alert(alert_id)

    # ------------------------------------------------------------------- read
    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM soc_alerts WHERE id = ?", (alert_id,)
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_alerts(self, status: Optional[str] = None,
                    severity: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM soc_alerts WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(query, params).fetchall()
            finally:
                conn.close()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        if data.get("details"):
            try:
                data["details"] = json.loads(data["details"])
            except Exception:
                pass
        return data

    # ------------------------------------------------------------- transicoes
    def assign_alert(self, alert_id: int, assignee: str) -> Optional[Dict[str, Any]]:
        """Atribui o alerta a um analista (ASSIGNED)."""
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "UPDATE soc_alerts SET assignee = ?, status = 'ASSIGNED', assigned_at = ? "
                    "WHERE id = ?",
                    (assignee, now, alert_id),
                )
                conn.commit()
            finally:
                conn.close()
        if cur.rowcount == 0:
            return None
        return self.get_alert(alert_id)

    def set_status(self, alert_id: int, status: str) -> Optional[Dict[str, Any]]:
        """Transição manual de estado com timestamps correspondentes."""
        status = status.upper()
        if status not in SOC_ALERT_STATUS:
            raise ValueError(f"Status inválido: {status}. Válidos: {SOC_ALERT_STATUS}")
        now = time.time()
        set_cols = "status = ?"
        params: list = [status]
        if status == "CONTAINED":
            set_cols += ", contained_at = ?"
            params.append(now)
        elif status == "CLOSED":
            set_cols += ", closed_at = ?"
            params.append(now)
        params.append(alert_id)
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    f"UPDATE soc_alerts SET {set_cols} WHERE id = ?",
                    params,
                )
                conn.commit()
            finally:
                conn.close()
        if cur.rowcount == 0:
            return None
        return self.get_alert(alert_id)

    def close_alert(self, alert_id: int, resolution: str = "") -> Optional[Dict[str, Any]]:
        """Encerra o caso (CLOSED) registrando a resolução no detalhe."""
        alert = self.get_alert(alert_id)
        if alert is None:
            return None
        details = alert.get("details") or {}
        if isinstance(details, dict) and resolution:
            details["resolution"] = resolution
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE soc_alerts SET status = 'CLOSED', closed_at = ?, details = ? WHERE id = ?",
                    (time.time(), json.dumps(details, ensure_ascii=False) if details else None, alert_id),
                )
                conn.commit()
            finally:
                conn.close()
        return self.get_alert(alert_id)

    def sla_breached_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Alertas ainda abertos cujo SLA/deadline já expirou."""
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM soc_alerts WHERE status != 'CLOSED' AND sla_deadline < ? "
                    "ORDER BY sla_deadline ASC LIMIT ?",
                    (now, limit),
                ).fetchall()
            finally:
                conn.close()
        return [self._row_to_dict(r) for r in rows]

    # --------------------------------------------------------------- metricas
    def metrics(self) -> Dict[str, Any]:
        """KPIs operacionais do SOC: fila por status/severidade, MTTA e MTTR."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM soc_alerts").fetchall()
            finally:
                conn.close()

        by_status = {s: 0 for s in SOC_ALERT_STATUS}
        by_severity = {s: 0 for s in SOC_ALERT_PRIORITIES}
        for r in rows:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1

        # MTTA: média de (assigned_at - created_at) para alertas atribuídos
        mtta_values = [
            r["assigned_at"] - r["created_at"]
            for r in rows if r["assigned_at"] and r["created_at"]
        ]
        # MTTR: média de (closed_at - created_at) para alertas encerrados
        mttr_values = [
            r["closed_at"] - r["created_at"]
            for r in rows if r["closed_at"] and r["created_at"]
        ]

        open_rows = [r for r in rows if r["status"] != "CLOSED"]
        now = time.time()
        avg_queue_age = (
            sum(now - r["created_at"] for r in open_rows) / len(open_rows)
            if open_rows else 0.0
        )

        return {
            "total_alerts": len(rows),
            "by_status": by_status,
            "by_severity": by_severity,
            "mtta_avg_seconds": round(sum(mtta_values) / len(mtta_values), 2) if mtta_values else 0.0,
            "mttr_avg_seconds": round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else 0.0,
            "avg_open_queue_age_seconds": round(avg_queue_age, 2),
            "sla_breached_count": len(self.sla_breached_alerts()),
        }