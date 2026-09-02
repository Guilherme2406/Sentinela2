# sentinel_core/logger.py
import sqlite3
import threading
import logging
from contextlib import closing
from typing import List, Tuple, Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [SENTINEL-LOG] %(message)s'
)

class SecurityEventLogger:
    """Gerenciador de armazenamento seguro de logs de auditoria e segurança em SQLite."""
    
    def __init__(self, db_path: str = "sentinel_events.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        return conn

    def _init_db(self):
        with self._lock:
            with closing(self._get_connection()) as conn:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS security_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                            severity TEXT NOT NULL,
                            category TEXT NOT NULL,
                            target TEXT NOT NULL,
                            description TEXT NOT NULL
                        )
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON security_events(category)")

    def log_event(self, severity: str, category: str, target: str, description: str) -> int:
        with self._lock:
            with closing(self._get_connection()) as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO security_events (severity, category, target, description)
                        VALUES (?, ?, ?, ?)
                    """, (severity.upper(), category.upper(), str(target), str(description)))
                    return cursor.lastrowid or 0

    def get_recent_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            with closing(self._get_connection()) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, severity, category, target, description 
                    FROM security_events 
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]

    def get_filtered_events(self, severity: Optional[str] = None, category: Optional[str] = None, date_str: Optional[str] = None, search: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            with closing(self._get_connection()) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                query = "SELECT id, timestamp, severity, category, target, description FROM security_events WHERE 1=1"
                params: List[Any] = []
                if severity and severity.upper() != "ALL":
                    query += " AND severity = ?"
                    params.append(severity.upper())
                if category and category.upper() != "ALL":
                    query += " AND category = ?"
                    params.append(category.upper())
                if date_str and date_str.strip() and date_str.upper() != "ALL":
                    query += " AND date(timestamp) = ?"
                    params.append(date_str.strip())
                if search and search.strip():
                    query += " AND (target LIKE ? OR description LIKE ? OR category LIKE ?)"
                    term = f"%{search.strip()}%"
                    params.extend([term, term, term])
                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

    def get_available_categories(self) -> List[str]:
        with self._lock:
            with closing(self._get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT category FROM security_events ORDER BY category ASC")
                return [row[0] for row in cursor.fetchall() if row[0]]

    def get_available_dates(self) -> List[str]:
        with self._lock:
            with closing(self._get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT date(timestamp) FROM security_events ORDER BY date(timestamp) DESC LIMIT 30")
                return [row[0] for row in cursor.fetchall() if row[0]]

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            with closing(self._get_connection()) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM security_events")
                total = cursor.fetchone()[0]

                cursor.execute("SELECT severity, COUNT(*) FROM security_events GROUP BY severity")
                by_severity = dict(cursor.fetchall())

                cursor.execute("SELECT category, COUNT(*) FROM security_events GROUP BY category")
                by_category = dict(cursor.fetchall())

                return {
                    "total_events": total,
                    "by_severity": by_severity,
                    "by_category": by_category
                }

    def clear_events(self) -> int:
        with self._lock:
            with closing(self._get_connection()) as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM security_events")
                    return cursor.rowcount

    # Alias de compatibilidade
    def get_logs(self, category: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        return self.get_filtered_events(category=category, limit=limit)

    get_event_counts = get_stats

SentinelLogger = SecurityEventLogger


