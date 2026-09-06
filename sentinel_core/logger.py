# sentinel_core/logger.py
import sqlite3
import threading
import logging
from contextlib import closing
from typing import List, Tuple, Dict, Any, Optional

# NOTE: NÃO configuramos logging.basicConfig() aqui. Isso permite que cada
# ponto de entrada (main.py, sentinela_service.py, sentinel_cli.py) defina
# o destino real dos logs (console ou arquivo). Antes, o basicConfig deste
# módulo instalava um StreamHandler primeiro e os basicConfig() dos pontos
# de entrada eram ignorados — o que impedia, por exemplo, a gravação efetiva
# de logs do daemon em 'sentinel_daemon.log'.

class SecurityEventLogger:
    """Gerenciador de armazenamento seguro de logs de auditoria e segurança em SQLite."""
    
    def __init__(self, db_path: str = "sentinel_events.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=15)
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA cache_size = -8000;")
            conn.execute("PRAGMA temp_store = MEMORY;")
        except Exception:
            pass
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
        self._listeners: List = []
        # Purge de inicialização para manter o banco leve e veloz
        try:
            self.rotate_and_purge_old_events()
        except Exception:
            pass

    def add_listener(self, fn) -> None:
        """Registra um callback para ser notificado instantaneamente a cada novo evento gravado."""
        if fn not in self._listeners:
            self._listeners.append(fn)

    def log_event(self, severity: str, category: str, target: str, description: str) -> int:
        event_id = 0
        with self._lock:
            with closing(self._get_connection()) as conn:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO security_events (severity, category, target, description)
                        VALUES (?, ?, ?, ?)
                    """, (severity.upper(), category.upper(), str(target), str(description)))
                    event_id = cursor.lastrowid or 0

        for listener in list(self._listeners):
            try:
                listener(severity.upper(), category.upper(), str(target), str(description), event_id)
            except Exception:
                pass

        return event_id

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

    def rotate_and_purge_old_events(self, max_records: int = 25000, days: int = 30) -> int:
        """Limpa eventos antigos além do limite de retenção (por dias ou quantidade máxima)."""
        with self._lock:
            with closing(self._get_connection()) as conn:
                with conn:
                    cursor = conn.cursor()
                    # 1. Deletar eventos anteriores ao período de retenção
                    cursor.execute("DELETE FROM security_events WHERE timestamp < datetime('now', '-' || ? || ' days')", (days,))
                    purged = cursor.rowcount or 0
                    
                    # 2. Deletar excedente além de 'max_records'
                    cursor.execute("SELECT COUNT(*) FROM security_events")
                    row = cursor.fetchone()
                    total = row[0] if row else 0
                    if total > max_records:
                        excess = total - max_records
                        cursor.execute("""
                            DELETE FROM security_events WHERE id IN (
                                SELECT id FROM security_events ORDER BY id ASC LIMIT ?
                            )
                        """, (excess,))
                        purged += (cursor.rowcount or 0)
                    return purged

    def vacuum_database(self) -> bool:
        """Executa VACUUM no banco SQLite para desfragmentar e devolver espaço ao disco do SO."""
        with self._lock:
            conn = None
            try:
                conn = self._get_connection()
                conn.isolation_level = None  # Requer autocommit
                conn.execute("VACUUM;")
                return True
            except Exception as e:
                logging.warning(f"[LOGGER] Erro ao executar VACUUM: {e}")
                return False
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass


    # Alias de compatibilidade
    def get_logs(self, category: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        return self.get_filtered_events(category=category, limit=limit)

    get_event_counts = get_stats

SentinelLogger = SecurityEventLogger


