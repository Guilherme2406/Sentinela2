# sentinel_core/db_postgres.py
"""
Módulo Oficial de Persistência PostgreSQL para o SENTINEL XDR.
Gerencia conexão, pool, tabelas de usuários, dispositivos (HWID),
auditoria SIEM e telemetria em tempo real com auto-migração e fallback.
"""

import os
import sys
import json
import time
import datetime
import logging
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("sentinel_postgres")

DEFAULT_PG_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://guilherme:150764@167.249.121.40:5432/db_guilherme"
)

# Detecta drivers disponíveis (psycopg2 ou pg8000)
HAS_PSYCOPG2 = False
HAS_PG8000 = False

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    pass

try:
    import pg8000.native
    HAS_PG8000 = True
except ImportError:
    pass

class PostgresManager:
    def __init__(self, db_url: str = DEFAULT_PG_URL, connect_timeout: int = 3):
        self.db_url = db_url
        self.connect_timeout = connect_timeout
        self.parsed = urlparse(db_url)
        self._connected = False
        self._initialized = False
        self._last_error = ""

    def get_connection(self):
        """Abre conexão com o PostgreSQL utilizando o melhor driver disponível."""
        if HAS_PSYCOPG2:
            try:
                conn = psycopg2.connect(
                    self.db_url,
                    connect_timeout=self.connect_timeout
                )
                return conn, "psycopg2"
            except Exception as e:
                self._last_error = str(e)
                logger.debug("Falha ao conectar via psycopg2: %s", e)

        if HAS_PG8000:
            try:
                user = self.parsed.username or "guilherme"
                password = self.parsed.password or ""
                host = self.parsed.hostname or "localhost"
                port = self.parsed.port or 5432
                database = self.parsed.path.lstrip("/") or "postgres"

                conn = pg8000.native.Connection(
                    user=user,
                    password=password,
                    host=host,
                    port=port,
                    database=database,
                    timeout=self.connect_timeout
                )
                return conn, "pg8000"
            except Exception as e:
                self._last_error = str(e)
                logger.debug("Falha ao conectar via pg8000: %s", e)

        raise ConnectionError(f"Não foi possível conectar ao PostgreSQL em {self.parsed.hostname}:{self.parsed.port} ({self._last_error or 'timeout'})")

    def test_connection(self) -> Tuple[bool, str]:
        """Testa se a conexão com o banco de dados está funcional."""
        try:
            conn, driver = self.get_connection()
            if driver == "psycopg2":
                with conn.cursor() as cur:
                    cur.execute("SELECT version();")
                    ver = cur.fetchone()[0]
                conn.close()
                self._connected = True
                return True, f"Conectado via {driver}: {ver}"
            elif driver == "pg8000":
                res = conn.run("SELECT version();")
                conn.close()
                ver = res[0][0] if res else "OK"
                self._connected = True
                return True, f"Conectado via {driver}: {ver}"
        except Exception as e:
            self._connected = False
            self._last_error = str(e)
            return False, str(e)
        return False, "Nenhum driver compatível instalado"

    def get_status(self) -> Dict[str, Any]:
        """Retorna o estado detalhado da conexão com o PostgreSQL para diagnóstico."""
        ok, msg = self.test_connection()
        return {
            "configured": True,
            "connected": ok,
            "host": self.parsed.hostname,
            "port": self.parsed.port or 5432,
            "database": self.parsed.path.lstrip("/"),
            "user": self.parsed.username,
            "drivers": {
                "psycopg2": HAS_PSYCOPG2,
                "pg8000": HAS_PG8000
            },
            "status_message": msg,
            "error": None if ok else self._last_error
        }

    def init_tables(self) -> bool:
        """Cria as tabelas necessárias para o Sentinela no PostgreSQL se não existirem."""
        if self._initialized:
            return True
        schema_sql = """
        CREATE TABLE IF NOT EXISTS sentinel_users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sentinel_devices (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES sentinel_users(id) ON DELETE CASCADE,
            computer_id VARCHAR(64) UNIQUE NOT NULL,
            hostname VARCHAR(255),
            os_name VARCHAR(255),
            sync_token TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sentinel_telemetry (
            computer_id VARCHAR(64) PRIMARY KEY,
            snapshot_json TEXT NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sentinel_audit_events (
            id SERIAL PRIMARY KEY,
            computer_id VARCHAR(64) NOT NULL,
            event_type VARCHAR(100) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            description TEXT NOT NULL,
            payload_json TEXT,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_sentinel_devices_user ON sentinel_devices(user_id);
        CREATE INDEX IF NOT EXISTS idx_sentinel_audit_comp ON sentinel_audit_events(computer_id);
        """
        try:
            conn, driver = self.get_connection()
            if driver == "psycopg2":
                with conn.cursor() as cur:
                    cur.execute(schema_sql)
                conn.commit()
                conn.close()
            elif driver == "pg8000":
                conn.run(schema_sql)
                conn.close()
            self._connected = True
            logger.info("[POSTGRES] Tabelas do Sentinela XDR inicializadas com sucesso.")
            return True
        except Exception as e:
            logger.warning("[POSTGRES] Falha ao inicializar tabelas: %s", e)
            return False

    # -------------------------------------------------------------------------
    # OPERAÇÕES DE USUÁRIOS
    # -------------------------------------------------------------------------

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        try:
            conn, driver = self.get_connection()
            if driver == "psycopg2":
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("SELECT id, email, password_hash FROM sentinel_users WHERE email = %s", (email.lower(),))
                    row = cur.fetchone()
                conn.close()
                return dict(row) if row else None
            elif driver == "pg8000":
                res = conn.run("SELECT id, email, password_hash FROM sentinel_users WHERE email = :em", em=email.lower())
                conn.close()
                if res:
                    return {"id": res[0][0], "email": res[0][1], "password_hash": res[0][2]}
        except Exception as e:
            logger.debug("get_user_by_email error: %s", e)
        return None

    def create_user(self, email: str, password_hash: str) -> Optional[int]:
        try:
            conn, driver = self.get_connection()
            user_id = None
            if driver == "psycopg2":
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO sentinel_users (email, password_hash) VALUES (%s, %s) RETURNING id",
                        (email.lower(), password_hash)
                    )
                    user_id = cur.fetchone()[0]
                conn.commit()
                conn.close()
            elif driver == "pg8000":
                res = conn.run(
                    "INSERT INTO sentinel_users (email, password_hash) VALUES (:em, :pw) RETURNING id",
                    em=email.lower(), pw=password_hash
                )
                conn.close()
                if res:
                    user_id = res[0][0]
            return user_id
        except Exception as e:
            logger.debug("create_user error: %s", e)
        return None

    # -------------------------------------------------------------------------
    # OPERAÇÕES DE DISPOSITIVOS (HARDWARE ID)
    # -------------------------------------------------------------------------

    def upsert_device(self, user_id: int, computer_id: str, hostname: str, os_name: str, sync_token: str) -> bool:
        sql = """
        INSERT INTO sentinel_devices (user_id, computer_id, hostname, os_name, sync_token, last_seen)
        VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (computer_id) DO UPDATE SET 
            user_id = EXCLUDED.user_id,
            hostname = EXCLUDED.hostname,
            os_name = EXCLUDED.os_name,
            sync_token = EXCLUDED.sync_token,
            last_seen = CURRENT_TIMESTAMP;
        """
        try:
            conn, driver = self.get_connection()
            if driver == "psycopg2":
                with conn.cursor() as cur:
                    cur.execute(sql, (user_id, computer_id, hostname, os_name, sync_token))
                conn.commit()
                conn.close()
            elif driver == "pg8000":
                sql_pg8 = sql.replace("%s", ":p0", 1).replace("%s", ":p1", 1).replace("%s", ":p2", 1).replace("%s", ":p3", 1).replace("%s", ":p4", 1)
                conn.run(sql_pg8, p0=user_id, p1=computer_id, p2=hostname, p3=os_name, p4=sync_token)
                conn.close()
            return True
        except Exception as e:
            logger.debug("upsert_device error: %s", e)
        return False

    def get_devices(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            conn, driver = self.get_connection()
            devices = []
            if driver == "psycopg2":
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT computer_id, hostname, os_name, sync_token, created_at, last_seen 
                        FROM sentinel_devices WHERE user_id = %s ORDER BY last_seen DESC
                    """, (user_id,))
                    devices = [dict(r) for r in cur.fetchall()]
                conn.close()
            elif driver == "pg8000":
                res = conn.run("""
                    SELECT computer_id, hostname, os_name, sync_token, created_at, last_seen 
                    FROM sentinel_devices WHERE user_id = :uid ORDER BY last_seen DESC
                """, uid=user_id)
                conn.close()
                for r in res:
                    devices.append({
                        "computer_id": r[0], "hostname": r[1], "os_name": r[2],
                        "sync_token": r[3], "created_at": str(r[4]), "last_seen": str(r[5])
                    })
            return devices
        except Exception as e:
            logger.debug("get_devices error: %s", e)
        return []

    # -------------------------------------------------------------------------
    # OPERAÇÕES DE TELEMETRIA & AUDITORIA
    # -------------------------------------------------------------------------

    def save_telemetry_snapshot(self, computer_id: str, snapshot: Dict[str, Any]) -> bool:
        json_str = json.dumps(snapshot, ensure_ascii=False)
        sql = """
        INSERT INTO sentinel_telemetry (computer_id, snapshot_json, updated_at)
        VALUES (%s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (computer_id) DO UPDATE SET 
            snapshot_json = EXCLUDED.snapshot_json,
            updated_at = CURRENT_TIMESTAMP;
        """
        try:
            conn, driver = self.get_connection()
            if driver == "psycopg2":
                with conn.cursor() as cur:
                    cur.execute(sql, (computer_id, json_str))
                    # Atualiza heartbeat do dispositivo
                    cur.execute("UPDATE sentinel_devices SET last_seen = CURRENT_TIMESTAMP WHERE computer_id = %s", (computer_id,))
                    # Registra eventos recentes
                    for ev in snapshot.get("recent_events", [])[:10]:
                        cur.execute("""
                            INSERT INTO sentinel_audit_events (computer_id, event_type, severity, description, payload_json)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (computer_id, ev.get("type", "SECURITY"), ev.get("severity", "INFO"), ev.get("description", ""), json.dumps(ev)))
                conn.commit()
                conn.close()
            elif driver == "pg8000":
                sql_pg8 = sql.replace("%s", ":p0", 1).replace("%s", ":p1", 1)
                conn.run(sql_pg8, p0=computer_id, p1=json_str)
                conn.run("UPDATE sentinel_devices SET last_seen = CURRENT_TIMESTAMP WHERE computer_id = :cid", cid=computer_id)
                conn.close()
            return True
        except Exception as e:
            logger.debug("save_telemetry_snapshot error: %s", e)
        return False

    def get_telemetry_snapshot(self, computer_id: str) -> Optional[Tuple[Dict[str, Any], str]]:
        try:
            conn, driver = self.get_connection()
            if driver == "psycopg2":
                with conn.cursor() as cur:
                    cur.execute("SELECT snapshot_json, updated_at FROM sentinel_telemetry WHERE computer_id = %s", (computer_id,))
                    row = cur.fetchone()
                conn.close()
                if row:
                    return json.loads(row[0]), str(row[1])
            elif driver == "pg8000":
                res = conn.run("SELECT snapshot_json, updated_at FROM sentinel_telemetry WHERE computer_id = :cid", cid=computer_id)
                conn.close()
                if res:
                    return json.loads(res[0][0]), str(res[0][1])
        except Exception as e:
            logger.debug("get_telemetry_snapshot error: %s", e)
        return None

# Instância global
pg_manager = PostgresManager()

if __name__ == "__main__":
    print(f"Testando conexão com PostgreSQL ({DEFAULT_PG_URL.split('@')[1] if '@' in DEFAULT_PG_URL else DEFAULT_PG_URL})...")
    ok, msg = pg_manager.test_connection()
    print("Resultado:", "SUCESSO" if ok else "FALHA")
    print("Detalhes:", msg)
    if ok:
        print("Criando tabelas...")
        created = pg_manager.init_tables()
        print("Tabelas inicializadas:", created)
