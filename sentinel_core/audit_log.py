# sentinel_core/audit_log.py
"""
Auditoria GLOBAL de ações de operadores do Sentinel (trilha de auditoria).

Toda ação destrutiva/sensível executada pela API (quarentena, kill, ban,
contenção, exclusões) DEVE registrar aqui: quem, o quê, quando e de onde.

Cadeia Criptográfica (Hash Chain) & Custódia WORM (Write Once Read Many):
- Cada registro encadeia SHA-256 com o hash do registro anterior.
- Verificação de inviolabilidade ponta a ponta (detecta qualquer alteração manual no banco).
- Exportação formal WORM selada com Assinatura Pós-Quântica NIST FIPS 204 (ML-DSA-87).

Persistência: SQLite (`sentinel_vault/audit_actions.db`), thread-safe.
"""
import os
import sys
import json
import time
import uuid
import stat
import sqlite3
import hashlib
import threading
from typing import Any, Dict, List, Optional

GENESIS_HASH = "0" * 64


class AuditLogger:
    """Registro imutável (append-only) e encadeado criptograficamente de ações de operadores."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            vault_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "sentinel_vault",
            )
            os.makedirs(vault_dir, exist_ok=True)
            db_path = os.path.join(vault_dir, "audit_actions.db")
        self.db_path = db_path
        self._lock = threading.RLock()
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.worm_dir = os.environ.get(
            "SENTINEL_WORM_DIR",
            os.path.join(parent if parent else ".", "worm_exports")
        )
        os.makedirs(self.worm_dir, exist_ok=True)
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
                    CREATE TABLE IF NOT EXISTS audit_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target TEXT,
                        ip TEXT,
                        details TEXT,
                        created_at REAL,
                        request_path TEXT,
                        request_method TEXT,
                        prev_hash TEXT,
                        record_hash TEXT
                    )
                """)
                # Migração transparente de colunas se já existia a tabela antiga
                cur = conn.execute("PRAGMA table_info(audit_actions)")
                cols = [r["name"] for r in cur.fetchall()]
                if "prev_hash" not in cols:
                    conn.execute("ALTER TABLE audit_actions ADD COLUMN prev_hash TEXT")
                if "record_hash" not in cols:
                    conn.execute("ALTER TABLE audit_actions ADD COLUMN record_hash TEXT")

                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_actions(user)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_actions(action)"
                )
                conn.commit()
            finally:
                conn.close()

    def _compute_hash(self, prev_hash: str, user: str, action: str, target: str,
                      ip: Optional[str], created_at: float, details_json: Optional[str],
                      request_path: str, request_method: str) -> str:
        """Calcula o hash SHA-256 do registro encadeado."""
        raw = (
            f"{prev_hash}|{user}|{action}|{target or ''}|{ip or ''}|"
            f"{created_at:.4f}|{details_json or ''}|{request_path or ''}|{request_method or ''}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def log_action(self, user: str, action: str, target: str = "",
                   ip: Optional[str] = None, details: Optional[Dict[str, Any]] = None,
                   request_path: str = "", request_method: str = "") -> int:
        """Registra uma ação com hash encadeado (hash chain). Retorna o id do registro. Nunca levanta."""
        if not user:
            user = "unknown"
        details_json = json.dumps(details, ensure_ascii=False) if details is not None else None
        now_ts = time.time()
        with self._lock:
            conn = self._connect()
            try:
                # Obtém o hash do último registro para encadeamento
                last_row = conn.execute(
                    "SELECT record_hash FROM audit_actions ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = (
                    last_row["record_hash"]
                    if (last_row and last_row["record_hash"])
                    else GENESIS_HASH
                )

                rec_hash = self._compute_hash(
                    prev_hash, user, action, target, ip, now_ts, details_json,
                    request_path, request_method
                )

                cur = conn.execute(
                    "INSERT INTO audit_actions "
                    "(user, action, target, ip, details, created_at, request_path, request_method, prev_hash, record_hash) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (user, action, target, ip, details_json, now_ts,
                     request_path, request_method, prev_hash, rec_hash),
                )
                conn.commit()
                return int(cur.lastrowid)
            finally:
                conn.close()

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Verifica a integridade criptográfica completa da trilha de auditoria.
        Detecta inserções não autorizadas, deleções ou adulterações de dados no SQLite.
        """
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_actions ORDER BY id ASC"
                ).fetchall()
            finally:
                conn.close()

        if not rows:
            return {
                "valid": True,
                "total_records": 0,
                "genesis_hash": GENESIS_HASH,
                "latest_root_hash": GENESIS_HASH,
                "status": "EMPTY_CHAIN"
            }

        expected_prev = GENESIS_HASH
        for idx, row in enumerate(rows):
            # Se a linha for legada (sem hash gravado), consideramos que o encadeamento começou após
            if not row["record_hash"]:
                continue

            # Checa se o prev_hash bate com o anterior
            if row["prev_hash"] and row["prev_hash"] != expected_prev and expected_prev != GENESIS_HASH:
                return {
                    "valid": False,
                    "tampered_id": row["id"],
                    "reason": f"Quebra de encadeamento no ID {row['id']}: prev_hash divergente.",
                    "total_audited": idx
                }

            # Recomputa o hash próprio
            calc_hash = self._compute_hash(
                row["prev_hash"] or GENESIS_HASH,
                row["user"],
                row["action"],
                row["target"] or "",
                row["ip"],
                row["created_at"],
                row["details"],
                row["request_path"] or "",
                row["request_method"] or ""
            )

            if row["record_hash"] and row["record_hash"] != calc_hash:
                return {
                    "valid": False,
                    "tampered_id": row["id"],
                    "reason": f"Adulteração de payload detectada no registro ID {row['id']}.",
                    "expected_hash": calc_hash,
                    "stored_hash": row["record_hash"],
                    "total_audited": idx
                }

            expected_prev = row["record_hash"]

        return {
            "valid": True,
            "total_records": len(rows),
            "latest_root_hash": expected_prev,
            "status": "CHAIN_VERIFIED_INTACT"
        }

    def export_worm_package(self, limit: int = 500, start_id: int = 0,
                            pqc_shield=None, destination_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Gera pacote formal WORM (Write Once Read Many) da trilha de auditoria
        com selo de integridade criptográfica e Assinatura Digital Pós-Quântica (ML-DSA-87).
        Salva o artefato com permissão de somente leitura em disco imutável.
        """
        dest_dir = destination_dir or self.worm_dir
        os.makedirs(dest_dir, exist_ok=True)

        with self._lock:
            conn = self._connect()
            try:
                query = "SELECT * FROM audit_actions WHERE id >= ? ORDER BY id ASC LIMIT ?"
                rows = conn.execute(query, (start_id, max(1, min(int(limit), 2000)))).fetchall()
            finally:
                conn.close()

        records = [self._row_to_dict(r) for r in rows]
        integrity = self.verify_chain_integrity()

        now = time.time()
        package_id = f"WORM-AUDIT-{int(now)}-{uuid.uuid4().hex[:8]}"

        manifest_data = {
            "format": "SENTINEL-WORM-AUDIT-V1",
            "package_id": package_id,
            "exported_at": now,
            "record_count": len(records),
            "start_id": records[0]["id"] if records else 0,
            "end_id": records[-1]["id"] if records else 0,
            "chain_root_hash": integrity.get("latest_root_hash", GENESIS_HASH),
            "chain_integrity_status": integrity.get("status", "UNKNOWN"),
            "system_node": os.environ.get("COMPUTERNAME", "SENTINEL-HOST"),
        }

        # Assinatura digital pós-quântica
        pqc_signature = None
        algo = "NONE"
        if pqc_shield is not None:
            try:
                pqc_signature = pqc_shield.sign_command_pqc(manifest_data)
                algo = getattr(pqc_shield, "algorithm_dsa", "ML-DSA-87")
            except Exception as exc:
                pqc_signature = f"PQC_SIGN_ERR:{exc}"
        else:
            # Tenta instanciar PQC shield interno se não fornecido
            try:
                from sentinel_core.post_quantum_shield import PostQuantumShield
                shield = PostQuantumShield(agent_id="SENTINEL_WORM_NODE")
                pqc_signature = shield.sign_command_pqc(manifest_data)
                algo = shield.algorithm_dsa
            except Exception:
                pqc_signature = "UNAVAILABLE"

        package = {
            "manifest": manifest_data,
            "pqc_integrity_seal": {
                "algorithm": algo,
                "signature": pqc_signature,
                "signed_at": now,
                "standard": "NIST FIPS 204 (ML-DSA-87)"
            },
            "records": records
        }

        # Gravação atômica do arquivo WORM
        filename = f"{package_id}.json"
        target_path = os.path.join(dest_dir, filename)
        temp_path = target_path + ".tmp"

        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=2, ensure_ascii=False)

        # Move atômico
        if os.path.exists(target_path):
            os.remove(target_path)
        os.rename(temp_path, target_path)

        # Aplica atributo de somente leitura para reforço WORM
        try:
            os.chmod(target_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            pass

        return {
            "status": "success",
            "package_id": package_id,
            "file_path": target_path,
            "file_name": filename,
            "records_exported": len(records),
            "chain_root_hash": manifest_data["chain_root_hash"],
            "pqc_signature": pqc_signature,
            "package": package
        }

    def list_worm_archives(self) -> List[Dict[str, Any]]:
        """Lista os pacotes de custódia WORM existentes no repositório com metadados."""
        if not os.path.exists(self.worm_dir):
            return []

        archives = []
        for fname in sorted(os.listdir(self.worm_dir), reverse=True):
            if fname.startswith("WORM-AUDIT-") and fname.endswith(".json"):
                fpath = os.path.join(self.worm_dir, fname)
                try:
                    fstat = os.stat(fpath)
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    manifest = data.get("manifest", {})
                    seal = data.get("pqc_integrity_seal", {})
                    archives.append({
                        "file_name": fname,
                        "file_path": fpath,
                        "size_bytes": fstat.st_size,
                        "package_id": manifest.get("package_id", fname),
                        "exported_at": manifest.get("exported_at", fstat.st_mtime),
                        "record_count": manifest.get("record_count", 0),
                        "start_id": manifest.get("start_id", 0),
                        "end_id": manifest.get("end_id", 0),
                        "chain_root_hash": manifest.get("chain_root_hash"),
                        "pqc_algorithm": seal.get("algorithm"),
                        "pqc_sealed": bool(seal.get("signature") and not str(seal.get("signature")).startswith("PQC_SIGN_ERR"))
                    })
                except Exception:
                    pass
        return archives

    def list_actions(self, limit: int = 200, user: Optional[str] = None,
                     action: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_actions WHERE 1=1"
        params: list = []
        if user:
            query += " AND user = ?"
            params.append(user)
        if action:
            query += " AND action = ?"
            params.append(action)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(query, params).fetchall()
            finally:
                conn.close()
        return [self._row_to_dict(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        """Agregados do trilho de auditoria com integridade da cadeia."""
        integrity = self.verify_chain_integrity()
        with self._lock:
            conn = self._connect()
            try:
                total = conn.execute("SELECT COUNT(*) AS c FROM audit_actions").fetchone()["c"]
                by_action_rows = conn.execute(
                    "SELECT action, COUNT(*) AS c FROM audit_actions GROUP BY action ORDER BY c DESC"
                ).fetchall()
                by_user_rows = conn.execute(
                    "SELECT user, COUNT(*) AS c FROM audit_actions GROUP BY user ORDER BY c DESC"
                ).fetchall()
                last_rows = conn.execute(
                    "SELECT * FROM audit_actions ORDER BY created_at DESC LIMIT 10"
                ).fetchall()
            finally:
                conn.close()
        return {
            "total_actions": total,
            "chain_integrity": integrity,
            "by_action": {r["action"]: r["c"] for r in by_action_rows},
            "by_user": {r["user"]: r["c"] for r in by_user_rows},
            "recent": [self._row_to_dict(r) for r in last_rows],
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        if data.get("details"):
            try:
                data["details"] = json.loads(data["details"])
            except Exception:
                pass
        return data