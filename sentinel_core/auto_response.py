# sentinel_core/auto_response.py
import os
import shutil
import logging
import psutil
from datetime import datetime
from typing import List, Dict, Optional, Set
from sentinel_core.logger import SecurityEventLogger
from sentinel_core.crypto_vault import CryptoVault

class AutoResponseEngine:
    """Motor de Resposta Automática a Incidentes (SOAR), Quarentena e Restauração de Arquivos."""

    SAFE_PROTECTED_FILENAMES: Set[str] = {
        "main.py", "sentinel_api.py", "sentinel_cli.py", "dashboard.html",
        "iniciar.bat", "iniciar_cli.bat", "setup_project.py", "sentinel_events.db",
        "sentinel.key", "__init__.py", "test_sentinela.py"
    }

    def __init__(self, logger: SecurityEventLogger, vault: CryptoVault, quarantine_dir: str = "quarantine"):
        self.logger = logger
        self.vault = vault
        self.quarantine_dir = os.path.abspath(quarantine_dir) if not os.path.isabs(quarantine_dir) else quarantine_dir
        self.restored_dir = os.path.join(os.path.dirname(self.quarantine_dir), "restored")
        self._ensure_dirs()

    def _ensure_dirs(self):
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir, exist_ok=True)
        if not os.path.exists(self.restored_dir):
            os.makedirs(self.restored_dir, exist_ok=True)

    def is_protected_file(self, file_path: str) -> bool:
        """Impede que arquivos do próprio sistema sejam jogados na quarentena por engano."""
        if not file_path:
            return True
        abs_path = os.path.abspath(file_path).lower()
        filename = os.path.basename(abs_path)

        if filename in self.SAFE_PROTECTED_FILENAMES:
            return True

        normalized = abs_path.replace('\\', '/')
        if "/sentinel_core/" in normalized or "/honeypots/" in normalized or "/quarantine/" in normalized:
            return True

        return False

    def isolate_file(self, file_path: str) -> bool:
        """Move o arquivo malicioso/suspeito para a quarentena e o criptografa com AES-256."""
        abs_path = os.path.abspath(file_path)
        if not os.path.exists(abs_path):
            logging.warning(f"[SOAR] Arquivo para quarentena não encontrado: {abs_path}")
            return False

        # Proteção contra falso-positivo em arquivos do próprio Sentinela
        if self.is_protected_file(abs_path):
            logging.warning(f"[SOAR] Tentativa de isolar arquivo protegido do projeto '{abs_path}' cancelada.")
            return False

        try:
            self._ensure_dirs()
            filename = os.path.basename(abs_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantined_name = f"{timestamp}_{filename}.quarantine"
            dest_path = os.path.join(self.quarantine_dir, quarantined_name)

            # 1. Criptografa o arquivo no local de destino
            if not self.vault.encrypt_file(abs_path, dest_path):
                raise IOError(f"Falha na criptografia do cofre ao salvar em {dest_path}")

            # 2. Remove o arquivo malicioso original do sistema
            try:
                os.remove(abs_path)
            except Exception as e:
                logging.warning(f"[SOAR] Não foi possível deletar arquivo original imediatamente: {e}")

            desc = f"ARQUIVO ISOLADO EM QUARENTENA! '{abs_path}' -> '{dest_path}' (Criptografado)"
            self.logger.log_event("HIGH", "SOAR_QUARANTINE", abs_path, desc)
            logging.info(f"[SOAR] {desc}")
            return True

        except Exception as e:
            err_msg = f"Falha ao isolar arquivo {abs_path}: {e}"
            self.logger.log_event("CRITICAL", "SOAR_ERROR", abs_path, err_msg)
            logging.error(f"[SOAR] {err_msg}")
            return False

    def restore_file(self, quarantined_file_name: str, restore_to_path: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        Restaura um arquivo da quarentena, decifrando-o de volta para o sistema.
        Se restore_to_path não for informado, restaura para a pasta 'restored/'.
        Retorna (sucesso, caminho_restaurado).
        """
        self._ensure_dirs()
        # Permite passar apenas o nome do arquivo ou o caminho completo
        quarantined_name = os.path.basename(quarantined_file_name)
        quarantine_file_path = os.path.join(self.quarantine_dir, quarantined_name)
        
        if not os.path.exists(quarantine_file_path):
            logging.error(f"[SOAR] Arquivo na quarentena não encontrado: {quarantine_file_path}")
            return (False, None)

        # Determina o nome original retirando o prefixo timestamp_
        clean_name = quarantined_name
        if "_" in quarantined_name and quarantined_name.endswith(".quarantine"):
            parts = quarantined_name.split("_", 2)
            if len(parts) >= 3:
                clean_name = parts[2].replace(".quarantine", "")
            else:
                clean_name = quarantined_name.replace(".quarantine", "")

        if not restore_to_path:
            restore_to_path = os.path.join(self.restored_dir, clean_name)
        else:
            restore_to_path = os.path.abspath(restore_to_path)

        try:
            dest_dir = os.path.dirname(restore_to_path)
            if dest_dir and not os.path.exists(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)

            success = self.vault.decrypt_file(quarantine_file_path, restore_to_path)
            if success:
                # Remove da quarentena após restaurar com sucesso
                try:
                    os.remove(quarantine_file_path)
                except Exception:
                    pass

                desc = f"ARQUIVO LIBERADO DA QUARENTENA! '{quarantined_name}' -> '{restore_to_path}'"
                self.logger.log_event("INFO", "SOAR_RESTORE", restore_to_path, desc)
                logging.info(f"🟢 [SOAR RESTORE] {desc}")
                return (True, restore_to_path)
            return (False, None)
        except Exception as e:
            err_msg = f"Falha ao restaurar {quarantined_file_name}: {e}"
            self.logger.log_event("HIGH", "SOAR_ERROR", quarantined_file_name, err_msg)
            logging.error(f"[SOAR] {err_msg}")
            return (False, None)

    def delete_quarantined_file(self, quarantined_file_name: str) -> bool:
        """Exclui definitivamente um arquivo da quarentena."""
        quarantined_name = os.path.basename(quarantined_file_name)
        quarantine_file_path = os.path.join(self.quarantine_dir, quarantined_name)
        if not os.path.exists(quarantine_file_path):
            return False
        try:
            os.remove(quarantine_file_path)
            desc = f"Arquivo da quarentena excluído definitivamente: '{quarantined_name}'"
            self.logger.log_event("INFO", "SOAR_DELETE", quarantined_name, desc)
            logging.info(f"🗑️ [SOAR] {desc}")
            return True
        except Exception as e:
            logging.error(f"[SOAR] Falha ao deletar da quarentena: {e}")
            return False

    def list_quarantine(self) -> List[Dict]:
        """Lista todos os arquivos presentes no diretório de quarentena com a localização original de onde vieram."""
        self._ensure_dirs()
        items = []
        try:
            import sqlite3
            # Resolve o caminho do banco de dados de eventos
            db_candidates = []
            if self.logger and hasattr(self.logger, 'db_path') and self.logger.db_path:
                db_candidates.append(self.logger.db_path)
            db_candidates.append(os.path.join(os.path.dirname(self.quarantine_dir), "sentinel_events.db"))
            db_candidates.append(os.path.abspath("sentinel_events.db"))

            active_db = next((db for db in db_candidates if os.path.exists(db)), None)

            for fname in os.listdir(self.quarantine_dir):
                fpath = os.path.join(self.quarantine_dir, fname)
                if os.path.isfile(fpath):
                    # Extrai nome original limpo
                    clean_name = fname
                    if "_" in fname and fname.endswith(".quarantine"):
                        parts = fname.split("_", 2)
                        clean_name = parts[2].replace(".quarantine", "") if len(parts) >= 3 else fname.replace(".quarantine", "")

                    original_location = "Origem não encontrada nos logs"
                    
                    if active_db:
                        try:
                            with sqlite3.connect(active_db) as conn:
                                cur = conn.cursor()
                                # 1. Busca por nome exato do arquivo de quarentena
                                cur.execute("SELECT target FROM security_events WHERE description LIKE ? ORDER BY id DESC LIMIT 1", (f"%{fname}%",))
                                row = cur.fetchone()
                                if row and row[0]:
                                    original_location = row[0]
                                else:
                                    # 2. Busca por nome original do arquivo
                                    cur.execute("SELECT target FROM security_events WHERE (target LIKE ? OR description LIKE ?) AND category IN ('SOAR_QUARANTINE', 'MALWARE', 'FIM') ORDER BY id ASC LIMIT 1", (f"%{clean_name}%", f"%{clean_name}%"))
                                    row2 = cur.fetchone()
                                    if row2 and row2[0]:
                                        original_location = row2[0]
                        except Exception as e:
                            logging.debug(f"[SOAR] Erro ao consultar origem de '{fname}': {e}")

                    # Formata a data de forma limpa e legível (ex: 2026-08-30 21:11:06)
                    try:
                        mtime = os.path.getmtime(fpath)
                        formatted_date = datetime.fromtimestamp(mtime).strftime("%d/%m/%Y %H:%M:%S")
                    except Exception:
                        formatted_date = "N/A"

                    items.append({
                        "name": fname,
                        "original_name": clean_name,
                        "original_location": original_location,
                        "path": fpath,
                        "size": os.path.getsize(fpath),
                        "modified": formatted_date
                    })
        except Exception as e:
            logging.error(f"[SOAR] Erro ao listar quarentena: {e}")
        return items



    def kill_process_by_pid(self, pid: int) -> bool:
        """Encerra forçadamente um processo suspeito pelo PID."""
        try:
            pid_int = int(pid)
            process = psutil.Process(pid_int)
            process_name = process.name()
            process.kill()
            desc = f"PROCESSO MALICIOSO ENCERRADO! PID: {pid_int} ({process_name})"
            self.logger.log_event("CRITICAL", "SOAR_KILL", str(pid_int), desc)
            logging.info(f"[SOAR] {desc}")
            return True
        except psutil.NoSuchProcess:
            logging.warning(f"[SOAR] Processo com PID {pid} não foi encontrado.")
            return False
        except Exception as e:
            err_msg = f"Erro ao encerrar PID {pid}: {e}"
            self.logger.log_event("HIGH", "SOAR_ERROR", str(pid), err_msg)
            logging.error(f"[SOAR] {err_msg}")
            return False

    # Aliases de compatibilidade
    def quarantine_file(self, file_path: str, reason: str = "") -> bool:
        return self.isolate_file(file_path)

    def kill_process(self, pid: int, reason: str = "") -> bool:
        return self.kill_process_by_pid(pid)

    def trigger_incident(self, incident_type: str, severity: str = "CRITICAL", details: str = "") -> bool:
        if self.logger:
            self.logger.log_event(severity, incident_type, "SOAR_INCIDENT", details)
        logging.critical(f"[SOAR INCIDENT] [{severity}] {incident_type}: {details}")
        return True

SOAREngine = AutoResponseEngine





