# sentinel_core/honeyfiles.py
import os
import time
import logging
from typing import List, Dict, Any

class HoneyfileManager:
    """
    Gerenciador de Decepção Cibernética & Arquivos Canário (Honeyfiles).
    Cria arquivos armadilha e detecta acessos não autorizados para interromper exfiltração DLP.
    """

    def __init__(self, base_dir: str, logger=None, auto_response_engine=None):
        self.base_dir = base_dir
        self.logger = logger
        self.soar = auto_response_engine
        self.honeyfile_paths: Dict[str, float] = {}  # caminho -> mtime inicial

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def deploy_canaries(self) -> List[str]:
        """Gera arquivos armadilha estrategicamente em pastas sensíveis."""
        canary_dir = os.path.join(self.base_dir, "canary_traps")
        os.makedirs(canary_dir, exist_ok=True)

        canary_files = {
            os.path.join(canary_dir, "passwords_banco_2026.xlsx"): "CONFIDENTIAL DATABASE ACCESS KEYS - DO NOT TOUCH",
            os.path.join(canary_dir, "id_rsa_backup.key"): "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0CanaryTokenSentinelXDR\n-----END RSA PRIVATE KEY-----",
            os.path.join(canary_dir, "financeiro_secret.pdf"): "%PDF-1.5 Sentinel Canary Trap Document",
            os.path.join(canary_dir, "senhas_banco_backup.xlsx"): "CONFIDENTIAL BACKUP SENHAS - CANARY TRAP",
            os.path.join(canary_dir, "chaves_privadas_ssh.pem"): "-----BEGIN RSA PRIVATE KEY-----\nCANARY_SSH_KEY\n-----END RSA PRIVATE KEY-----"
        }

        created = []
        for file_path, content in canary_files.items():
            try:
                if not os.path.exists(file_path):
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                self.honeyfile_paths[file_path] = os.path.getmtime(file_path)
                created.append(file_path)
            except Exception as e:
                self._log("ERROR", "HONEYFILE", "DEPLOY_ERROR", f"Erro ao criar canário {file_path}: {e}")

        self._log("INFO", "HONEYFILE", "DEPLOYED", f"{len(created)} Arquivos Canário de Decepção ativos em '{canary_dir}'.")
        return created

    def check_integrity(self):
        """Verifica se algum arquivo canário foi lido, alterado ou deletado."""
        for file_path, original_mtime in list(self.honeyfile_paths.items()):
            if not os.path.exists(file_path):
                self._trigger_alert(file_path, "DELETED", "Arquivo Canário DELETADO por potencial malfeitor/Ransomware!")
                continue

            current_mtime = os.path.getmtime(file_path)
            if current_mtime != original_mtime:
                self.honeyfile_paths[file_path] = current_mtime
                self._trigger_alert(file_path, "TAMPERED", "Arquivo Canário ACESSADO/MODIFICADO! Alerta de exfiltração DLP.")

    def _trigger_alert(self, file_path: str, action: str, details: str):
        self._log("CRITICAL", "CANARY_TRAP", action, f"🚨 ARMADILHA ATIVADA: {file_path} - {details}")
        if self.soar:
            self.soar.trigger_incident("CANARY_FILE_BREACH", "CRITICAL", f"Acesso à armadilha: {file_path}")
