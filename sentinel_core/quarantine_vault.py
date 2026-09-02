# sentinel_core/quarantine_vault.py
import os
import time
import shutil
import logging
from typing import List, Dict, Any, Optional

class QuarantineVault:
    """
    Cofre de Quarentena Isolado e Criptografado.
    Move arquivos maliciosos detectados para um diretório seguro, aplicando cifragem
    para impedir execução acidental no sistema operacional hospedeiro.
    """

    def __init__(self, vault_dir: str = "sentinel_quarantine", logger=None):
        self.vault_dir = os.path.abspath(vault_dir)
        self.logger = logger
        self.xor_key = 0xAA  # Chave de ofuscação/criptografia simples
        self._ensure_vault_exists()

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def _ensure_vault_exists(self):
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir, mode=0o700, exist_ok=True)

    def quarantine_file(self, file_path: str, reason: str = "Malware/DLP Trigger") -> Optional[str]:
        """Isola um arquivo no cofre e desativa sua capacidade de execução."""
        if not os.path.exists(file_path):
            self._log("WARNING", "QUARANTINE", "FILE_NOT_FOUND", f"Arquivo não encontrado para quarentena: {file_path}")
            return None

        try:
            filename = os.path.basename(file_path)
            quarantined_filename = f"QUARANTINED_{int(time.time())}_{filename}.locked"
            target_path = os.path.join(self.vault_dir, quarantined_filename)

            # Criptografa o conteúdo ao mover
            with open(file_path, 'rb') as f_in:
                raw_bytes = f_in.read()

            encrypted_bytes = bytearray(b ^ self.xor_key for b in raw_bytes)

            with open(target_path, 'wb') as f_out:
                f_out.write(encrypted_bytes)

            # Remove o arquivo original com segurança
            os.remove(file_path)

            self._log("CRITICAL", "QUARANTINE", "FILE_ISOLATED", 
                      f"Arquivo {filename} foi isolado e criptografado com sucesso em {target_path}. Motivo: {reason}")
            return target_path

        except Exception as e:
            self._log("ERROR", "QUARANTINE", "ISOLATION_FAILED", f"Erro ao isolar arquivo {file_path}: {str(e)}")
            return None

    def list_quarantined(self) -> List[Dict[str, Any]]:
        """Lista todos os arquivos atualmente retidos em quarentena."""
        self._ensure_vault_exists()
        items = []
        for fname in os.listdir(self.vault_dir):
            fpath = os.path.join(self.vault_dir, fname)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                items.append({
                    "filename": fname,
                    "size_bytes": stat.st_size,
                    "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_ctime)),
                    "path": fpath
                })
        return items

    def restore_file(self, quarantined_filename: str, restore_to_path: str) -> bool:
        """Restaura e descriptografa um arquivo caso seja um falso-positivo."""
        source_path = os.path.join(self.vault_dir, quarantined_filename)
        if not os.path.exists(source_path):
            return False

        try:
            with open(source_path, 'rb') as f_in:
                encrypted_bytes = f_in.read()

            decrypted_bytes = bytearray(b ^ self.xor_key for b in encrypted_bytes)

            with open(restore_to_path, 'wb') as f_out:
                f_out.write(decrypted_bytes)

            os.remove(source_path)
            self._log("INFO", "QUARANTINE", "FILE_RESTORED", f"Arquivo {quarantined_filename} restaurado em {restore_to_path}")
            return True
        except Exception as e:
            self._log("ERROR", "QUARANTINE", "RESTORE_FAILED", f"Falha ao restaurar {quarantined_filename}: {str(e)}")
            return False
