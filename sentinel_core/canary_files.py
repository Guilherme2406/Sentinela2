# sentinel_core/canary_files.py
import os
import time
import threading
import logging
from typing import List, Callable

class CanaryTokenEngine:
    """
    Motor de Decepção com Arquivos Isca (Honeyfiles/Canary Tokens).
    Cria armadilhas em pastas estratégicas para detectar leituras/exclusões não autorizadas.
    """

    def __init__(self, base_dir: str = "./canary_traps", trigger_callback: Callable = None, logger=None):
        self.base_dir = os.path.abspath(base_dir)
        self.trigger_callback = trigger_callback
        self.logger = logger
        self.is_running = False
        self.canary_files = [
            "senhas_banco_backup.xlsx",
            "chaves_privadas_ssh.pem",
            "relatorio_financeiro_confidencial.pdf"
        ]
        self._initial_mtimes = {}

    def setup_canaries(self):
        """Gera os arquivos armadilha com conteúdo isca."""
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir, exist_ok=True)

        for filename in self.canary_files:
            filepath = os.path.join(self.base_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"--- CONFIDENTIAL CANARY TOKEN SENTINEL XDR ---\nSECURITY ISCA FILE: {filename}\nDO NOT TOUCH.")
            
            self._initial_mtimes[filepath] = os.path.getmtime(filepath)

    def start_monitoring(self, poll_interval: float = 2.0):
        """Inicia a thread de monitoramento contínuo das armadilhas."""
        self.setup_canaries()
        self.is_running = True
        thread = threading.Thread(target=self._monitor_loop, args=(poll_interval,), daemon=True)
        thread.start()
        logging.info("[CANARY_TOKEN] Engine de Arquivos Canário iniciada.")

    def _monitor_loop(self, interval: float):
        while self.is_running:
            time.sleep(interval)
            for filename in self.canary_files:
                filepath = os.path.join(self.base_dir, filename)
                
                # Se o arquivo foi apagado ou modificado por um ataque/ransomware
                if not os.path.exists(filepath):
                    self._trigger_alarm(filename, "EXCLUSAO_OU_SEQUESTRO_RANSOMWARE")
                    self.setup_canaries() # recria a armadilha
                else:
                    current_mtime = os.path.getmtime(filepath)
                    if current_mtime != self._initial_mtimes.get(filepath, current_mtime):
                        self._trigger_alarm(filename, "ACESSO_OU_MODIFICACAO_NAO_AUTORIZADA")
                        self._initial_mtimes[filepath] = current_mtime

    def _trigger_alarm(self, filename: str, attack_type: str):
        msg = f"ALERTA CANÁRIO: O arquivo armadilha '{filename}' sofreu {attack_type}!"
        if self.logger:
            self.logger.log_event("CRITICAL", "CANARY_TRAP", "HONEYFILE_TOUCHED", msg)
        logging.critical(f"[CANARY_TRAP] {msg}")

    def create_canary_files(self) -> List[str]:
        self.setup_canaries()
        return [os.path.join(self.base_dir, f) for f in self.canary_files]

    def get_status(self) -> dict:
        return {
            "active": self.is_running,
            "traps_count": len(self.canary_files),
            "trap_files": self.canary_files,
            "base_dir": self.base_dir
        }

    def stop(self):
        self.is_running = False

CanaryFileManager = CanaryTokenEngine

