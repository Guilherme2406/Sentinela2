# sentinel_core/sentinel_companion_watchdog.py
"""
🛡️ SENTINELA COMPANION WATCHDOG & ANTI-TAMPERING (AUTO-DEFESA)
Processo companion de auto-cura recíproca.
Supervisiona o PID do processo principal do Sentinela XDR.
Caso um invasor com privilégios de Administrador execute 'taskkill /F' ou derrube o processo,
o companion reanima o serviço imediatamente em segundo plano e registra o alerta de evasão MITRE T1562.001.
"""

import os
import sys
import time
import json
import logging
import subprocess
import threading
from typing import Dict, Any, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("SentinelaXDR.CompanionWatchdog")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME_FILE = os.path.join(BASE_DIR, "sentinel_runtime.json")


class CompanionWatchdog:
    """Monitor recíproco de auto-defesa e resiliência."""

    def __init__(self, check_interval: float = 3.0, logger_instance=None):
        self.check_interval = check_interval
        self.logger = logger_instance
        self.running = False
        self.revivals_count = 0
        self._thread: Optional[threading.Thread] = None

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger:
                self.logger.log_event(level, category, action, msg)
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def is_target_alive(self, target_pid: int) -> bool:
        """Verifica se o processo do Sentinela continua vivo e em execução."""
        if target_pid <= 0:
            return False
        if HAS_PSUTIL:
            try:
                proc = psutil.Process(target_pid)
                return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
        else:
            # Fallback nativo
            if sys.platform == "win32":
                out = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {target_pid}"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                return str(target_pid) in (out.stdout or "")
            return True


    def revive_sentinel(self, previous_pid: int) -> bool:
        """Dispara a reanimação autônoma do serviço Sentinela XDR."""
        self._log(
            "CRITICAL", "ANTI_TAMPERING", "DEFENSE_IMPAIRED",
            f"🚨 ALERTA DE EVASÃO! Processo principal PID {previous_pid} foi encerrado anormalmente. Reanimando serviço..."
        )

        try:
            cmd = [sys.executable, os.path.join(BASE_DIR, "sentinela_service.py")]
            if sys.platform == "win32":
                # Inicia de forma desanexada e invisível
                CREATE_NO_WINDOW = 0x08000000
                subprocess.Popen(cmd, creationflags=CREATE_NO_WINDOW, close_fds=True)
            else:
                subprocess.Popen(cmd, start_new_session=True)

            self.revivals_count += 1
            self._log("INFO", "ANTI_TAMPERING", "SERVICE_REVIVED", f"Sentinela XDR reanimado com sucesso (Revival #{self.revivals_count}).")
            return True
        except Exception as e:
            self._log("ERROR", "ANTI_TAMPERING", "REVIVAL_FAILED", f"Falha ao reanimar serviço: {e}")
            return False

    def start_supervision(self, target_pid: Optional[int] = None):
        """Inicia o loop de supervisão contínua em thread daemon."""
        if self.running:
            return
        self.running = True

        def _supervise():
            logger.info("🛡️ [WATCHDOG] Companion de Auto-Defesa iniciado e operando em segundo plano.")
            while self.running:
                time.sleep(self.check_interval)
                current_pid = target_pid

                # Se não fornecido, busca o PID dinamicamente em sentinel_runtime.json
                if not current_pid and os.path.exists(RUNTIME_FILE):
                    try:
                        with open(RUNTIME_FILE, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            current_pid = data.get("pid")
                    except Exception:
                        pass

                if current_pid:
                    if not self.is_target_alive(current_pid):
                        self.revive_sentinel(current_pid)
                        time.sleep(self.check_interval * 2)

        self._thread = threading.Thread(target=_supervise, name="SentinelCompanionWatchdog", daemon=True)
        self._thread.start()

    def stop_supervision(self):
        """Finaliza a supervisão de auto-defesa."""
        self.running = False

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status da camada de auto-defesa."""
        return {
            "engine": "Sentinel Companion Watchdog & Anti-Tampering Armor",
            "active": self.running,
            "status": "ACTIVE" if self.running else "STANDBY",
            "revivals_count": self.revivals_count,
            "check_interval_seconds": self.check_interval,
            "runtime_file": RUNTIME_FILE
        }

    def status(self) -> Dict[str, Any]:
        return self.get_status()
