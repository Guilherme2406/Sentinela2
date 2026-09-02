# sentinel_core/kernel_monitor.py
import os
import sys
import time
import logging
from typing import List, Dict, Any, Optional

class SystemKernelMonitor:
    """
    Abstração para monitoramento de eventos de integridade de sistema (Auditd / System Logs).
    Inspeciona alterações em arquivos críticos de sistema e tabelas de roteamento.
    """

    CRITICAL_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/crontab",
        r"C:\Windows\System32\drivers\etc\hosts"
    ]

    def __init__(self, logger=None):
        self.logger = logger
        self.path_snapshots: Dict[str, float] = {}
        self._init_snapshots()

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def _init_snapshots(self):
        for path in self.CRITICAL_PATHS:
            if os.path.exists(path):
                try:
                    self.path_snapshots[path] = os.path.getmtime(path)
                except Exception:
                    pass

    def inspect_system_integrity(self) -> List[Dict[str, Any]]:
        """Verifica se arquivos vitais do sistema operacional foram modificados."""
        integrity_alerts = []

        for path in self.CRITICAL_PATHS:
            if os.path.exists(path):
                try:
                    current_mtime = os.path.getmtime(path)
                    last_mtime = self.path_snapshots.get(path)

                    if last_mtime and current_mtime != last_mtime:
                        alert = {
                            "path": path,
                            "event": "CRITICAL_FILE_MODIFIED",
                            "timestamp": time.time()
                        }
                        integrity_alerts.append(alert)
                        self._log("CRITICAL", "KERNEL_MONITOR", "INTEGRITY_BREACH", 
                                  f"Arquivo vital do sistema modificado: {path}")
                        self.path_snapshots[path] = current_mtime
                except Exception as e:
                    self._log("ERROR", "KERNEL_MONITOR", "STAT_ERROR", f"Erro ao inspecionar {path}: {e}")

        return integrity_alerts
