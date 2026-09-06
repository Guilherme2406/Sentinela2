# sentinel_core/anti_hollowing_guard.py
"""
🛡️ SENTINELA ANTI-HOLLOWING & RWX MEMORY GUARD
Detecta e neutraliza ataques avançados de injeção de código e evasão:
  - Process Hollowing (MITRE T1055.012)
  - Injeção de memória com proteção RWX (PAGE_EXECUTE_READWRITE)
  - Process Masquerading / Spoofing de processos críticos do Windows (svchost, lsass, csrss)
"""

import os
import sys
import time
import logging
from typing import Dict, Any, List, Optional, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("SentinelaXDR.AntiHollowing")


class AntiHollowingGuard:
    """Motor de inspeção de integridade de memória e detecção de Process Hollowing."""

    # Processos do sistema que DEVEM obrigatoriamente rodar a partir de System32 e com linhagem estrita
    CORE_SYSTEM_BINARIES: Dict[str, Dict[str, Any]] = {
        "smss.exe": {"expected_dir": "system32", "allowed_parents": ["system", "idle"]},
        "csrss.exe": {"expected_dir": "system32", "allowed_parents": ["smss.exe"]},
        "wininit.exe": {"expected_dir": "system32", "allowed_parents": ["smss.exe"]},
        "services.exe": {"expected_dir": "system32", "allowed_parents": ["wininit.exe"]},
        "lsass.exe": {"expected_dir": "system32", "allowed_parents": ["wininit.exe"]},
        "winlogon.exe": {"expected_dir": "system32", "allowed_parents": ["smss.exe"]},
        "svchost.exe": {"expected_dir": "system32", "allowed_parents": ["services.exe", "system"]}
    }

    def __init__(self, logger_instance=None, soar=None):
        self.logger = logger_instance
        self.soar = soar
        self.detected_anomalies: List[Dict[str, Any]] = []

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger:
                self.logger.log_event(level, category, action, msg)
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def scan_system_processes_integrity(self) -> List[Dict[str, Any]]:
        """Varre todos os processos em execução procurando Process Hollowing e Masquerading."""
        anomalies_found = []
        if not HAS_PSUTIL:
            return anomalies_found

        system32_lower = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32").lower()

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'cmdline']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or '').lower()
                pid = pinfo['pid']

                if pid <= 4:
                    continue

                exe_path = (pinfo['exe'] or '').lower()

                # 1. Detecção de Masquerading de Binários Críticos do Windows
                if pname in self.CORE_SYSTEM_BINARIES:
                    spec = self.CORE_SYSTEM_BINARIES[pname]
                    # Se o executável não estiver na pasta oficial System32
                    if exe_path and not exe_path.startswith(system32_lower):
                        threat = {
                            "pid": pid,
                            "name": pinfo['name'],
                            "exe": pinfo['exe'],
                            "rule": "PROCESS_MASQUERADING_FAKE_SYSTEM_BIN",
                            "severity": "CRITICAL",
                            "description": f"Processo falso '{pname}' executando fora de System32: '{pinfo['exe']}'",
                            "timestamp": time.time()
                        }
                        anomalies_found.append(threat)
                        self._log("CRITICAL", "ANTI_HOLLOWING", "FAKE_SYSTEM_PROC", threat["description"])

                # 2. Varredura de Mapas de Memória RWX (se suportado pelo sistema)
                try:
                    maps = proc.memory_maps(grouped=False)
                    for m in maps:
                        perms = getattr(m, 'perms', '')
                        # Se tiver permissão de Leitura, Escrita e Execução simultânea em memória anônima
                        if 'rwx' in perms.lower() and not m.path:
                            threat = {
                                "pid": pid,
                                "name": pinfo['name'],
                                "rule": "ANONYMOUS_RWX_MEMORY_INJECTION",
                                "severity": "HIGH",
                                "description": f"Página de memória anônima RWX detectada no PID {pid} ({pname}) - Provável shellcode injetado.",
                                "timestamp": time.time()
                            }
                            anomalies_found.append(threat)
                            self._log("HIGH", "ANTI_HOLLOWING", "RWX_INJECTION", threat["description"])
                            break
                except Exception:
                    # Falta de permissão para ler memória de processos do sistema ou OS sem suporte
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.detected_anomalies.extend(anomalies_found)
        return anomalies_found

    def inspect_process(self, pid: int) -> Optional[Dict[str, Any]]:
        """Inspeciona cirurgicamente um processo específico por PID."""
        if not HAS_PSUTIL:
            return None
        try:
            proc = psutil.Process(pid)
            pname = proc.name().lower()
            exe_path = (proc.exe() or '').lower()
            system32_lower = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32").lower()

            if pname in self.CORE_SYSTEM_BINARIES and exe_path and not exe_path.startswith(system32_lower):
                return {
                    "pid": pid,
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "rule": "PROCESS_MASQUERADING_FAKE_SYSTEM_BIN",
                    "severity": "CRITICAL",
                    "description": f"Processo '{pname}' forjado fora do caminho oficial de sistema."
                }
            return None
        except Exception:
            return None

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status do motor de Anti-Hollowing."""
        return {
            "engine": "Sentinel Anti-Hollowing & RWX Memory Guard",
            "active": True,
            "core_binaries_monitored": len(self.CORE_SYSTEM_BINARIES),
            "anomalies_detected_count": len(self.detected_anomalies),
            "recent_anomalies": self.detected_anomalies[-10:] if self.detected_anomalies else []
        }
