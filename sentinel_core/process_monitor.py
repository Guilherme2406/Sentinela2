# sentinel_core/process_monitor.py
import os
import psutil
import logging
from typing import Set, List, Dict, Optional
from sentinel_core.logger import SecurityEventLogger

class ProcessMonitor:
    """Monitor de Processos em Execução e detecção de anomalias/suspeitas."""

    SUSPICIOUS_NAMES = {
        'nc.exe', 'netcat.exe', 'ncat.exe', 'mimikatz.exe', 'pwdump.exe', 
        'procdump.exe', 'psexec.exe', 'wireshark.exe', 'ettercap.exe', 'cain.exe'
    }
    
    def __init__(self, logger: Optional[SecurityEventLogger] = None):
        self.logger = logger
        self.known_pids: Set[int] = set()
        self._baseline_pids()

    def _baseline_pids(self):
        for proc in psutil.process_iter(['pid']):
            try:
                self.known_pids.add(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        logging.info(f"[PROCESS-MONITOR] Baseline de processos ativo: {len(self.known_pids)} PIDs mapeados.")

    def scan_processes(self) -> List[Dict]:
        current_pids = set()
        new_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cmdline']):
            try:
                pid = proc.info.get('pid')
                if not pid:
                    continue
                current_pids.add(pid)
                name = (proc.info.get('name') or "Desconhecido").lower()
                exe = proc.info.get('exe') or "N/A"

                if pid not in self.known_pids:
                    # Verifica anomalia de nome suspeito
                    is_suspicious = name in self.SUSPICIOUS_NAMES
                    severity = "CRITICAL" if is_suspicious else "INFO"
                    category = "PROCESS_SUSPICIOUS" if is_suspicious else "PROCESS_NEW"
                    desc = f"{'🚨 PROCESSO SUSPEITO INICIADO' if is_suspicious else 'Novo processo iniciado'}. Nome: {name} | Executável: {exe}"

                    if self.logger:
                        self.logger.log_event(
                            severity, 
                            category, 
                            f"PID:{pid} ({name})", 
                            desc
                        )
                    if is_suspicious:
                        logging.critical(f"[PROCESS ALERT] {desc}")
                    new_processes.append({"pid": pid, "name": name, "exe": exe, "suspicious": is_suspicious})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        self.known_pids = current_pids
        return new_processes

    run_scan = scan_processes
    scan = scan_processes

ProcessAnomalyMonitor = ProcessMonitor

