# sentinel_core/process_guard.py
import os
import sys
import time
import logging
import subprocess
from typing import List, Dict, Any, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class EDRProcessGuard:
    """
    Endpoint Detection & Response (EDR) Process Guard — Modo Brutal / Hardened.
    Monitora a árvore de processos do SO, detectando comportamentos de Ransomware,
    tentativas de deleção de cópias de sombra (VSS), dump de credenciais LSASS,
    ataques Living-off-the-Land (LOLBins) e executando neutralização forçada da árvore de processos.
    """

    # Assinaturas Comportamentais Críticas de Ransomware & Invasores
    CRITICAL_SIGNATURES = [
        # Ransomware / Destruição de Backups e Shadow Copies
        {"rule": "VSS_DELETION", "keywords": ["vssadmin", "delete", "shadows"], "severity": "CRITICAL"},
        {"rule": "WMIC_SHADOW_KILL", "keywords": ["wmic", "shadowcopy", "delete"], "severity": "CRITICAL"},
        {"rule": "WBADMIN_CATALOG_DELETE", "keywords": ["wbadmin", "delete", "catalog"], "severity": "CRITICAL"},
        {"rule": "BCDEDIT_RECOVERY_TAMPER", "keywords": ["bcdedit", "recoveryenabled", "no"], "severity": "CRITICAL"},
        {"rule": "BCDEDIT_BOOT_IGNORE", "keywords": ["bcdedit", "bootstatuspolicy", "ignoreallfailures"], "severity": "CRITICAL"},
        {"rule": "EVENTLOG_WIPING", "keywords": ["wevtutil", "cl", "security"], "severity": "CRITICAL"},
        
        # Dump de Credenciais & Roubo de Senhas
        {"rule": "MIMIKATZ_LSASS_DUMP", "keywords": ["mimikatz"], "severity": "CRITICAL"},
        {"rule": "PROCDUMP_LSASS", "keywords": ["procdump", "lsass"], "severity": "CRITICAL"},
        {"rule": "COMSVCS_MINIDUMP", "keywords": ["comsvcs.dll", "minidump"], "severity": "CRITICAL"},
        
        # LOLBins / Downloaders Ocultos / Obfuscated Shell
        {"rule": "POWERSHELL_ENCODED", "keywords": ["powershell", "-enc"], "severity": "HIGH"},
        {"rule": "POWERSHELL_HIDDEN_EXEC", "keywords": ["powershell", "-w", "hidden", "-enc"], "severity": "CRITICAL"},
        {"rule": "CERTUTIL_PAYLOAD_DOWNLOAD", "keywords": ["certutil", "-urlcache", "-split"], "severity": "HIGH"},
        {"rule": "BITSADMIN_TRANSFER", "keywords": ["bitsadmin", "/transfer"], "severity": "HIGH"},
        {"rule": "MSHTA_INLINE_PAYLOAD", "keywords": ["mshta", "http"], "severity": "HIGH"},
        {"rule": "RUNDLL32_JAVASCRIPT", "keywords": ["rundll32", "javascript:"], "severity": "CRITICAL"}
    ]

    SYSTEM_PROTECTED_PROCESSES = {
        "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", 
        "services.exe", "svchost.exe", "system", "idle", "explorer.exe"
    }

    def __init__(self, logger=None):
        self.logger = logger
        self.monitored_pids: set = set()
        self.terminated_history: List[Dict[str, Any]] = []

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def scan_active_processes(self) -> List[Dict[str, Any]]:
        """Varre a lista de processos buscando assinaturas comportamentais e comandos suspeitos."""
        threats_found = []

        if not HAS_PSUTIL:
            self._log("WARNING", "EDR_GUARD", "MISSING_DEP", "Biblioteca 'psutil' não encontrada. Instale para EDR nativo.")
            return threats_found

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or "").lower()

                # Ignora processos protegidos do próprio Windows
                if pname in self.SYSTEM_PROTECTED_PROCESSES or pinfo['pid'] <= 4:
                    continue

                cmdline_tokens = [t.lower() for t in (pinfo['cmdline'] or [])]
                cmdline_str = " ".join(cmdline_tokens)

                # 1. Checagem por matriz de assinaturas de alta precisão
                for sig in self.CRITICAL_SIGNATURES:
                    keywords = sig["keywords"]
                    # Verifica se todas as palavras-chave da regra estão presentes na linha de comando
                    if all(kw in cmdline_str for kw in keywords) or (len(keywords) == 1 and keywords[0] in pname):
                        threat_info = {
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "cmdline": cmdline_str,
                            "rule": sig["rule"],
                            "severity": sig["severity"],
                            "timestamp": time.time()
                        }
                        threats_found.append(threat_info)
                        self._log(
                            sig["severity"], "EDR_GUARD", "SUSPICIOUS_PROC", 
                            f"Processo hostil interceptado pelo EDR: PID {pinfo['pid']} ({pname}) - Regra: {sig['rule']}"
                        )
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return threats_found

    def terminate_process(self, pid: int, reason: str = "Ameaça EDR detectada") -> bool:
        """Encerra um processo e toda sua árvore de subprocessos com força total (Kill Process Tree)."""
        try:
            if HAS_PSUTIL:
                parent = psutil.Process(pid)
                # Encerra recursivamente todos os filhos para não deixar processos zumbis/trojans soltos
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                parent.kill()
            else:
                if sys.platform == "win32":
                    subprocess.run(f"taskkill /F /PID {pid} /T", shell=True, capture_output=True)
                else:
                    subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True)

            event = {
                "pid": pid,
                "reason": reason,
                "status": "TERMINATED",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            self.terminated_history.append(event)
            self._log("CRITICAL", "EDR_GUARD", "PROCESS_KILLED", f"Árvore de execução neutralizada: PID {pid}. Motivo: {reason}")
            return True

        except Exception as e:
            self._log("ERROR", "EDR_GUARD", "KILL_FAILED", f"Falha ao encerrar PID {pid}: {e}")
            return False

    def auto_remediate(self) -> int:
        """Varre e extermina automaticamente processos com assinaturas hostis ativas."""
        threats = self.scan_active_processes()
        killed_count = 0
        for threat in threats:
            if threat["severity"] in ["CRITICAL", "HIGH"]:
                success = self.terminate_process(threat["pid"], reason=f"Auto-Remediação EDR: {threat['rule']}")
                if success:
                    killed_count += 1
        return killed_count

    def get_edr_threats(self) -> List[Dict[str, Any]]:
        """Retorna as ameaças ativas em tempo real."""
        return self.scan_active_processes()
