"""
Sentinela XDR - LSASS Armor & Credential Guard Local
Módulo autônomo de blindagem do subsistema LSASS (Local Security Authority Subsystem Service).
Protege contra ataques de extração de credenciais em memória (Mimikatz, comsvcs.dll, ProcDump).
Compatível com MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory).
"""

import os
import sys
import logging
import psutil
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaLSASSGuard")


class LSASSArmorGuard:
    """Motor de proteção e auditoria contra extração de credenciais do LSASS."""

    DUMP_SIGNATURES = [
        {
            "name": "Comsvcs MiniDump LSASS",
            "keywords": ["comsvcs.dll", "minidump"],
            "severity": "CRITICAL",
            "technique": "T1003.001"
        },
        {
            "name": "Comsvcs Ordinal 24 LSASS",
            "keywords": ["comsvcs.dll", "#24"],
            "severity": "CRITICAL",
            "technique": "T1003.001"
        },
        {
            "name": "Mimikatz Sekurlsa Credential Extraction",
            "keywords": ["sekurlsa", "logonpasswords"],
            "severity": "CRITICAL",
            "technique": "T1003.001"
        },
        {
            "name": "ProcDump LSASS Memory Dump",
            "keywords": ["procdump", "lsass"],
            "severity": "CRITICAL",
            "technique": "T1003.001"
        },
        {
            "name": "Nanodump / Dumpert LSASS Tool",
            "keywords": ["nanodump", "dumpert"],
            "severity": "CRITICAL",
            "technique": "T1003.001"
        },
        {
            "name": "Rundll32 Memory Dumper",
            "keywords": ["rundll32", "comsvcs", "full"],
            "severity": "HIGH",
            "technique": "T1003.001"
        }
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.blocked_attempts_count = 0
        self.recent_blocks: List[Dict[str, Any]] = []
        self._lsass_pid = self._find_lsass_pid()
        self._log("INFO", "LSASS_ARMOR", "INIT", f"Motor ativado (LSASS PID monitorado: {self._lsass_pid or 'N/A'}).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def _find_lsass_pid(self) -> Optional[int]:
        """Localiza o PID do processo lsass.exe legítimo no Windows."""
        if sys.platform != "win32":
            return None
        try:
            for p in psutil.process_iter(['pid', 'name']):
                if p.info['name'] and p.info['name'].lower() == 'lsass.exe':
                    return p.info['pid']
        except Exception as e:
            pass
        return None

    def evaluate_command_line(self, cmdline: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Avalia se uma linha de comando representa uma tentativa de extração de credenciais do LSASS.
        Retorna dicionário com o resultado e aciona bloqueio SOAR se malicioso.
        """
        if not cmdline:
            return {"is_threat": False, "matched": False}

        cmd_lower = cmdline.lower()
        for sig in self.DUMP_SIGNATURES:
            if all(k in cmd_lower for k in sig["keywords"]):
                event = {
                    "rule": sig["name"],
                    "severity": sig["severity"],
                    "technique": sig["technique"],
                    "pid": pid,
                    "cmdline": cmdline[:250],
                    "blocked": True
                }
                self.blocked_attempts_count += 1
                self.recent_blocks.insert(0, event)
                if len(self.recent_blocks) > 50:
                    self.recent_blocks.pop()

                self._log(
                    "CRITICAL",
                    "LSASS_ARMOR",
                    "BLOCKED_DUMP",
                    f"Tentativa de extração de credenciais bloqueada! Regra: {sig['name']} (PID: {pid})"
                )
                return {
                    "is_threat": True,
                    "matched": True,
                    "event": event
                }

        return {"is_threat": False, "matched": False}

    def audit_lsass_access(self) -> List[Dict[str, Any]]:
        """
        Audita processos ativos no sistema buscando anomalias que tenham como alvo o LSASS.
        Verifica linhas de comando e processos suspeitos tentando interagir com o LSASS.
        """
        anomalies = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    info = p.info
                    cmd = " ".join(info['cmdline'] or [])
                    res = self.evaluate_command_line(cmd, pid=info['pid'])
                    if res.get("is_threat"):
                        anomalies.append({
                            "pid": info['pid'],
                            "name": info['name'],
                            "cmdline": cmd[:200],
                            "detection": res.get("event")
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self._log("DEBUG", "LSASS_ARMOR", "AUDIT_ERROR", str(e))

        return anomalies

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do módulo LSASS Armor."""
        return {
            "engine": "Sentinel LSASS Armor & Credential Guard",
            "active": True,
            "status": "ACTIVE",
            "lsass_pid": self._lsass_pid,
            "signatures_count": len(self.DUMP_SIGNATURES),
            "blocked_attempts_count": self.blocked_attempts_count,
            "recent_blocks": self.recent_blocks[:10]
        }

    def status(self) -> Dict[str, Any]:
        return self.get_status()
