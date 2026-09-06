"""
Sentinela XDR - Motor Anti-Ransomware VSS & MBR/Wiper Shield
Bloqueio em tempo real de destruição de Cópias de Sombra de Volume (VSS),
desativação de inicialização/recuperação BCDEdit e proteção contra Wipers de disco bruto.
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaVSSShield")


class RansomwareVSSShield:
    """Motor de proteção de Shadow Copies (VSS), BCDEdit e integridade de MBR."""

    RANSOMWARE_TACTICS = [
        {"id": "VSS-001", "name": "VSSAdmin Shadow Delete", "pattern": r"vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)", "severity": "CRITICAL"},
        {"id": "VSS-002", "name": "WMIC ShadowCopy Destruction", "pattern": r"wmic(\.exe)?\s+shadowcopy\s+delete", "severity": "CRITICAL"},
        {"id": "VSS-003", "name": "WBAdmin Backup Catalog Wipe", "pattern": r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)", "severity": "CRITICAL"},
        {"id": "VSS-004", "name": "BCDEdit Recovery Disablement", "pattern": r"bcdedit(\.exe)?\s+/set\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", "severity": "CRITICAL"},
        {"id": "VSS-005", "name": "PowerShell VSS Removal", "pattern": r"(get-wmiobject|get-ciminstance)\s+win32_shadowcopy.*\|\s*(remove-wmiobject|\.delete\(\))", "severity": "CRITICAL"},
        {"id": "WIPER-001", "name": "Raw Physical Drive Direct Access", "pattern": r"(\\\\\.\\physicaldrive[0-9]+|\\\\\\.\\([a-zA-Z]):)", "severity": "CRITICAL"},
        {"id": "WIPER-002", "name": "FSUTIL UsnJournal Deletion", "pattern": r"fsutil(\.exe)?\s+usn\s+deletejournal", "severity": "HIGH"}
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.total_evaluations = 0
        self.total_blocked = 0
        self.recent_blocks: List[Dict[str, Any]] = []
        self._log("INFO", "VSS_SHIELD_INIT", "INIT", "Motor Anti-Ransomware VSS & Wiper Shield ativado.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def inspect_command(self, cmdline: str, parent_process: str = "", pid: Optional[int] = None) -> Dict[str, Any]:
        """Inspeciona comandos executados no sistema em busca de táticas pré-ransomware."""
        self.total_evaluations += 1
        if not cmdline:
            return {"status": "allowed", "blocked": False}

        cmd_clean = cmdline.lower().strip()
        matched = []

        for tactic in self.RANSOMWARE_TACTICS:
            if re.search(tactic["pattern"], cmd_clean, re.IGNORECASE):
                matched.append(tactic)

        if matched:
            self.total_blocked += 1
            highest_rule = matched[0]
            event = {
                "timestamp": time.time(),
                "rule_id": highest_rule["id"],
                "rule_name": highest_rule["name"],
                "severity": highest_rule["severity"],
                "cmdline": cmdline[:250],
                "parent_process": parent_process,
                "pid": pid,
                "action": "BLOCKED"
            }
            self.recent_blocks.insert(0, event)
            if len(self.recent_blocks) > 50:
                self.recent_blocks.pop()

            self._log(
                "CRITICAL",
                "RANSOMWARE_VSS_SHIELD",
                "DESTRUCTION_PREVENTED",
                f"Tática de destruição de backups/recuperação bloqueada! Regra: '{highest_rule['name']}' Comutador: '{cmdline[:120]}'"
            )

            return {
                "status": "blocked",
                "blocked": True,
                "is_threat": True,
                "rule_id": highest_rule["id"],
                "rule_name": highest_rule["name"],
                "severity": highest_rule["severity"],
                "reason": "Tentativa de neutralização de Shadow Copies ou manipulação destrutiva de boot interceptada."
            }

        return {"status": "allowed", "blocked": False, "is_threat": False}


    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do escudo VSS & Wiper."""
        return {
            "status": "active",
            "total_evaluations": self.total_evaluations,
            "total_blocked": self.total_blocked,
            "tactics_monitored": len(self.RANSOMWARE_TACTICS),
            "recent_blocks": self.recent_blocks[:10]
        }

    evaluate_command_line = inspect_command
    status = get_status

