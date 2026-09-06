"""
Sentinela XDR - Motor Application Control & LOLBAS Blocker
Controle de aplicação e prevenção de abuso de binários legítimos do Windows (Living Off The Land Binaries),
incluindo certutil, bitsadmin, mshta, rundll32, regsvr32 e wmic.
"""

import re
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaLOLBAS")


class LOLBASGuard:
    """Motor de controle de aplicação e bloqueio de técnicas LOLBAS."""

    LOLBAS_RULES = [
        {
            "id": "LOLBAS-001",
            "name": "Certutil Remote Payload Download",
            "binary": "certutil.exe",
            "pattern": r"certutil(\.exe)?\s+.*(-urlcache|-split|-f\s+http)",
            "severity": "CRITICAL",
            "mitre": "T1105 - Ingress Tool Transfer"
        },
        {
            "id": "LOLBAS-002",
            "name": "Bitsadmin Background File Transfer",
            "binary": "bitsadmin.exe",
            "pattern": r"bitsadmin(\.exe)?\s+.*(/transfer|/create|/addfile)",
            "severity": "HIGH",
            "mitre": "T1197 - BITS Jobs"
        },
        {
            "id": "LOLBAS-003",
            "name": "Mshta Inline Remote Script Execution",
            "binary": "mshta.exe",
            "pattern": r"mshta(\.exe)?\s+.*(https?://|vbscript:|javascript:)",
            "severity": "CRITICAL",
            "mitre": "T1218.005 - Mshta"
        },
        {
            "id": "LOLBAS-004",
            "name": "Regsvr32 Remote Scriptlet (Squiblydoo)",
            "binary": "regsvr32.exe",
            "pattern": r"regsvr32(\.exe)?\s+.*(/s\s+/n\s+/u\s+/i:|scrobj\.dll)",
            "severity": "CRITICAL",
            "mitre": "T1218.010 - Regsvr32"
        },
        {
            "id": "LOLBAS-005",
            "name": "Rundll32 Execution from Temp/AppData",
            "binary": "rundll32.exe",
            "pattern": r"rundll32(\.exe)?\s+.*(appdata|temp|tmp|\.bin|\.dat|\.txt)",
            "severity": "HIGH",
            "mitre": "T1218.011 - Rundll32"
        },
        {
            "id": "LOLBAS-006",
            "name": "WMIC Process Remote Spawning",
            "binary": "wmic.exe",
            "pattern": r"wmic(\.exe)?\s+.*(process\s+call\s+create|process\s+create)",
            "severity": "HIGH",
            "mitre": "T1047 - Windows Management Instrumentation"
        }
    ]

    def __init__(self, logger_instance=None, mode: str = "BLOCK"):
        self.logger = logger_instance
        self.mode = mode  # "BLOCK" ou "AUDIT"
        self.total_inspected: int = 0
        self.total_blocked: int = 0
        self.recent_events: List[Dict[str, Any]] = []
        self._log("INFO", "LOLBAS_INIT", "INIT", f"Motor LOLBAS Blocker operacional (Modo: {self.mode}, {len(self.LOLBAS_RULES)} regras ativas).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def inspect_process_execution(self, cmdline: str, parent: str = "", pid: Optional[int] = None) -> Dict[str, Any]:
        """Inspeciona comandos executados no host em busca de abuso de utilitários LOLBAS."""
        self.total_inspected += 1
        if not cmdline:
            return {"status": "allowed", "blocked": False}

        cmd_clean = cmdline.lower().strip()
        matched_rules = []

        for rule in self.LOLBAS_RULES:
            if re.search(rule["pattern"], cmd_clean, re.IGNORECASE):
                matched_rules.append(rule)

        # 2. Avaliação de Ofuscação Avançada de Comandos (Entropia e Evasão)
        try:
            from sentinel_core.command_obfuscation_classifier import CommandObfuscationClassifier
            obf_classifier = CommandObfuscationClassifier()
            obf_result = obf_classifier.analyze_command(cmdline)
            if obf_result.get("is_obfuscated") and obf_result.get("score", 0.0) >= 0.70:
                matched_rules.append({
                    "id": "LOLBAS-OBF-001",
                    "name": f"High Obfuscation Command Evasion ({', '.join(obf_result['indicators'][:2])})",
                    "binary": "script_interpreter",
                    "severity": obf_result["risk_level"],
                    "mitre": "T1027 - Obfuscated Files or Information"
                })
        except Exception:
            obf_result = {}

        if matched_rules:
            highest_rule = matched_rules[0]
            is_block = (self.mode == "BLOCK")
            if is_block:
                self.total_blocked += 1

            event = {
                "timestamp": time.time(),
                "rule_id": highest_rule["id"],
                "rule_name": highest_rule["name"],
                "severity": highest_rule["severity"],
                "mitre": highest_rule["mitre"],
                "cmdline": cmdline[:250],
                "parent_process": parent,
                "pid": pid,
                "action": "BLOCKED" if is_block else "AUDITED"
            }
            self.recent_events.insert(0, event)
            if len(self.recent_events) > 50:
                self.recent_events.pop()

            self._log(
                highest_rule["severity"],
                "LOLBAS_GUARD",
                "ATTACK_INTERCEPTED",
                f"Tática LOLBAS interceptada: {highest_rule['name']} ({highest_rule['mitre']})! Processo/Cmd: '{cmdline[:120]}'"
            )

            return {
                "status": "blocked" if is_block else "flagged",
                "blocked": is_block,
                "rule_id": highest_rule["id"],
                "rule_name": highest_rule["name"],
                "severity": highest_rule["severity"],
                "mitre": highest_rule["mitre"],
                "reason": f"Tentativa de abuso de utilitário do sistema ({highest_rule['binary']}) para fins maliciosos.",
                "obfuscation": obf_result
            }

        return {"status": "allowed", "blocked": False, "obfuscation": obf_result}

    def set_mode(self, new_mode: str) -> str:
        """Altera o modo de operação entre BLOCK e AUDIT."""
        if new_mode.upper() in ["BLOCK", "AUDIT"]:
            self.mode = new_mode.upper()
            self._log("INFO", "LOLBAS_MODE", "CHANGED", f"Modo de operação LOLBAS alterado para {self.mode}.")
        return self.mode

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do motor LOLBAS."""
        return {
            "status": "active",
            "mode": self.mode,
            "total_inspected": self.total_inspected,
            "total_blocked": self.total_blocked,
            "rules_count": len(self.LOLBAS_RULES),
            "recent_events": self.recent_events[:10]
        }
