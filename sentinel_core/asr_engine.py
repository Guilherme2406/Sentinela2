"""
Sentinela XDR - Motor de Redução de Superfície de Ataque (ASR - Attack Surface Reduction)
Módulo corporativo inspirado nas regras ASR do Microsoft Defender e CrowdStrike.
Impede a propagação de infecções iniciais por phishing, macros de Office e executáveis maliciosos em pastas temporárias.
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaASREngine")


class ASREngine:
    """Motor de execução e auditoria de regras ASR (Attack Surface Reduction)."""

    DEFAULT_RULES = [
        {
            "id": "ASR-001",
            "name": "Bloquear criação de processos filhos por aplicações do Microsoft Office",
            "description": "Impede que Word, Excel, PowerPoint ou Outlook gerem shells ou interpretadores de scripts.",
            "parents": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
            "blocked_children": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"],
            "severity": "CRITICAL",
            "technique": "T1059.001 / T1204.002",
            "enabled": True,
            "mode": "BLOCK"
        },
        {
            "id": "ASR-002",
            "name": "Bloquear criação de processos filhos por leitores de PDF (Adobe Reader)",
            "description": "Impede a exploração de arquivos PDF maliciosos tentando iniciar interpretadores de comando.",
            "parents": ["acrobat.exe", "acrord32.exe", "foxitreader.exe"],
            "blocked_children": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe"],
            "severity": "HIGH",
            "technique": "T1204.002",
            "enabled": True,
            "mode": "BLOCK"
        },
        {
            "id": "ASR-003",
            "name": "Bloquear executáveis e scripts suspeitos em pastas temporárias (Temp/AppData)",
            "description": "Bloqueia a execução de binários suspeitos disparados diretamente de diretórios voláteis.",
            "target_dirs": ["\\temp\\", "\\appdata\\local\\temp\\", "c:\\windows\\temp\\"],
            "target_extensions": [".bat", ".vbs", ".js", ".ps1", ".hta"],
            "severity": "HIGH",
            "technique": "T1059 / T1036",
            "enabled": True,
            "mode": "BLOCK"
        },
        {
            "id": "ASR-004",
            "name": "Bloquear ferramentas de linha de comando legítimas de fazerem download de payloads",
            "description": "Impede o abuso de binários nativos do Windows (LOLBins) para baixar malwares da internet.",
            "signatures": [
                {"bin": "certutil.exe", "flags": ["-urlcache", "-split"]},
                {"bin": "bitsadmin.exe", "flags": ["/transfer", "http"]},
                {"bin": "regsvr32.exe", "flags": ["/s", "/u", "/i:http"]}
            ],
            "severity": "CRITICAL",
            "technique": "T1105 (Ingress Tool Transfer)",
            "enabled": True,
            "mode": "BLOCK"
        }
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.rules = [dict(r) for r in self.DEFAULT_RULES]
        self.violations_count = 0
        self.recent_violations: List[Dict[str, Any]] = []
        self._log("INFO", "ASR_ENGINE", "INIT", f"Motor de Redução de Superfície de Ataque ativado ({len(self.rules)} regras operacionais).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def evaluate_process_spawn(
        self,
        parent_name: str,
        child_name: str,
        cmdline: str = "",
        child_path: str = ""
    ) -> Dict[str, Any]:
        """
        Avalia o nascimento de um processo filho e sua linha de comando contra as regras ASR.
        Retorna se a ação deve ser bloqueada ou auditada.
        """
        parent_clean = (parent_name or "").lower().strip()
        child_clean = (child_name or "").lower().strip()
        cmd_clean = (cmdline or "").lower()
        path_clean = (child_path or "").lower()

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            # Regra 1 e 2: Parent -> Child
            if "parents" in rule and "blocked_children" in rule:
                if any(p in parent_clean for p in rule["parents"]):
                    if any(c in child_clean for c in rule["blocked_children"]):
                        return self._record_violation(rule, parent_name, child_name, cmdline)

            # Regra 3: Pastas Temporárias
            if "target_dirs" in rule and "target_extensions" in rule:
                in_temp = any(td in path_clean or td in cmd_clean for td in rule["target_dirs"])
                has_ext = any(cmd_clean.endswith(ext) or (ext + " ") in cmd_clean for ext in rule["target_extensions"])
                if in_temp and has_ext:
                    return self._record_violation(rule, parent_name, child_name, cmdline)

            # Regra 4: LOLBins Download
            if "signatures" in rule:
                for sig in rule["signatures"]:
                    if sig["bin"] in child_clean or sig["bin"] in cmd_clean:
                        if all(f in cmd_clean for f in sig["flags"]):
                            return self._record_violation(rule, parent_name, child_name, cmdline)

        return {"is_violation": False, "blocked": False}

    def _record_violation(self, rule: Dict[str, Any], parent: str, child: str, cmdline: str) -> Dict[str, Any]:
        """Registra a violação da regra ASR nos logs e no histórico."""
        self.violations_count += 1
        event = {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "technique": rule["technique"],
            "parent": parent,
            "child": child,
            "cmdline": cmdline[:200],
            "mode": rule.get("mode", "BLOCK"),
            "blocked": rule.get("mode", "BLOCK") == "BLOCK"
        }
        self.recent_violations.insert(0, event)
        if len(self.recent_violations) > 50:
            self.recent_violations.pop()

        self._log(
            "WARNING",
            "ASR_VIOLATION",
            rule["id"],
            f"Regra '{rule['id']}' disparada! Processo '{parent}' tentou gerar '{child}'. Ação: {rule.get('mode', 'BLOCK')}"
        )

        return {
            "is_violation": True,
            "blocked": rule.get("mode", "BLOCK") == "BLOCK",
            "event": event
        }

    def get_rules(self) -> List[Dict[str, Any]]:
        """Retorna as regras ASR cadastradas."""
        return self.rules

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do motor ASR."""
        return {
            "engine": "Sentinel Attack Surface Reduction (ASR) Engine",
            "active": True,
            "total_rules": len(self.rules),
            "violations_count": self.violations_count,
            "recent_violations": self.recent_violations[:10]
        }
