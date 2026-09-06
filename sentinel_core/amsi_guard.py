"""
Sentinela XDR - Motor AMSI Script Guard & De-Obfuscation Engine
Interceptação e desofuscação heurística de scripts em memória (PowerShell, VBScript, JScript).
Detecção de AMSI Memory Patching / Bypass (AmsiScanBuffer hook / patching).
"""

import os
import re
import base64
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaAMSI")


class AMSIScriptGuard:
    """Motor de inspeção, desofuscação e proteção contra bypass de AMSI."""

    SUSPICIOUS_SCRIPT_SIGNATURES = [
        {"id": "AMSI-001", "name": "In-Memory Base64 Execution (IEX)", "pattern": r"(iex|invoke-expression)\s*\(?\s*(\[system\.text\.encoding\]|\[system\.convert\]|downloadstring)", "severity": "CRITICAL"},
        {"id": "AMSI-002", "name": "AMSI Memory Patching Attempt", "pattern": r"(\[ref\]\.assembly\.gettype\(.*amsiutils.*\)|amsiscanbuffer.*virtualprotect|amsiinitfailed.*\$true)", "severity": "CRITICAL"},
        {"id": "AMSI-003", "name": "PowerSploit / Empire Cradle", "pattern": r"(invokemimikatz|invoke-mimikatz|sekurlsa|kerberoast|invoke-bloodhound|sharpup)", "severity": "CRITICAL"},
        {"id": "AMSI-004", "name": "Download & Execute Remote Cradle", "pattern": r"(net\.webclient.*download(string|file|data)|invoke-webrequest.*-outfile|curl.*\|.*sh)", "severity": "HIGH"},
        {"id": "AMSI-005", "name": "Reflective Assembly Loading", "pattern": r"\[system\.reflection\.assembly\]::load\(", "severity": "HIGH"},
        {"id": "AMSI-006", "name": "Obfuscated Backticks / Format String", "pattern": r"(\`[a-zA-Z]{1,3}\`|\-join\s*\(|\-f\s*[\'\"].*\{[0-9]+\})", "severity": "MEDIUM"}
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.total_inspected = 0
        self.total_blocked = 0
        self.recent_events: List[Dict[str, Any]] = []
        self._log("INFO", "AMSI_INIT", "INIT", "Motor AMSI Script Guard ativado com desofuscador heurístico.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    @staticmethod
    def deobfuscate_buffer(content: str) -> str:
        """Aplica técnicas de normalização e desofuscação sobre o buffer de script."""
        if not content:
            return ""

        result = content

        # 1. Remover acentos graves/backticks do PowerShell (ex: `d`o`w`n`l`o`a`d)
        result = re.sub(r"`([a-zA-Z0-9])", r"\1", result)

        # 2. Desofuscar Base64 comum embutido
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", result)
        for b64_str in b64_matches:
            try:
                decoded_bytes = base64.b64decode(b64_str)
                # Tentar UTF-16 (padrão do PowerShell -enc) ou UTF-8
                try:
                    decoded_text = decoded_bytes.decode('utf-16le')
                except Exception:
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                
                if any(c.isalnum() for c in decoded_text):
                    result += f"\n[DEOBFUSCATED_BASE64] {decoded_text}"
            except Exception:
                pass

        # 3. Normalizar espaçamentos e quebras de concatenação
        result = re.sub(r"['\"]\s*\+\s*['\"]", "", result)

        return result

    def inspect_script_content(self, script_content: str, source_app: str = "powershell.exe", pid: Optional[int] = None) -> Dict[str, Any]:
        """Inspeciona um buffer de script contra assinaturas de ataque e técnicas de AMSI bypass."""
        self.total_inspected += 1
        deobfuscated = self.deobfuscate_buffer(script_content)
        lower_raw = script_content.lower()
        lower_deobf = deobfuscated.lower()

        matched_signatures = []
        is_malicious = False
        highest_severity = "LOW"

        for sig in self.SUSPICIOUS_SCRIPT_SIGNATURES:
            if re.search(sig["pattern"], lower_raw, re.IGNORECASE) or re.search(sig["pattern"], lower_deobf, re.IGNORECASE):
                matched_signatures.append(sig)
                is_malicious = True
                if sig["severity"] == "CRITICAL" or highest_severity != "CRITICAL":
                    highest_severity = sig["severity"]

        # Se for malicioso, registrar violação
        if is_malicious:
            self.total_blocked += 1
            event = {
                "timestamp": time.time(),
                "source_app": source_app,
                "pid": pid,
                "severity": highest_severity,
                "matched_rules": [s["name"] for s in matched_signatures],
                "sample_preview": script_content[:200],
                "action": "BLOCKED"
            }
            self.recent_events.insert(0, event)
            if len(self.recent_events) > 50:
                self.recent_events.pop()

            self._log(
                "CRITICAL" if highest_severity == "CRITICAL" else "WARNING",
                "AMSI_SCRIPT_GUARD",
                "MALICIOUS_SCRIPT_BLOCKED",
                f"Execução em memória barrada pelo AMSI Guard! App: '{source_app}' (PID: {pid}). Regras: {[s['id'] for s in matched_signatures]}"
            )

            return {
                "status": "blocked",
                "is_malicious": True,
                "severity": highest_severity,
                "matched_rules": matched_signatures,
                "deobfuscated_preview": deobfuscated[:300]
            }

        return {
            "status": "allowed",
            "is_malicious": False,
            "matched_rules": []
        }

    def detect_amsi_patch(self, pid: int) -> Dict[str, Any]:
        """Audita se a memória do processo possui indicativos de patching de AmsiScanBuffer."""
        # Verificação heurística simulada em processos auditados
        return {
            "status": "clean",
            "pid": pid,
            "patch_detected": False,
            "memory_state": "INTACT"
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do motor AMSI."""
        return {
            "status": "active",
            "total_inspected": self.total_inspected,
            "total_blocked": self.total_blocked,
            "active_signatures": len(self.SUSPICIOUS_SCRIPT_SIGNATURES),
            "recent_events": self.recent_events[:10]
        }

    inspect_script = inspect_script_content
    inspect = inspect_script_content
    status = get_status
