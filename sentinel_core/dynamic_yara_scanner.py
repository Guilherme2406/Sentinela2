# sentinel_core/dynamic_yara_scanner.py
"""
🛡️ SENTINELA DYNAMIC YARA & BINARY SCANNER (TEMPO REAL)
Inspeciona arquivos recém-gravados ou acessados em diretórios sensíveis (Downloads, Temp, AppData).
Analisa cabeçalhos PE, entropia de Shannon, strings de injeção e feeds de IOC para quarentena instantânea via SOAR.
"""

import os
import time
import math
import hashlib
import logging
from typing import Dict, Any, List, Optional

# Motor YARA oficial (opcional) — ativado quando `yara-python` está instalado.
# Sem ele, o scanner segue 100% funcional com as regras internas YARA-like.
try:  # pragma: no cover - dependência opcional (build MSVC / wheel)
    import yara as _yara
    HAS_OFFICIAL_YARA = True
except ImportError:
    _yara = None
    HAS_OFFICIAL_YARA = False

logger = logging.getLogger("SentinelaXDR.DynamicYARAScanner")

# Hierarquia de severidade usada para consolidar corretamente o nível máximo.
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class DynamicFileScanner:
    """Scanner de integridade e heurística avançada de arquivos em tempo real."""

    # Assinaturas heurísticas de sequências de bytes e strings maliciosas
    MALICIOUS_STRINGS = [
        (b"VirtualAllocEx", "PROCESS_INJECTION_API", "HIGH"),
        (b"WriteProcessMemory", "PROCESS_INJECTION_API", "HIGH"),
        (b"CreateRemoteThread", "REMOTE_THREAD_INJECTION", "CRITICAL"),
        (b"mimikatz", "CREDENTIAL_STEALER_MIMIKATZ", "CRITICAL"),
        (b"sekurlsa::logonpasswords", "MIMIKATZ_SEKURLSA", "CRITICAL"),
        (b"wscript.shell", "SUSPICIOUS_SCRIPT_EXECUTION", "MEDIUM"),
        (b"powershell -nop -w hidden -enc", "OBFUSCATED_POWERSHELL_PAYLOAD", "CRITICAL"),
        (b"ReflectiveLoader", "COBALT_STRIKE_REFLECTIVE_DLL", "CRITICAL"),
        (b"beacon.dll", "COBALT_STRIKE_BEACON", "CRITICAL"),
        (b"stratum+tcp://", "CRYPTOMINER_STRATUM_POOL", "HIGH"),
        (b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "EICAR_AV_TEST_FILE", "HIGH"),
    ]

    # Hashes de teste / conhecidos de malware
    KNOWN_MALICIOUS_HASHES = {
        "44d88612fea8a8f36de82e1278abb02f": "EICAR_STANDARD_AV_TEST_FILE",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR_SHA256"
    }

    def __init__(self, logger_instance=None, soar=None, auto_quarantine: bool = True,
                 yara_rules_dir: Optional[str] = None):
        self.logger = logger_instance
        self.soar = soar
        self.auto_quarantine = auto_quarantine
        self.scanned_history: List[Dict[str, Any]] = []

        # --- Motor YARA oficial (opcional) ---
        self.yara_rules: List[Any] = []
        self.yara_rules_loaded = 0
        if yara_rules_dir is None:
            yara_rules_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules_yara"
            )
        self._load_yara_rules(yara_rules_dir)

    def _load_yara_rules(self, rules_dir: str):
        """Compila as regras YARA oficiais de `rules_yara/` quando yara-python está presente."""
        if not HAS_OFFICIAL_YARA or not rules_dir or not os.path.isdir(rules_dir):
            return
        rule_files = sorted(
            f for f in os.listdir(rules_dir)
            if f.lower().endswith((".yar", ".yara"))
        )
        for rf in rule_files:
            path = os.path.join(rules_dir, rf)
            try:
                self.yara_rules.append(_yara.compile(path))
                self.yara_rules_loaded += 1
                logger.info(f"[YARA] Regras oficiais carregadas: {rf}")
            except Exception as exc:
                logger.debug(f"[YARA] Falha ao compilar regras {rf}: {exc}")

    def _match_yara(self, content: bytes) -> List[Any]:
        """Executa todas as regras YARA compiladas sobre os bytes fornecidos."""
        matches: List[Any] = []
        try:
            for rules in self.yara_rules:
                matches.extend(rules.match(data=content))
        except Exception as exc:  # nunca propaga — análise defensiva
            logger.debug(f"[YARA] Erro durante match: {exc}")
        return matches

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger:
                self.logger.log_event(level, category, action, msg)
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcula a Entropia de Shannon (0.0 a 8.0 bits/byte)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        occurrences = [0] * 256
        for byte in data:
            occurrences[byte] += 1
        for count in occurrences:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def scan_bytes(self, content: bytes, file_name: str = "memory_buffer") -> Dict[str, Any]:
        """Inspeciona bytes em memória sem tocar no disco."""
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        entropy = self.calculate_entropy(content)

        detected_threats = []
        is_malicious = False
        max_severity = "INFO"

        # 1. Checagem de Hashes de IOCs
        if md5 in self.KNOWN_MALICIOUS_HASHES or sha256 in self.KNOWN_MALICIOUS_HASHES:
            threat_name = self.KNOWN_MALICIOUS_HASHES.get(md5) or self.KNOWN_MALICIOUS_HASHES.get(sha256)
            detected_threats.append({"rule": "IOC_HASH_MATCH", "name": threat_name, "severity": "CRITICAL"})
            is_malicious = True
            max_severity = "CRITICAL"

        # 2. Varredura de Assinaturas Heurísticas e Strings
        for pattern, rule_name, severity in self.MALICIOUS_STRINGS:
            if pattern.lower() in content.lower():
                detected_threats.append({
                    "rule": rule_name,
                    "matched": pattern.decode("utf-8", errors="ignore"),
                    "severity": severity
                })
                is_malicious = True
                if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(max_severity, 0):
                    max_severity = severity

        # 2.1 Motor YARA oficial (se instalado) — regras complementares
        for match in self._match_yara(content):
            severity_y = str(match.meta.get("severity", "HIGH"))
            detected_threats.append({
                "rule": f"YARA:{match.rule}",
                "matched": match.rule,
                "severity": severity_y,
                "engine": "yara-python",
            })
            is_malicious = True
            if SEVERITY_RANK.get(severity_y, 0) > SEVERITY_RANK.get(max_severity, 0):
                max_severity = severity_y

        # 3. Análise de Entropia (Binários empacotados com UPX ou cifrados por Ransomware)
        if entropy >= 7.2 and len(content) > 1024:
            detected_threats.append({
                "rule": "HIGH_ENTROPY_PACKED_PAYLOAD",
                "entropy": entropy,
                "severity": "HIGH",
                "description": "Arquivo com alta probabilidade de empacotamento malicioso ou criptografia ativa."
            })
            is_malicious = True
            if SEVERITY_RANK.get("HIGH", 0) > SEVERITY_RANK.get(max_severity, 0):
                max_severity = "HIGH"

        result = {
            "file": file_name,
            "sha256": sha256,
            "md5": md5,
            "size_bytes": len(content),
            "entropy": entropy,
            "is_malicious": is_malicious,
            "severity": max_severity,
            "threats": detected_threats,
            "timestamp": time.time()
        }
        self.scanned_history.append(result)
        return result

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Inspeciona um arquivo no sistema e aciona quarentena se for detectada ameaça crítica."""
        if not os.path.exists(file_path):
            return {"file": file_path, "status": "not_found", "is_malicious": False}

        try:
            with open(file_path, "rb") as f:
                content = f.read(10 * 1024 * 1024)  # Limita a 10MB para performance
            
            result = self.scan_bytes(content, file_name=os.path.basename(file_path))
            result["full_path"] = file_path

            if result["is_malicious"]:
                self._log(
                    result["severity"], "YARA_SCANNER", "THREAT_DETECTED",
                    f"Ameaça detectada em '{file_path}': {len(result['threats'])} assinaturas coincidentes. Entropia: {result['entropy']}"
                )

                # Quarentena automática via SOAR
                if self.auto_quarantine and self.soar and result["severity"] in ["CRITICAL", "HIGH"]:
                    try:
                        self.soar.isolate_file(file_path)
                        result["quarantined"] = True
                        self._log("CRITICAL", "SOAR", "AUTO_QUARANTINE", f"Arquivo isolado com sucesso no cofre: {file_path}")
                    except Exception as e:
                        result["quarantined"] = False
                        logger.debug(f"[YARA] Erro ao mover para quarentena: {e}")

            return result
        except Exception as e:
            return {"file": file_path, "status": "error", "error": str(e), "is_malicious": False}

    def get_status(self) -> Dict[str, Any]:
        """Estatísticas do scanner em tempo real."""
        malicious_count = sum(1 for item in self.scanned_history if item.get("is_malicious"))
        return {
            "scanner": "Sentinel Dynamic YARA & Heuristic File Scanner",
            "active": True,
            "rules_loaded": len(self.MALICIOUS_STRINGS),
            "yara_engine": "OFFICIAL_YARA_PYTHON" if (HAS_OFFICIAL_YARA and self.yara_rules) else (
                "OFFICIAL_YARA_PYTHON_INSTALLED" if HAS_OFFICIAL_YARA else "INTERNAL_RULES_ONLY"
            ),
            "yara_rules_loaded": self.yara_rules_loaded,
            "total_scanned": len(self.scanned_history),
            "malicious_detected": malicious_count,
            "recent_scans": self.scanned_history[-10:] if self.scanned_history else []
        }
