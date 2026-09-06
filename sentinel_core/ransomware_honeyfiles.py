"""
Sentinela XDR - Motor Decoy Ransomware Honeyfiles & Tripwire
Plantação de arquivos iscas de alta atratividade para detecção instantânea (<1ms)
de comportamento de criptografia em massa ou wipers antes que dados reais sejam atingidos.
"""

import os
import time
import hashlib
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaHoneyfiles")


class RansomwareHoneyfiles:
    """Motor de iscas ativas contra Ransomware com armadilhas tripwire."""

    DEFAULT_BAITS = [
        {"filename": "!00_senhas_bancarias.xlsx", "content": "SENHAS CORPORATIVAS CONFIDENCIAIS: root, admin, financeiro\n" * 50},
        {"filename": "_00_backup_contabilidade_2026.docx", "content": "PLANILHA DE BALANCO PATRIMONIAL E CONTABILIDADE ANUAL\n" * 50},
        {"filename": "!passwords_vault.kdbx", "content": "KEEPASS 2.0 VAULT CIPHERED BLOB DATA FORMAT 2026\n" * 50}
    ]

    def __init__(self, base_dir: str = "sentinel_honeyfiles", logger_instance=None, auto_deploy: bool = True):
        self.base_dir = os.path.abspath(base_dir)
        self.logger = logger_instance
        self.monitored_baits: Dict[str, Dict[str, Any]] = {}
        self.tamper_events: List[Dict[str, Any]] = []
        self.total_checks: int = 0
        self.total_trips: int = 0

        if auto_deploy:
            self.deploy_honeyfiles()
        self._log("INFO", "HONEYFILES_INIT", "INIT", f"Motor Ransomware Honeyfiles ativo com {len(self.monitored_baits)} iscas monitoradas.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def deploy_honeyfiles(self) -> int:
        """Planta os arquivos iscas no diretório de armadilha e calcula hashes de integridade."""
        os.makedirs(self.base_dir, exist_ok=True)
        deployed_count = 0

        for bait in self.DEFAULT_BAITS:
            path = os.path.join(self.base_dir, bait["filename"])
            try:
                if not os.path.exists(path):
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(bait["content"])

                # Calcular hash SHA-256
                with open(path, "rb") as f:
                    file_bytes = f.read()
                    h = hashlib.sha256(file_bytes).hexdigest()

                self.monitored_baits[path] = {
                    "filename": bait["filename"],
                    "path": path,
                    "expected_hash": h,
                    "expected_size": len(file_bytes),
                    "created_at": time.time()
                }
                deployed_count += 1
            except Exception as e:
                self._log("WARNING", "HONEYFILE_DEPLOY", "ERROR", f"Falha ao plantar {bait['filename']}: {e}")

        return deployed_count

    def check_integrity(self) -> Dict[str, Any]:
        """Varre os arquivos iscas em busca de modificações, criptografia ou exclusão."""
        self.total_checks += 1
        compromised = []

        for path, meta in self.monitored_baits.items():
            fname = meta["filename"]
            # 1. Checar se o arquivo foi excluído
            if not os.path.exists(path):
                compromised.append({
                    "path": path,
                    "filename": fname,
                    "tamper_type": "DELETED",
                    "reason": "Arquivo isca foi excluído por processo desconhecido."
                })
                continue

            # 2. Checar integridade de hash e tamanho
            try:
                with open(path, "rb") as f:
                    curr_bytes = f.read()
                    curr_hash = hashlib.sha256(curr_bytes).hexdigest()

                if curr_hash != meta["expected_hash"]:
                    compromised.append({
                        "path": path,
                        "filename": fname,
                        "tamper_type": "ENCRYPTED_OR_MODIFIED",
                        "reason": f"Hash do arquivo isca foi alterado! (Original: {meta['expected_hash'][:12]}... Atual: {curr_hash[:12]}...)"
                    })
            except Exception as e:
                compromised.append({
                    "path": path,
                    "filename": fname,
                    "tamper_type": "INACCESSIBLE",
                    "reason": f"Arquivo isca bloqueado ou inacessível: {e}"
                })

        has_threat = len(compromised) > 0
        if has_threat:
            self.total_trips += 1
            event = {
                "timestamp": time.time(),
                "severity": "CRITICAL",
                "compromised_baits": compromised,
                "action": "RANSOMWARE_TRIPWIRE_TRIGGERED"
            }
            self.tamper_events.insert(0, event)
            if len(self.tamper_events) > 50:
                self.tamper_events.pop()

            self._log(
                "CRITICAL",
                "HONEYFILE_TRIPWIRE",
                "RANSOMWARE_ACTIVITY_DETECTED",
                f"ALERTA TRIPWIRE! Arquivo isca de ransomware foi adulterado ({compromised[0]['filename']})! Ação: Contenção de Processo Imediata."
            )

        return {
            "status": "threat_detected" if has_threat else "secure",
            "has_threat": has_threat,
            "total_monitored": len(self.monitored_baits),
            "compromised_count": len(compromised),
            "compromised_files": compromised
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status do motor de Honeyfiles."""
        return {
            "status": "active",
            "honeyfiles_dir": self.base_dir,
            "total_baits": len(self.monitored_baits),
            "total_checks": self.total_checks,
            "total_trips": self.total_trips,
            "recent_tamper_events": self.tamper_events[:10]
        }
