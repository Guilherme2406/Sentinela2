# sentinel_core/honeytoken_deception.py
import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaXDR.DeceptionEngine")

class HoneytokenManager:
    """
    Gerenciador de Decepção e Armadilhas (Honeytokens / Canary Credentials).
    Planta credenciais falsas em navegadores, registros e arquivos de configuração.
    """

    HONEY_AWS_KEY = "AKIAZ57X99FAKE99HONEY"
    HONEY_GITHUB_TOKEN = "ghp_FakeHoneyTokenForInfostealerDetection9999"

    def __init__(self, bait_dir: str = "./sentinel_baits"):
        self.bait_dir = Path(bait_dir)
        self.bait_dir.mkdir(exist_ok=True)
        self.deployed_baits: Dict[str, str] = {}
        self._deploy_baits()

    def _deploy_baits(self):
        """Planta as credenciais de isca no sistema."""
        # 1. Isca AWS Credentials File
        aws_bait_path = self.bait_dir / "aws_credentials.txt"
        aws_content = f"[default]\naws_access_key_id = {self.HONEY_AWS_KEY}\naws_secret_access_key = FakeSecretKeySentinelXDRDoNotTouch\n"
        aws_bait_path.write_text(aws_content, encoding="utf-8")
        self.deployed_baits[str(aws_bait_path.resolve())] = self.HONEY_AWS_KEY

        # 2. Isca Browser Cookies / GitHub Token
        github_bait_path = self.bait_dir / "github_session.json"
        github_content = json.dumps({"token": self.HONEY_GITHUB_TOKEN, "user": "admin_honey_account"})
        github_bait_path.write_text(github_content, encoding="utf-8")
        self.deployed_baits[str(github_bait_path.resolve())] = self.HONEY_GITHUB_TOKEN

        logger.info(f"🍯 [Honeytokens] {len(self.deployed_baits)} iscas ativas plantadas em: {self.bait_dir}")

    def inspect_file_access(self, accessing_process_name: str, accessing_pid: int, accessed_file_path: str) -> Optional[Dict[str, Any]]:
        """
        Intercepta acessos aos arquivos de isca. Se um processo não autorizado ler o arquivo, aciona o alerta instantâneo.
        """
        resolved_path = str(Path(accessed_file_path).resolve())
        
        if resolved_path in self.deployed_baits:
            token_triggered = self.deployed_baits[resolved_path]
            logger.critical(f"🚨 [HONEYTOKEN TRIGGERED] Processo '{accessing_process_name}' (PID: {accessing_pid}) acessou a isca '{resolved_path}'!")
            
            return {
                "alert_type": "HONEYTOKEN_ACCESS_DETECTED",
                "mitre_id": "T1555.003",
                "mitre_tactic": "Credential Access (Infostealer)",
                "severity": "CRÍTICO",
                "description": f"Detecção de Infostealer! O processo '{accessing_process_name}' leu a credencial falsa ({token_triggered}).",
                "malicious_process": accessing_process_name,
                "pid": accessing_pid,
                "triggered_bait": resolved_path
            }
            
        return None
