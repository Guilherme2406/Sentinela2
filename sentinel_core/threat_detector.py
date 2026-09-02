# sentinel_core/threat_detector.py
import hashlib
import os
import logging
from typing import List, Dict, Set, Optional
from sentinel_core.logger import SecurityEventLogger

class ThreatDetector:
    """Motor de detecção de ameaças baseado em assinaturas de HASH (SHA-256) e heurística com Whitelist inteligente."""

    # Hashes reais de malwares conhecidos para teste e detecção
    DEFAULT_MALWARE_HASHES: Set[str] = {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR Standard Antivirus Test File
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",  # WannaCry Ransomware SHA-256
        "8d4f40f0c0b50c91473d09adfb4f52bf548f7d56114e52b60070e8b4e21e2d49",  # Emotet Trojan SHA-256
    }

    # Arquivos e pastas do próprio projeto que NUNCA devem ser considerados maliciosos
    SAFE_PROJECT_FILENAMES: Set[str] = {
        "main.py", "sentinel_api.py", "sentinel_cli.py", "dashboard.html",
        "iniciar.bat", "iniciar_cli.bat", "setup_project.py", "sentinel_events.db",
        "sentinel.key", "__init__.py", "test_sentinela.py"
    }

    SAFE_PROJECT_DIRS: Set[str] = {
        "sentinel_core", "honeypots", "quarantine", ".git", ".vscode",
        ".idea", "__pycache__", ".agents", ".gemini", "node_modules", "venv", ".venv"
    }

    def __init__(self, logger: Optional[SecurityEventLogger] = None):
        self.logger = logger
        self.known_malware_hashes: Set[str] = set(self.DEFAULT_MALWARE_HASHES)
        self.custom_whitelist: Set[str] = set()

    def is_whitelisted(self, file_path: str) -> bool:
        """Verifica se o arquivo pertence à lista segura/confiável do projeto."""
        if not file_path:
            return False
        
        abs_path = os.path.abspath(file_path)
        filename = os.path.basename(abs_path).lower()

        # 1. Checagem de nome de arquivo seguro
        if filename in self.SAFE_PROJECT_FILENAMES:
            return True

        # 2. Checagem de pastas seguras do projeto
        normalized_path = abs_path.replace('\\', '/').lower()
        parts = set(normalized_path.split('/'))
        if self.SAFE_PROJECT_DIRS.intersection(parts):
            return True

        # 3. Checagem na whitelist personalizada
        if abs_path.lower() in self.custom_whitelist or filename in self.custom_whitelist:
            return True

        return False

    def add_whitelist(self, path_or_name: str):
        """Adiciona um caminho ou nome de arquivo à lista de exceções (Whitelist)."""
        if path_or_name:
            self.custom_whitelist.add(os.path.abspath(path_or_name).lower())
            self.custom_whitelist.add(os.path.basename(path_or_name).lower())

    def remove_whitelist(self, path_or_name: str):
        """Remove da lista de exceções."""
        self.custom_whitelist.discard(os.path.abspath(path_or_name).lower())
        self.custom_whitelist.discard(os.path.basename(path_or_name).lower())

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calcula o hash SHA-256 de qualquer arquivo de forma segura em chunks."""
        if not os.path.isfile(file_path):
            return ""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest().lower()
        except (PermissionError, FileNotFoundError, OSError) as e:
            logging.debug(f"[DETECTOR] Não foi possível ler {file_path} para cálculo de hash: {e}")
            return ""

    def add_ioc_hash(self, file_hash: str):
        """Adiciona um novo hash de malware conhecido à base de inteligência de ameaças."""
        if file_hash:
            self.known_malware_hashes.add(file_hash.lower().strip())

    def remove_ioc_hash(self, file_hash: str):
        """Remove um hash da base de IOCs."""
        self.known_malware_hashes.discard(file_hash.lower().strip())

    def scan_file(self, file_path: str) -> Dict:
        """Escaneia um arquivo específico verificando seu Hash SHA-256 e padrões heurísticos."""
        if not os.path.exists(file_path):
            return {"status": "ERROR", "reason": "Arquivo não existe", "file": file_path}

        if os.path.isdir(file_path):
            return {"status": "SKIPPED", "reason": "É um diretório", "file": file_path}

        # Arquivos protegidos da whitelist nunca são classificados como malware
        if self.is_whitelisted(file_path):
            return {"status": "CLEAN", "reason": "Arquivo confiável (Whitelist do Projeto)", "file": file_path}

        try:
            # Arquivos de tamanho zero não são maliciosos
            if os.path.getsize(file_path) == 0:
                return {"status": "CLEAN", "reason": "Arquivo vazio (0 bytes)", "file": file_path}
        except OSError:
            pass

        file_hash = self.calculate_sha256(file_path)
        filename = os.path.basename(file_path).lower()

        # 1. Verificação de assinatura exata (IOC HASH)
        if file_hash and file_hash in self.known_malware_hashes:
            desc = f"AMEAÇA CONFIRMADA! Arquivo '{file_path}' coincide com IOC SHA256: {file_hash}"
            if self.logger:
                self.logger.log_event(
                    severity="CRITICAL",
                    category="MALWARE",
                    target=file_path,
                    description=desc
                )
            logging.critical(f"[THREAT DETECTED] {desc}")
            return {
                "status": "MALWARE_DETECTED",
                "threat_type": "KNOWN_IOC_HASH",
                "hash": file_hash,
                "file": file_path,
                "description": desc
            }

        # 2. Heurística de extensão dupla perigosa (ex: documento.pdf.exe)
        parts = filename.split('.')
        if len(parts) > 2:
            second_last = f".{parts[-2]}"
            last = f".{parts[-1]}"
            if last in {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1'} and second_last in {'.pdf', '.docx', '.xlsx', '.txt', '.jpg', '.png'}:
                desc = f"HEURÍSTICA SUSPEITA! Arquivo com dupla extensão camuflada: '{file_path}'"
                if self.logger:
                    self.logger.log_event(
                        severity="HIGH",
                        category="MALWARE_HEURISTIC",
                        target=file_path,
                        description=desc
                    )
                logging.warning(f"[HEURISTIC ALERT] {desc}")
                return {
                    "status": "SUSPICIOUS",
                    "threat_type": "DOUBLE_EXTENSION",
                    "hash": file_hash,
                    "file": file_path,
                    "description": desc
                }

        return {"status": "CLEAN", "hash": file_hash, "file": file_path}

    analyze_file = scan_file
    inspect_file = scan_file


