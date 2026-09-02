# sentinel_core/fim.py
import os
import hashlib
import logging
from typing import Dict, List, Optional, Set
from sentinel_core.logger import SecurityEventLogger
from sentinel_core.threat_detector import ThreatDetector
from sentinel_core.auto_response import AutoResponseEngine

IGNORED_EXTENSIONS = {'.db', '.db-journal', '.db-wal', '.db-shm', '.pyc', '.key', '.enc', '.quarantine', '.tmp', '.log'}
IGNORED_DIRS = {'__pycache__', '.git', '.vscode', '.idea', 'quarantine', '.agents', '.gemini', 'node_modules', 'venv', '.venv'}

class FileIntegrityMonitor:
    """Monitor de Integridade de Arquivos (FIM) com integração ao Detector de Ameaças."""
    
    def __init__(
        self, 
        watch_paths: Optional[List[str]] = None, 
        logger: Optional[SecurityEventLogger] = None,
        threat_detector: Optional[ThreatDetector] = None,
        auto_response: Optional[AutoResponseEngine] = None,
        auto_isolate: bool = False
    ):
        self.watch_paths = [os.path.abspath(p) for p in (watch_paths or [os.getcwd()])]
        self.logger = logger
        self.threat_detector = threat_detector
        self.auto_response = auto_response
        self.auto_isolate = auto_isolate
        self.file_hashes: Dict[str, str] = {}
        self._build_baseline()

    def _should_ignore(self, filepath: str) -> bool:
        normalized = filepath.replace('\\', '/')
        parts = set(normalized.split('/'))
        if IGNORED_DIRS.intersection(parts):
            return True
        _, ext = os.path.splitext(filepath)
        if ext.lower() in IGNORED_EXTENSIONS:
            return True
        return False

    def _hash_file(self, filepath: str) -> str:
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return ""

    def _build_baseline(self):
        logging.info("[FIM] Mapeando baseline de integridade...")
        count = 0
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                if not self._should_ignore(path):
                    h = self._hash_file(path)
                    if h:
                        self.file_hashes[path] = h
                        count += 1
            else:
                for root, dirs, files in os.walk(path):
                    dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                    for file in files:
                        filepath = os.path.join(root, file)
                        if not self._should_ignore(filepath):
                            h = self._hash_file(filepath)
                            if h:
                                self.file_hashes[filepath] = h
                                count += 1
        logging.info(f"[FIM] Baseline concluído com {count} arquivos protegidos.")

    def scan(self):
        """Executa varredura de integridade e verificação de ameaças nos arquivos."""
        found_files = set()
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                if not self._should_ignore(path):
                    found_files.add(path)
                    self._check_file(path)
            else:
                for root, dirs, files in os.walk(path):
                    dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                    for file in files:
                        filepath = os.path.join(root, file)
                        if not self._should_ignore(filepath):
                            found_files.add(filepath)
                            self._check_file(filepath)

        for tracked_path in list(self.file_hashes.keys()):
            if tracked_path not in found_files and not os.path.exists(tracked_path):
                if self.logger:
                    self.logger.log_event("WARNING", "FIM", tracked_path, "Arquivo removido do diretório protegido.")
                del self.file_hashes[tracked_path]

    run_scan = scan

    def _check_file(self, filepath: str):
        current_hash = self._hash_file(filepath)
        if not current_hash:
            return

        is_new = filepath not in self.file_hashes
        is_modified = not is_new and self.file_hashes[filepath] != current_hash

        if is_new:
            if self.logger:
                self.logger.log_event("WARNING", "FIM", filepath, "Novo arquivo detectado no diretório protegido.")
            self.file_hashes[filepath] = current_hash
        elif is_modified:
            if self.logger:
                self.logger.log_event("HIGH", "FIM", filepath, "ALERTA: Integridade violada! Hash SHA-256 alterado.")
            self.file_hashes[filepath] = current_hash

        # Se for novo ou modificado, avalia ameaça
        if (is_new or is_modified) and self.threat_detector:
            result = self.threat_detector.scan_file(filepath)
            if result.get("status") == "MALWARE_DETECTED":
                if self.auto_isolate and self.auto_response:
                    logging.warning(f"[FIM+SOAR] Isolando arquivo malicioso automaticamente: {filepath}")
                    self.auto_response.isolate_file(filepath)
                    self.file_hashes.pop(filepath, None)

