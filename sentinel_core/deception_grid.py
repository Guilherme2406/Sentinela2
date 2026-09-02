# sentinel_core/deception_grid.py
import os
import sys
import time
import socket
import threading
import logging
from typing import List, Dict, Any, Callable, Optional

class CanaryFileTracker:
    """
    Cria e monitora arquivos canário ('iscas') no sistema de arquivos.
    Qualquer tentativa de leitura, modificação ou remoção por processos não autorizados
    é detectada como indício direto de escaneamento ou atividade de ransomware.
    """

    def __init__(self, watch_dirs: Optional[List[str]] = None, logger=None):
        self.logger = logger
        self.watch_dirs = watch_dirs or [os.path.expanduser("~")]
        self.canary_files: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def deploy_canaries(self) -> List[str]:
        """Gera arquivos de isca estratégicos nos diretórios configurados."""
        deployed = []
        canary_names = [
            "__passwords_backup.docx",
            "__wallet_seed_phrase.txt",
            "__database_config.sql"
        ]

        for base_dir in self.watch_dirs:
            if not os.path.exists(base_dir):
                continue

            for cname in canary_names:
                fpath = os.path.join(base_dir, cname)
                try:
                    if not os.path.exists(fpath):
                        with open(fpath, "w", encoding="utf-8") as f:
                            f.write(f"# SENTINELA CANARY FILE - DO NOT MODIFY\nCreated at {time.ctime()}\nID: CANARY_{os.urandom(4).hex()}\n")
                    
                    st = os.stat(fpath)
                    self.canary_files[fpath] = {
                        "mtime": st.st_mtime,
                        "size": st.st_size,
                        "created_at": time.time()
                    }
                    deployed.append(fpath)
                except Exception as e:
                    self._log("ERROR", "DECEPTION", "CANARY_CREATE_FAIL", f"Falha ao criar canário em {fpath}: {e}")

        self._log("INFO", "DECEPTION", "CANARY_DEPLOYED", f"{len(deployed)} arquivos canário ativos em monitoramento.")
        return deployed

    def check_canaries(self) -> List[Dict[str, Any]]:
        """Verifica a integridade dos arquivos canário."""
        tampered = []
        for fpath, meta in list(self.canary_files.items()):
            if not os.path.exists(fpath):
                event = {"file": fpath, "type": "DELETED", "timestamp": time.time()}
                tampered.append(event)
                self._log("CRITICAL", "DECEPTION", "CANARY_DELETED", f"Arquivo canário removido: {fpath}")
                continue

            try:
                st = os.stat(fpath)
                if st.st_mtime != meta["mtime"] or st.st_size != meta["size"]:
                    event = {"file": fpath, "type": "MODIFIED", "timestamp": time.time()}
                    tampered.append(event)
                    self._log("CRITICAL", "DECEPTION", "CANARY_MODIFIED", f"Arquivo canário adulterado: {fpath}")
                    # Atualiza metadados para não alertar repetidamente em loop
                    self.canary_files[fpath]["mtime"] = st.st_mtime
                    self.canary_files[fpath]["size"] = st.st_size
            except Exception as e:
                self._log("ERROR", "DECEPTION", "CANARY_STAT_ERR", f"Erro ao checar {fpath}: {e}")

        return tampered

class PassivHoneypotPort:
    """
    Abre sockets de escuta passiva em portas isca (ex: 21, 2222, 3389).
    Registra conexões de escaneamento de rede sem responder ou interagir de forma nociva.
    """

    def __init__(self, ports: Optional[List[int]] = None, logger=None):
        self.logger = logger
        self.ports = ports or [2121, 33890]  # Portas não privilegiadas padrão para demonstração
        self.sockets: List[socket.socket] = []
        self._running = False
        self._threads: List[threading.Thread] = []
        self.detected_scans: List[Dict[str, Any]] = []

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def _listen_port(self, port: int):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", port))
            server.listen(5)
            server.settimeout(2.0)
            self.sockets.append(server)
            self._log("INFO", "DECEPTION", "HONEYPOT_START", f"Porta isca escutando na porta {port}")

            while self._running:
                try:
                    conn, addr = server.accept()
                    scan_event = {
                        "remote_ip": addr[0],
                        "remote_port": addr[1],
                        "target_port": port,
                        "timestamp": time.time()
                    }
                    self.detected_scans.append(scan_event)
                    self._log("WARNING", "DECEPTION", "PORT_SCAN_DETECTED", 
                              f"Conexão isca detectada! IP: {addr[0]}:{addr[1]} acessou porta honeypot {port}")
                    conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            self._log("ERROR", "DECEPTION", "HONEYPOT_BIND_ERR", f"Não foi possível abrir porta isca {port}: {e}")
        finally:
            server.close()

    def start(self):
        """Inicia os leitores de portas honeypot em threads separadas."""
        self._running = True
        for p in self.ports:
            t = threading.Thread(target=self._listen_port, args=(p,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        """Encerra a escuta das portas isca."""
        self._running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass
        self._log("INFO", "DECEPTION", "HONEYPOT_STOP", "Portas isca encerradas com sucesso.")
