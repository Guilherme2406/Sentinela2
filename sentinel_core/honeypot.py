# sentinel_core/honeypot.py
import socket
import threading
import time
import os
import logging
from typing import List, Dict, Set, Optional
from sentinel_core.logger import SecurityEventLogger

class Honeypot:
    """
    Módulo de Decepção Ativa que cria portas armadilha (honeypots)
    e arquivos canary (iscas) para detectar e responder a atacantes.
    """

    DEFAULT_TRAP_PORTS: List[int] = [2222, 8080, 8888, 9999, 21, 23, 80, 3389]

    def __init__(
        self, 
        logger: Optional[SecurityEventLogger] = None, 
        honeypot_dir: str = "honeypots",
        forbidden_ips_file: str = "forbidden_ips.txt",
        trap_ports: Optional[List[int]] = None,
        port: Optional[int] = None,
        alert_callback = None
    ):
        self.logger = logger
        self.honeypot_dir = os.path.abspath(honeypot_dir) if not os.path.isabs(honeypot_dir) else honeypot_dir
        self.forbidden_ips_file = os.path.join(self.honeypot_dir, forbidden_ips_file)
        if port:
            self.trap_ports = [port]
        else:
            self.trap_ports = trap_ports or list(self.DEFAULT_TRAP_PORTS)
        self.alert_callback = alert_callback

        
        self.canary_files: Dict[str, str] = {
            os.path.join(self.honeypot_dir, "salarios_confidenciais.docx"): "Este arquivo é uma isca de auditoria de segurança.",
            os.path.join(self.honeypot_dir, "backup_passwords.txt.zip"): "Conteúdo canary de senhas para atrair acessos não autorizados."
        }
        
        self.is_running = False
        self.sockets: List[socket.socket] = []
        self.active_listeners: List[threading.Thread] = []
        self.canary_thread: Optional[threading.Thread] = None
        self.forbidden_ips: Set[str] = set()

        self._ensure_dir()
        self.forbidden_ips = self._load_forbidden_ips()
        self._setup_canary_files()

    def _ensure_dir(self):
        if not os.path.exists(self.honeypot_dir):
            os.makedirs(self.honeypot_dir, exist_ok=True)

    def _load_forbidden_ips(self) -> Set[str]:
        """Carrega IPs banidos de um arquivo."""
        if not os.path.exists(self.forbidden_ips_file):
            return set()
        try:
            with open(self.forbidden_ips_file, "r", encoding="utf-8") as f:
                ips = {line.strip() for line in f if line.strip()}
            return ips
        except Exception:
            return set()

    def _add_forbidden_ip(self, ip: str):
        """Adiciona um IP à lista de banidos e salva no arquivo."""
        if ip not in self.forbidden_ips:
            self.forbidden_ips.add(ip)
            try:
                with open(self.forbidden_ips_file, "a", encoding="utf-8") as f:
                    f.write(f"{ip}\n")
            except Exception as e:
                logging.debug(f"[HONEYPOT] Falha ao salvar IP banido: {e}")

            if self.logger:
                self.logger.log_event("CRITICAL", "IP_BANNED", ip, f"IP {ip} adicionado à lista de banidos por interagir com honeypot.")
            logging.warning(f"🚫 [HONEYPOT BAN] IP {ip} adicionado à lista de banidos.")

    def _setup_canary_files(self):
        """Cria os arquivos isca (canary files) no sistema."""
        self._ensure_dir()
        for path, content in self.canary_files.items():
            dir_name = os.path.dirname(path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
            if not os.path.exists(path):
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(content)
                except Exception as e:
                    logging.debug(f"[HONEYPOT] Falha ao criar canary {path}: {e}")

    def _handle_trap_connection(self, conn: socket.socket, addr: tuple):
        """Lida com conexões em portas armadilha."""
        ip_address = addr[0]
        port = addr[1]
        msg = f"Conexão detectada na porta armadilha {port} originada de {ip_address}"
        if self.logger:
            self.logger.log_event("CRITICAL", "HONEYPOT_HIT", f"{ip_address}:{port}", msg)
        logging.warning(f"🍯 [HONEYPOT TRAP] {msg}")

        if self.alert_callback:
            try:
                self.alert_callback(ip_address, f"HONEYPOT_TRAP_PORT_{port}", "CRITICAL")
            except Exception as e:
                logging.debug(f"[HONEYPOT] Erro ao invocar alert_callback: {e}")
        
        try:
            conn.sendall(b"220 Service Ready - Authentication Required.\r\n") 
            time.sleep(0.5)
            conn.sendall(b"530 Please login with valid credentials.\r\n")
            data = conn.recv(512)
            if data:
                logging.warning(f"[HONEYPOT] Payload recebido do atacante {ip_address}: {data.decode(errors='ignore')}")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self._add_forbidden_ip(ip_address)

    def _listen_on_trap_port(self, port: int):
        """Cria um servidor de escuta em uma porta armadilha específica."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(5)
            s.settimeout(1.0)
            self.sockets.append(s)
            logging.info(f"[HONEYPOT] Armadilha ativa na porta {port}")
            while self.is_running:
                try:
                    conn, addr = s.accept()
                    if addr[0] in self.forbidden_ips:
                        conn.close()
                        continue
                    handler = threading.Thread(target=self._handle_trap_connection, args=(conn, addr), daemon=True)
                    handler.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except (PermissionError, OSError) as e:
            logging.debug(f"[HONEYPOT] Porta {port} indisponível para honeypot ({e})")
        finally:
            try:
                s.close()
            except Exception:
                pass

    def start(self):
        """Inicia todos os honeypots e monitor de arquivos isca."""
        if self.is_running:
            return
        self.is_running = True
        logging.info("[HONEYPOT] Inicializando portas armadilha e canários...")
        
        for port in self.trap_ports:
            thread = threading.Thread(target=self._listen_on_trap_port, args=(port,), daemon=True)
            thread.start()
            self.active_listeners.append(thread)

        self.canary_thread = threading.Thread(target=self._monitor_canary_files_loop, daemon=True)
        self.canary_thread.start()
        logging.info("[HONEYPOT] Decepção ativa em execução.")

    start_honeypots = start

    def stop(self):
        """Para todos os honeypots e fecha sockets de escuta."""
        self.is_running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass
        self.sockets.clear()
        logging.info("[HONEYPOT] Decepção Ativa & Honeypots finalizados.")

    def _monitor_canary_files_loop(self, interval: int = 5):
        """Loop de monitoramento dos arquivos isca."""
        initial_mtimes = {path: os.path.getmtime(path) for path in self.canary_files if os.path.exists(path)}
        
        while self.is_running:
            for path in list(self.canary_files.keys()):
                if os.path.exists(path):
                    current_mtime = os.path.getmtime(path)
                    if path not in initial_mtimes or current_mtime > initial_mtimes[path]:
                        desc = f"ARQUIVO ISCA (CANARY) ATINGIDO! Arquivo '{path}' foi modificado/acessado."
                        if self.logger:
                            self.logger.log_event("CRITICAL", "CANARY_HIT", path, desc)
                        logging.critical(f"🚨 [CANARY ALERT] {desc}")
                        initial_mtimes[path] = current_mtime
                else:
                    self._setup_canary_files()
                    if os.path.exists(path):
                        initial_mtimes[path] = os.path.getmtime(path)
            
            # Sleep responsivo para encerrar imediatamente no stop()
            for _ in range(max(1, int(interval * 5))):
                if not self.is_running:
                    break
                time.sleep(0.2)

    @property
    def running(self) -> bool:
        return self.is_running

SentinelHoneypot = Honeypot




