# sentinel_core/tarpit_engine.py
import time
import socket
import threading
import logging
from typing import Dict, Any, List

class TarpitEngine:
    """
    Motor Avançado de Countermeasures & Tarpitting (Poço de Lodo Ciber) — Modo Hardened.
    Retém conexões maliciosas intencionalmente a uma taxa ultra lenta (1 byte a cada 4 segundos)
    para esgotar recursos de scanners automatizados de atacantes (Nmap, Shodan, Masscan).
    """

    def __init__(self, port=8888, logger=None):
        self.port = port
        self.logger = logger
        self.is_running = False
        self._server_socket = None
        self.trapped_ips: Dict[str, Dict[str, Any]] = {}

    def start(self):
        """Inicia a escuta do servidor Tarpit."""
        self.is_running = True
        thread = threading.Thread(target=self._listen_loop, daemon=True)
        thread.start()
        logging.info(f"[+] Motor Tarpit (Poço de Lodo Ciber) ativo na porta {self.port}.")

    def _listen_loop(self):
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("0.0.0.0", self.port))
            self._server_socket.listen(10)

            while self.is_running:
                client_sock, addr = self._server_socket.accept()
                ip = addr[0]
                self.trap_connection(ip, duration_seconds=120)
                
                # Trata o hacker em thread dedicada para prender a conexão dele
                t = threading.Thread(target=self._drain_hacker, args=(client_sock, ip), daemon=True)
                t.start()
        except Exception as e:
            if self.is_running:
                logging.error(f"[TARPIT ERROR] {e}")

    def trap_connection(self, ip: str, duration_seconds: int = 60):
        """Registra a retenção forçada do IP invasor."""
        self.trapped_ips[ip] = {
            "ip": ip,
            "trapped_at": time.time(),
            "duration": duration_seconds,
            "status": "TRAPPED_IN_TARPIT"
        }
        if self.logger:
            self.logger.log_event("WARNING", "TARPIT", "TRAPPED", f"Invasor {ip} caiu no Poço de Lodo (Tarpit - Retido por {duration_seconds}s)!")

    def _drain_hacker(self, client_sock: socket.socket, ip: str):
        """Segura o hacker enviando respostas infinitamente lentas para degradar sockets."""
        try:
            client_sock.sendall(b"HTTP/1.1 200 OK\r\nServer: Sentinel-Tarpit-Defense-Sovereign\r\nContent-Type: text/plain\r\n\r\n")
            # Envia 1 byte a cada 4 segundos
            for _ in range(60):
                if not self.is_running:
                    break
                client_sock.sendall(b"~")
                time.sleep(4)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self):
        self.is_running = False
        if self._server_socket:
            self._server_socket.close()
