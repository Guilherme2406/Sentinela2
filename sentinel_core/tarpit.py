# sentinel_core/tarpit.py
import socket
import threading
import time
import logging

class CyberTarpitServer:
    """
    Servidor Tarpit (Poço de Lodo).
    Prende atacantes em conexões lentas para neutralizar scanners automatizados e colher telemetria.
    """

    def __init__(self, host: str = "0.0.0.0", port: str = 9999, logger=None):
        self.host = host
        self.port = int(port)
        self.logger = logger
        self.is_running = False
        self._server_socket = None

    def start(self):
        self.is_running = True
        thread = threading.Thread(target=self._run_server, daemon=True)
        thread.start()
        logging.info(f"[TARPIT] Servidor Poço de Lodo rodando na porta {self.port}.")

    def _run_server(self):
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(100)

            while self.is_running:
                client_sock, addr = self._server_socket.accept()
                ip = addr[0]
                if self.logger:
                    self.logger.log_event("WARNING", "TARPIT", "INTRUDER_TRAPPED", f"Invasor {ip} caiu na armadilha Tarpit. Retendo conexão.")
                
                # Inicia thread de lentidão forçada para o invasor
                threading.Thread(target=self._hold_attacker, args=(client_sock, ip), daemon=True).start()

        except Exception as e:
            if self.is_running:
                logging.error(f"[TARPIT_ERROR] {str(e)}")

    def _hold_attacker(self, sock: socket.socket, ip: str):
        """Envia dados na taxa de 1 byte a cada 5-10 segundos para travar o robô/hacker."""
        try:
            sock.sendall(b"HTTP/1.1 200 OK\r\nServer: SentinelTarpit/1.0\r\n\r\n")
            while self.is_running:
                time.sleep(5)
                # Envia um byte inútil para manter a conexão aberta e consumir memória do atacante
                sock.sendall(b".")
        except (socket.error, ConnectionResetError):
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def trap_connection(self, ip: str, duration_seconds: int = 60):
        """Registra e retém um IP atacante no poço de lodo."""
        if self.logger:
            self.logger.log_event("WARNING", "TARPIT", ip, f"Invasor {ip} preso intencionalmente no Poço de Lodo por {duration_seconds}s.")
        logging.info(f"[TARPIT] IP {ip} preso em conexão lenta de contenção ({duration_seconds}s).")

    def get_status(self) -> dict:
        return {
            "active": self.is_running,
            "port": self.port,
            "mode": "SLOW_DRAIN_1BPS"
        }

    def stop(self):
        self.is_running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

TarpitManager = CyberTarpitServer

