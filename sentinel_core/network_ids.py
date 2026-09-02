# sentinel_core/network_ids.py
import time
import threading
import logging
import psutil
from typing import Dict, Set, List
from sentinel_core.logger import SecurityEventLogger

class NetworkIDS:
    """
    Sistema de Detecção de Intrusão em Rede (NIDS) em tempo real.
    Monitora conexões ativas, identifica Port Scans e conexões de saída suspeitas.
    """

    def __init__(self, logger: SecurityEventLogger = None, scan_threshold: int = 10, check_interval: int = 5, alert_callback = None):
        self.logger = logger
        self.scan_threshold = scan_threshold  # Máximo de conexões únicas por IP em curto intervalo
        self.check_interval = check_interval
        self.alert_callback = alert_callback
        self.is_running = False
        self._thread = None
        
        # Histórico temporário para rastrear port scans: { remote_ip: set(portas_acessadas) }
        self.ip_port_history: Dict[str, Set[int]] = {}
        # Portas de alto risco geralmente associadas a Trojans/Backdoors
        self.suspicious_ports: Set[int] = {4444, 5555, 6667, 1337, 31337, 9999, 8888}

    @property
    def running(self) -> bool:
        return self.is_running


    def start(self):
        """Inicia o monitoramento de rede em background thread."""
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._monitor_network, daemon=True)
            self._thread.start()
            logging.info("[NIDS] Radar de Detecção de Intrusão de Rede INICIADO.")

    def stop(self):
        """Para o monitoramento de rede."""
        self.is_running = False
        logging.info("[NIDS] Radar de Detecção de Intrusão de Rede PARADO.")

    def _monitor_network(self):
        """Loop principal de monitoramento de conexões."""
        while self.is_running:
            try:
                self._analyze_connections()
            except Exception as e:
                logging.error(f"[NIDS] Erro durante análise de rede: {e}")
            
            # Sleep responsivo para encerrar imediatamente no stop()
            for _ in range(max(1, int(self.check_interval * 5))):
                if not self.is_running:
                    break
                time.sleep(0.2)


    def _analyze_connections(self):
        """Coleta e analisa as conexões ativas do sistema."""
        current_history: Dict[str, Set[int]] = {}

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, Exception) as e:
            logging.warning(f"[NIDS] Permissão insuficiente para inspecionar todas as conexões: {e}")
            return

        for conn in connections:
            # Filtra apenas conexões estabelecidas ou em SYN_SENT com remote IP válido
            if conn.raddr and conn.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0

                # Ignora localhost / loopback
                if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue

                # 1. Alerta de Conexão em Porta Suspeita (Command & Control / Backdoor)
                if remote_port in self.suspicious_ports or local_port in self.suspicious_ports:
                    msg = f"Conexão ativa em porta de ALTO RISCO detectada! LocalPort: {local_port} -> Remote: {remote_ip}:{remote_port} (PID: {conn.pid})"
                    if self.logger:
                        self.logger.log_event("HIGH", "NIDS_SUSPICIOUS_PORT", f"{remote_ip}:{remote_port}", msg)
                    logging.warning(f"[NIDS] {msg}")
                    if self.alert_callback:
                        try:
                            self.alert_callback(remote_ip, "NIDS_SUSPICIOUS_PORT", "HIGH")
                        except Exception as e:
                            logging.debug(f"[NIDS] Erro ao invocar alert_callback: {e}")

                # 2. Agrupa por IP remoto para rastreio de Port Scan
                if remote_ip not in current_history:
                    current_history[remote_ip] = set()
                current_history[remote_ip].add(local_port)

        # 3. Análise de Port Scanning
        for r_ip, ports in current_history.items():
            if len(ports) >= self.scan_threshold:
                msg = f"POSSÍVEL PORT SCAN DETECTADO! IP remoto {r_ip} tentou contato com {len(ports)} portas locais distintas."
                if self.logger:
                    self.logger.log_event("CRITICAL", "NIDS_PORT_SCAN", r_ip, msg)
                logging.critical(f"[NIDS] {msg}")
                if self.alert_callback:
                    try:
                        self.alert_callback(r_ip, "NIDS_PORT_SCAN", "CRITICAL")
                    except Exception as e:
                        logging.debug(f"[NIDS] Erro ao invocar alert_callback: {e}")

        self.ip_port_history = current_history

NIDSRadar = NetworkIDS

