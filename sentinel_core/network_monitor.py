# sentinel_core/network_monitor.py
import psutil
import logging
from typing import List, Dict, Set, Optional
from sentinel_core.logger import SecurityEventLogger

class NetworkMonitor:
    """Monitor de conexões de rede ativas e detecção de portas/sockets suspeitos."""
    
    SUSPICIOUS_PORTS = {4444, 5555, 6667, 1337, 31337, 8888, 9999, 12345}

    def __init__(self, logger: Optional[SecurityEventLogger] = None):
        self.logger = logger
        self.known_connections: Set[str] = set()

    def scan_network_connections(self) -> List[Dict]:
        alerts = []
        try:
            connections = psutil.net_connections(kind='inet')
            current_conn_ids = set()

            for conn in connections:
                try:
                    if conn.status in (psutil.CONN_ESTABLISHED, psutil.CONN_LISTEN, psutil.CONN_SYN_SENT):
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                        pid = conn.pid or 0
                        
                        conn_id = f"{pid}-{laddr}-{raddr}"
                        current_conn_ids.add(conn_id)

                        remote_port = conn.raddr.port if conn.raddr else 0
                        local_port = conn.laddr.port if conn.laddr else 0

                        if remote_port in self.SUSPICIOUS_PORTS or local_port in self.SUSPICIOUS_PORTS:
                            if conn_id not in self.known_connections:
                                self.known_connections.add(conn_id)
                                proc_name = "Sistema/Desconhecido"
                                if pid:
                                    try:
                                        proc_name = psutil.Process(pid).name()
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                        pass

                                desc = f"Conexão em porta suspeita! Processo '{proc_name}' (PID: {pid}). Local: {laddr} -> Remoto: {raddr}"
                                if self.logger:
                                    self.logger.log_event("HIGH", "NETWORK", f"PID:{pid}", desc)
                                logging.warning(f"🚨 [ALERTA DE REDE] {desc}")
                                alerts.append({
                                    "pid": pid,
                                    "process": proc_name,
                                    "laddr": laddr,
                                    "raddr": raddr,
                                    "status": conn.status,
                                    "desc": desc
                                })
                except (AttributeError, IndexError):
                    continue

            self.known_connections = self.known_connections.intersection(current_conn_ids)

        except psutil.AccessDenied:
            logging.debug("[REDE] Acesso negado para listar algumas conexões (necessário privilégio de Administrador).")
        except Exception as e:
            logging.error(f"[ERRO REDE] Falha ao inspecionar conexões: {e}")
            
        return alerts

    scan = scan_network_connections

