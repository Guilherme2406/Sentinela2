# sentinel_core/firewall_manager.py
import subprocess
import sys
import time
import logging
from datetime import datetime
from typing import Set, Dict, Any, List

class OSFirewallManager:
    """
    Gerenciador de Firewall Dinâmico em Nível de SO (Kernel) e Nível de Aplicação (XDR Shield).
    Bane IPs maliciosos instantaneamente no Windows (netsh) ou Linux (iptables),
    garantindo bloqueio ativo mesmo em processos sem elevação de privilégios.
    """

    def __init__(self, logger=None):
        self.logger = logger
        self.banned_ips: Set[str] = set()
        self.banned_records: Dict[str, Dict[str, Any]] = {}
        self.is_windows = sys.platform == "win32"

        # Pre-seed de ameaças CTI de alta criticidade
        self.block_ip("185.220.101.5", reason="Tor Exit Node / Port Scan Brute Force")
        self.block_ip("45.146.164.110", reason="Ransomware C2 Botnet / Malicious Traffic")

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger:
            self.logger.log_event(level, category, action, msg)
        logging.info(f"[{category}] {msg}")

    def is_banned(self, ip: str) -> bool:
        """Verifica se o IP está banido na camada ativa."""
        return ip in self.banned_ips

    def block_ip(self, ip: str, reason: str = "Ataque detectado pelo Sentinela XDR") -> bool:
        """Adiciona regra de bloqueio de IP no Firewall do SO e no XDR Shield."""
        if not ip or ip in ("127.0.0.1", "localhost", "0.0.0.0") or ip.startswith("192.168."):
            return False

        if ip in self.banned_ips:
            return True

        rule_name = f"SENTINELA_BLOCK_{ip.replace('.', '_')}"
        kernel_enforced = False

        try:
            if self.is_windows:
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} description="{reason}"'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    kernel_enforced = True
            else:
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    kernel_enforced = True

            # Registra o IP na camada do Sentinela
            self.banned_ips.add(ip)
            now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            self.banned_records[ip] = {
                "ip": ip,
                "reason": reason,
                "timestamp": now_str,
                "kernel_enforced": kernel_enforced,
                "status": "BLOCKED"
            }

            if kernel_enforced:
                self._log("CRITICAL", "FIREWALL_KERNEL", "IP_BAN", f"IP {ip} foi banido no Firewall do Kernel do SO (netsh/iptables). Motivo: {reason}")
            else:
                self._log("HIGH", "FIREWALL_APP", "IP_BAN", f"IP {ip} foi banido na Camada Ativa XDR Shield (Execute como Admin para regra direta de Kernel). Motivo: {reason}")

            return True

        except Exception as e:
            self.banned_ips.add(ip)
            self._log("HIGH", "FIREWALL_APP", "IP_BAN", f"IP {ip} protegido na camada do Sentinela. Erro no SO: {str(e)}")
            return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove regra de bloqueio do IP."""
        if ip not in self.banned_ips:
            return False

        rule_name = f"SENTINELA_BLOCK_{ip.replace('.', '_')}"
        try:
            if self.is_windows:
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd, shell=True, capture_output=True)
            else:
                cmd = f'iptables -D INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, capture_output=True)
        except Exception:
            pass

        self.banned_ips.discard(ip)
        self.banned_records.pop(ip, None)
        self._log("INFO", "FIREWALL_KERNEL", "IP_UNBAN", f"IP {ip} foi liberado do Firewall.")
        return True

    def get_banned_list(self) -> List[Dict[str, Any]]:
        """Retorna lista estruturada de todos os IPs banidos."""
        return list(self.banned_records.values())
