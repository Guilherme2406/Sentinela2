# sentinel_core/firewall_manager.py
import re
import ipaddress
import subprocess
import sys
import time
import logging
from datetime import datetime
from typing import Set, Dict, Any, List

#: Whitelist estrita de caracteres seguros para a descrição da regra no shell/CMD
_SAFE_REASON_RE = re.compile(r'[^A-Za-z0-9 _\-.,:()/]+')
_IPV4_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$')

#: Redes privadas/link-local que NUNCA devem ser bloqueadas (evita auto-isolamento)
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("0.0.0.0/8"),
)

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

    @staticmethod
    def _sanitize_reason(reason: str) -> str:
        """Remove metacaracteres de shell/CMD da descrição para evitar injeção."""
        reason = _SAFE_REASON_RE.sub(" ", str(reason or "")).strip()
        return reason[:200] or "Ataque detectado pelo Sentinela XDR"

    def _valid_ip(self, ip: str) -> bool:
        """Valida se o IP é um IPv4 sintaticamente correto."""
        if not ip or not isinstance(ip, str):
            return False
        return bool(_IPV4_RE.match(ip.strip()) and ip.count(".") == 3)

    def _is_private_or_linklocal(self, ip: str) -> bool:
        """Detecta IPs de redes privadas/locais que jamais devem ser banidos."""
        try:
            addr = ipaddress.IPv4Address(ip.strip())
        except ipaddress.AddressValueError:
            return True
        return any(addr in net for net in _PRIVATE_NETWORKS)

    def is_banned(self, ip: str) -> bool:
        """Verifica se o IP está banido na camada ativa."""
        return ip in self.banned_ips

    def block_ip(self, ip: str, reason: str = "Ataque detectado pelo Sentinela XDR") -> bool:
        """Adiciona regra de bloqueio de IP no Firewall do SO e no XDR Shield."""
        ip = str(ip or "").strip()
        if not self._valid_ip(ip):
            logging.warning(f"[FIREWALL] IP inválido ignorado: {ip!r}")
            return False
        if self._is_private_or_linklocal(ip):
            logging.warning(f"[FIREWALL] IP de rede privada/local ignorado para bloqueio: {ip}")
            return False

        if ip in self.banned_ips:
            return True

        reason = self._sanitize_reason(reason)
        rule_name = f"SENTINELA_BLOCK_{ip.replace('.', '_')}"
        kernel_enforced = False

        try:
            if self.is_windows:
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={rule_name}", "dir=in", "action=block",
                       f"remoteip={ip}", f"description={reason}"]
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if self.is_windows else 0
                res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6, creationflags=flags)
                if res.returncode == 0:
                    kernel_enforced = True
            else:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6)
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
        ip = str(ip or "").strip()
        if not self._valid_ip(ip):
            return False
        if ip not in self.banned_ips:
            return False

        rule_name = f"SENTINELA_BLOCK_{ip.replace('.', '_')}"
        try:
            if self.is_windows:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if self.is_windows else 0
                subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6, creationflags=flags)
            else:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=6)

        except Exception:
            pass

        self.banned_ips.discard(ip)
        self.banned_records.pop(ip, None)
        self._log("INFO", "FIREWALL_KERNEL", "IP_UNBAN", f"IP {ip} foi liberado do Firewall.")
        return True

    def get_banned_list(self) -> List[Dict[str, Any]]:
        """Retorna lista estruturada de todos os IPs banidos."""
        return list(self.banned_records.values())
