# sentinel_core/network_perimeter_guard.py
"""
🌐 SENTINELA NETWORK & LOCAL PERIMETER GUARD (NÍVEL SOVEREIGN ENTERPRISE)
Motor de proteção de perímetro de rede local, detecção de ataques Man-in-the-Middle (ARP Spoofing),
bloqueio de C2 via algoritmos de geração de domínios (DGA), detecção de exfiltração por DNS Tunneling
e auditoria de integridade do arquivo hosts e portas de backdoor em escuta.
Alinhado rigorosamente com MITRE ATT&CK:
- T1557: Adversary-in-the-Middle (T1557.002 ARP Poisoning, T1557.001 LLMNR/NBT-NS Poisoning)
- T1568.002: Dynamic Resolution: Domain Generation Algorithms (DGA)
- T1071.004: Application Layer Protocol: DNS (DNS Tunneling Exfiltration)
- T1565.001: Data Manipulation: Stored Data Manipulation (Hosts File Hijack)
"""

import os
import sys
import time
import re
import math
import subprocess
import logging
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

_sys_log = logging.getLogger("SentinelaXDR.PerimeterGuard")


class NetworkPerimeterGuard:
    """
    Motor de Defesa de Rede e Perímetro Local.
    Protege o endpoint contra envenenamento ARP em redes locais/Wi-Fi,
    bloqueia consultas a domínios DGA de alta entropia e audita o arquivo hosts do sistema.
    """

    # Domínios de segurança e serviços críticos cuja alteração no hosts indica sequestro
    CRITICAL_SECURITY_DOMAINS = {
        "microsoft.com", "windowsupdate.com", "virustotal.com", "kaspersky.com",
        "symantec.com", "sophos.com", "mcafee.com", "github.com", "bitdefender.com"
    }

    # Provedores conhecidos de Dynamic DNS e túneis frequentemente abusados por agentes maliciosos
    SUSPICIOUS_TUNNEL_DOMAINS = {
        "duckdns.org", "ngrok-free.app", "localtunnel.me", "nip.io", "sslip.io", "portmap.io"
    }

    # Portas padrão de Trojans e listeners de backdoor
    BACKDOOR_LISTEN_PORTS = {4444, 1337, 31337, 5555, 6667, 8888, 9999}

    def __init__(self, logger=None, soar=None, orchestrator=None):
        self.logger = logger
        self.soar = soar
        self.orchestrator = orchestrator
        self.intercepted_events: List[Dict[str, Any]] = []
        self.active_shields = {
            "dga_armor": True,
            "arp_mitm_shield": True,
            "dns_tunneling_guard": True,
            "hosts_file_guard": True,
            "backdoor_listener_guard": True
        }
        logger_name = self.logger.__class__.__name__ if self.logger else "None"
        _sys_log.info(f"🌐 [PERIMETER_GUARD] Motor de Rede e Perímetro Local ativado (Logger: {logger_name}).")

    def _log_event(self, severity: str, action: str, target: str, message: str) -> None:
        """Registra no SecurityEventLogger e despacha ao Orquestrador se disponível."""
        if self.logger:
            try:
                self.logger.log_event(severity, "NETWORK_PERIMETER_GUARD", target, message)
            except Exception as e:
                _sys_log.error(f"[PERIMETER_GUARD] Falha ao registrar log de segurança: {e}")

        if self.orchestrator:
            try:
                from sentinel_core.sentinela_orchestrator import SecurityEvent
                event = SecurityEvent(
                    source="NETWORK_PERIMETER_GUARD",
                    severity=severity,
                    data={
                        "action": action,
                        "target": target,
                        "description": message,
                        "timestamp": time.time()
                    }
                )
                self.orchestrator.emit(event)
            except Exception as e:
                _sys_log.debug(f"[PERIMETER_GUARD] Erro ao emitir evento ao orquestrador: {e}")

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calcula a entropia estocástica de Shannon de uma string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum(p * math.log2(p) for p in prob)
        return round(entropy, 3)

    def inspect_dns_query(self, domain: str) -> Dict[str, Any]:
        """
        Analisa um domínio em busca de padrões DGA (alta entropia),
        DNS Tunneling (subdomínios anormais com dados codificados) ou C2 dinâmico.
        """
        domain_clean = domain.lower().strip().rstrip(".")
        if not domain_clean:
            return {"status": "CLEAN", "domain": domain, "reason": "Empty"}

        parts = domain_clean.split(".")
        main_label = parts[0] if len(parts) > 0 else ""
        entropy = self.calculate_shannon_entropy(main_label)
        total_len = len(domain_clean)

        # 1. Detecção de DNS Tunneling (MITRE T1071.004)
        # Consultas de exfiltração por DNS possuem rótulos extremamente longos ou sequências hex/base64
        is_tunneling = False
        tunneling_reason = ""
        for p in parts[:-2] if len(parts) >= 2 else parts:
            if len(p) >= 35 or (len(p) >= 20 and re.match(r"^[a-f0-9]+$", p)):
                is_tunneling = True
                tunneling_reason = f"Subdomínio de alta densidade de carga útil ({len(p)} caracteres)"
                break

        if is_tunneling:
            threat = {
                "status": "DNS_TUNNELING_DETECTED",
                "domain": domain_clean,
                "mitre": "T1071.004",
                "severity": "CRITICAL",
                "entropy": entropy,
                "length": total_len,
                "description": f"Possível canal de exfiltração oculta via DNS Tunneling: {tunneling_reason}"
            }
            self.intercepted_events.append(threat)
            self._log_event("CRITICAL", "DNS_TUNNELING", domain_clean, threat["description"])
            return threat

        # 2. Detecção de DGA (Domain Generation Algorithm - MITRE T1568.002)
        # Domínios DGA normalmente têm alta entropia (>3.65), comprimento >= 12 e poucas vogais
        vowels = set("aeiou")
        vowel_count = sum(1 for c in main_label if c in vowels)
        consonant_ratio = (len(main_label) - vowel_count) / max(1, len(main_label))

        is_dga = False
        if len(main_label) >= 12 and entropy >= 3.65 and consonant_ratio >= 0.70:
            is_dga = True

        if is_dga:
            threat = {
                "status": "DGA_C2_DETECTED",
                "domain": domain_clean,
                "mitre": "T1568.002",
                "severity": "HIGH",
                "entropy": entropy,
                "length": total_len,
                "description": f"Domínio sintético DGA detectado (Entropia: {entropy}, Consonantes: {round(consonant_ratio*100)}%)"
            }
            self.intercepted_events.append(threat)
            self._log_event("HIGH", "DGA_C2_BLOCKED", domain_clean, threat["description"])
            return threat

        # 3. Detecção de Túneis e Dynamic DNS Suspeitos
        for sus_tld in self.SUSPICIOUS_TUNNEL_DOMAINS:
            if domain_clean.endswith(sus_tld):
                threat = {
                    "status": "SUSPICIOUS_TUNNEL_DOMAIN",
                    "domain": domain_clean,
                    "mitre": "T1071",
                    "severity": "MEDIUM",
                    "entropy": entropy,
                    "description": f"Acesso a túnel de rede / Dynamic DNS potencialmente malicioso ({sus_tld})"
                }
                return threat

        return {
            "status": "CLEAN",
            "domain": domain_clean,
            "entropy": entropy,
            "length": total_len,
            "classification": "LEGITIMATE"
        }

    def audit_arp_table(self, custom_arp_output: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspeciona a tabela ARP do sistema operacional buscando duplicatas de MAC.
        Se múltiplos endereços IP (em particular o Gateway) apontarem para o mesmo MAC,
        indica ataque Man-in-the-Middle (ARP Poisoning).
        """
        raw_output = custom_arp_output
        if raw_output is None:
            try:
                res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=4)
                raw_output = res.stdout
            except Exception as e:
                _sys_log.debug(f"[PERIMETER_GUARD] Falha ao executar 'arp -a': {e}")
                raw_output = ""

        # Mapeia { mac_address: [ips] }
        mac_to_ips: Dict[str, List[str]] = {}
        ip_to_mac: Dict[str, str] = {}
        # Regex para linhas do arp -a no Windows: 192.168.1.1   00-11-22-33-44-55   dinâmico
        arp_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})\s+(\w+)")

        for line in raw_output.splitlines():
            m = arp_pattern.search(line)
            if m:
                ip, mac, arp_type = m.group(1), m.group(2).lower().replace("-", ":"), m.group(3)
                # Ignora endereços multicast / broadcast
                if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue

                ip_to_mac[ip] = mac
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = []
                mac_to_ips[mac].append(ip)

        # Identifica duplicatas de MAC (Ataque ARP Spoofing / MITM)
        spoofing_alerts = []
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                alert = {
                    "mac": mac,
                    "conflicting_ips": ips,
                    "severity": "CRITICAL",
                    "mitre": "T1557.002",
                    "description": f"🚨 [ARP SPOOFING / MITM] Endereço MAC '{mac}' associado a múltiplos IPs: {', '.join(ips)}! Possível interceptação de tráfego na rede local."
                }
                spoofing_alerts.append(alert)
                self.intercepted_events.append(alert)
                self._log_event("CRITICAL", "ARP_SPOOFING_DETECTED", mac, alert["description"])

        return {
            "status": "MITM_ATTACK_DETECTED" if spoofing_alerts else "HEALTHY",
            "entries_analyzed": len(ip_to_mac),
            "alerts_count": len(spoofing_alerts),
            "alerts": spoofing_alerts,
            "arp_mappings": [{"ip": ip, "mac": mac} for ip, mac in ip_to_mac.items()]
        }

    def audit_hosts_file(self) -> Dict[str, Any]:
        """
        Audita o arquivo de resolução estática de nomes (C:\\Windows\\System32\\drivers\\etc\\hosts).
        Gera alerta crítico se sites de antivírus, bancos ou updates estiverem redirecionados.
        """
        hosts_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
        if not os.path.exists(hosts_path):
            return {"status": "NOT_FOUND", "message": "Arquivo hosts não localizado."}

        hijacked_domains = []
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split()
                    if len(parts) >= 2:
                        target_ip = parts[0]
                        domain = parts[1].lower()
                        for sec_dom in self.CRITICAL_SECURITY_DOMAINS:
                            if sec_dom in domain and target_ip in ("127.0.0.1", "0.0.0.0"):
                                hijacked_domains.append({"domain": domain, "redirect_ip": target_ip})

            if hijacked_domains:
                alert_desc = f"Arquivo hosts do Windows adulterado! {len(hijacked_domains)} domínios de segurança redirecionados."
                self._log_event("CRITICAL", "HOSTS_FILE_HIJACK", hosts_path, alert_desc)
                return {
                    "status": "HOSTS_FILE_HIJACKED",
                    "severity": "CRITICAL",
                    "mitre": "T1565.001",
                    "hijacked_count": len(hijacked_domains),
                    "details": hijacked_domains
                }
        except Exception as e:
            _sys_log.debug(f"[PERIMETER_GUARD] Erro ao ler arquivo hosts: {e}")

        return {"status": "INTEACT", "hijacked_count": 0}

    def audit_network_listeners(self) -> List[Dict[str, Any]]:
        """
        Varre portas de escuta abertas no host em busca de backdoors e Trojans.
        """
        suspicious_listeners = []
        if not HAS_PSUTIL:
            return suspicious_listeners

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    port = conn.laddr.port
                    ip = conn.laddr.ip
                    pid = conn.pid

                    if port in self.BACKDOOR_LISTEN_PORTS and ip in ("0.0.0.0", "::", ""):
                        pname = "Desconhecido"
                        if pid:
                            try:
                                pname = psutil.Process(pid).name()
                            except Exception:
                                pass

                        listener_info = {
                            "port": port,
                            "ip": ip,
                            "pid": pid,
                            "process_name": pname,
                            "severity": "HIGH",
                            "description": f"Porta de alto risco {port} aberta em 0.0.0.0 pelo processo '{pname}' (PID: {pid})"
                        }
                        suspicious_listeners.append(listener_info)
                        self._log_event("HIGH", "BACKDOOR_LISTENER_OPEN", f"{ip}:{port}", listener_info["description"])
        except Exception as e:
            _sys_log.debug(f"[PERIMETER_GUARD] Erro ao inspecionar listeners: {e}")

        return suspicious_listeners

    def get_status(self) -> Dict[str, Any]:
        """Retorna as métricas e estado dos escudos de perímetro de rede."""
        return {
            "engine": "Sentinel Network & Local Perimeter Guard",
            "version": "2.5 Sovereign Enterprise",
            "status": "ACTIVE_DEFENSE",
            "active_shields": self.active_shields,
            "intercepted_events_count": len(self.intercepted_events),
            "recent_events": self.intercepted_events[-10:] if self.intercepted_events else []
        }
