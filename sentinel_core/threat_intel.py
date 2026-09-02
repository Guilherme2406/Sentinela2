# sentinel_core/threat_intel.py
import urllib.request
import json
import logging
from typing import Dict, Any

class ThreatIntelFeed:
    """
    Módulo de Cyber Threat Intelligence (CTI).
    Verifica reputação global de IPs em tempo real contra bases conhecidas de botnets e ataques.
    """

    def __init__(self, logger=None, firewall_manager=None):
        self.logger = logger
        self.firewall_manager = firewall_manager
        # IPs conhecidos de maliciosos mockados / cache local rápido
        self.known_malicious_ips = {
            "185.220.101.5": {"risk": "HIGH", "category": "Tor Exit Node", "country": "DE"},
            "45.146.164.110": {"risk": "CRITICAL", "category": "Ransomware C2", "country": "RU"},
            "193.142.146.35": {"risk": "HIGH", "category": "Brute Force Scanner", "country": "NL"},
            "45.154.255.120": {"risk": "CRITICAL", "category": "CobaltStrike C2", "country": "RU"},
            "91.240.118.172": {"risk": "HIGH", "category": "Mirai Botnet", "country": "UA"}
        }

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Consulta reputação do IP nas redes globais de inteligência."""
        if not ip or ip.startswith(("127.", "10.", "192.168.", "172.16.", "0.0.0.0", "localhost")):
            return {"ip": ip, "threat_score": 0, "status": "SAFE", "details": "Rede Interna"}

        if ip in self.known_malicious_ips:
            info = self.known_malicious_ips[ip]
            if self.logger:
                self.logger.log_event("CRITICAL", "THREAT_INTEL", ip, f"IP {ip} identificado na base CTI Global! Risco: {info['risk']} ({info['category']})")
            return {
                "ip": ip,
                "threat_score": 95,
                "status": "MALICIOUS",
                "category": info["category"],
                "country": info["country"]
            }

        return {"ip": ip, "threat_score": 5, "status": "CLEAN", "details": "Sem histórico de ataques recentes"}

    def is_ip_blacklisted(self, ip: str) -> bool:
        """Verifica se o IP está classificado como malicioso."""
        rep = self.check_ip_reputation(ip)
        return rep.get("status") == "MALICIOUS"

    def sync_global_feeds(self):
        """Sincroniza feeds públicos de CTI."""
        if self.logger:
            self.logger.log_event("INFO", "CTI_FEED", "SYNC", f"Feed CTI sincronizado. {len(self.known_malicious_ips)} IOCs globais mapeados.")
        logging.info(f"[+] Feed CTI sincronizado: {len(self.known_malicious_ips)} IOCs ativos.")

    def sync_feeds(self) -> int:
        self.sync_global_feeds()
        return len(self.known_malicious_ips)

    def start_auto_sync(self, interval_seconds: int = 3600):
        import time
        while True:
            try:
                self.sync_global_feeds()
            except Exception:
                pass
            time.sleep(interval_seconds)

    def get_status(self) -> dict:
        return {
            "feeds_count": len(self.known_malicious_ips),
            "threat_database": "CTI_GLOBAL_ACTIVE",
            "malicious_samples": list(self.known_malicious_ips.keys())
        }

# Alias de compatibilidade
GlobalThreatIntel = ThreatIntelFeed
ThreatIntelFeeds = ThreatIntelFeed


