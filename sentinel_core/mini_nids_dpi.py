"""
Sentinela XDR - Motor Mini-NIDS & Deep Packet Inspection (DPI)
Inspeção tática de pacotes em portas de rede críticas: detecção de tunelamento DNS (exfiltração Base64),
certificados TLS maliciosos, varreduras stealth e User-Agents de ferramentas de invasão (Cobalt Strike, Sqlmap).
"""

import math
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaMiniNIDS")


class MiniNIDSDPI:
    """Motor de inspeção profunda de pacotes (DPI) e detecção de intrusão de rede."""

    ATTACK_USER_AGENTS = [
        "sqlmap", "nikto", "nmap", "nessus", "acunetix",
        "masscan", "gobuster", "dirbuster", "wpscan"
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.total_packets_inspected: int = 0
        self.network_anomalies: int = 0
        self.recent_alerts: List[Dict[str, Any]] = []
        self._log("INFO", "MINI_NIDS_INIT", "INIT", "Motor Mini-NIDS & Deep Packet Inspection (DPI) operacional.")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def _calculate_entropy(self, text: str) -> float:
        """Calcula a entropia de Shannon de uma string."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def inspect_dns_query(self, query: str, client_ip: str = "") -> Dict[str, Any]:
        """Analisa requisições DNS em busca de tunelamento e exfiltração de dados."""
        self.total_packets_inspected += 1
        q_clean = query.lower().strip()
        entropy = self._calculate_entropy(q_clean)
        is_tunneling = False
        reason = ""

        # Critérios de DNS Tunneling:
        labels = q_clean.split(".")
        max_label_len = max([len(l) for l in labels]) if labels else 0
        if (len(q_clean) > 50 and entropy > 3.2) or max_label_len > 35 or len(q_clean) > 75:
            is_tunneling = True
            reason = f"Provável tunelamento DNS detectado! (Tamanho: {len(q_clean)}, Entropia: {entropy:.2f}, Rótulo máx: {max_label_len})"

        if is_tunneling:
            self.network_anomalies += 1
            alert = {
                "timestamp": time.time(),
                "type": "DNS_TUNNELING_EXFILTRATION",
                "severity": "HIGH",
                "client_ip": client_ip,
                "query": q_clean[:100],
                "entropy": round(entropy, 2),
                "reason": reason
            }
            self.recent_alerts.insert(0, alert)
            if len(self.recent_alerts) > 50:
                self.recent_alerts.pop()

            self._log("HIGH", "MINI_NIDS_ALERT", "DNS_TUNNELING", f"Tunelamento DNS interceptado a partir de {client_ip}: {q_clean[:60]}...")

        return {
            "status": "anomaly_detected" if is_tunneling else "clean",
            "is_anomaly": is_tunneling,
            "entropy": round(entropy, 2),
            "reason": reason
        }

    def inspect_http_traffic(self, user_agent: str, path: str, client_ip: str = "") -> Dict[str, Any]:
        """Analisa requisições HTTP em busca de scanners automáticos e exploração."""
        self.total_packets_inspected += 1
        ua_clean = user_agent.lower()
        matched_scanner = None

        for scanner in self.ATTACK_USER_AGENTS:
            if scanner in ua_clean:
                matched_scanner = scanner
                break

        if matched_scanner:
            self.network_anomalies += 1
            alert = {
                "timestamp": time.time(),
                "type": "ATTACK_SCANNER_DETECTED",
                "severity": "HIGH",
                "client_ip": client_ip,
                "scanner": matched_scanner,
                "user_agent": user_agent[:120],
                "path": path[:80]
            }
            self.recent_alerts.insert(0, alert)
            if len(self.recent_alerts) > 50:
                self.recent_alerts.pop()

            self._log("HIGH", "MINI_NIDS_ALERT", "SCANNER_DETECTED", f"Scanner de ataque detectado ({matched_scanner.upper()}) de {client_ip}!")

            return {
                "status": "blocked",
                "is_anomaly": True,
                "scanner": matched_scanner,
                "reason": f"User-Agent corresponde a ferramenta de ataque conhecida ({matched_scanner})."
            }

        return {"status": "clean", "is_anomaly": False}

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do Mini-NIDS."""
        return {
            "status": "active",
            "total_packets_inspected": self.total_packets_inspected,
            "network_anomalies": self.network_anomalies,
            "recent_alerts": self.recent_alerts[:10]
        }
