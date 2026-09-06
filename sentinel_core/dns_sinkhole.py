"""
Sentinela XDR - DNS Sinkholing & DGA Blocker Local
Módulo de bloqueio e desvio de resolução para domínios maliciosos de C2, Botnets e DGAs.
Interrompe a cadeia de comunicação com atacantes redirecionando consultas para o loopback (127.0.0.1).
"""

import math
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaDNSSinkhole")


class DNSSinkholeGuard:
    """Motor de inspeção, cálculo de entropia DGA e redirecionamento de DNS malicioso."""

    KNOWN_C2_DOMAINS = {
        "cobaltstrike-c2.online",
        "apt29-beacon.ru",
        "darkside-ransom.biz",
        "lockbit-leak.top",
        "revil-payment.cc",
        "emotet-loader.net",
        "redline-stealer.xyz",
        "qakbot-node.su"
    }

    SUSPICIOUS_TLDS = {".top", ".xyz", ".biz", ".cc", ".su", ".work", ".click", ".click"}

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.sinkholed_domains = set(self.KNOWN_C2_DOMAINS)
        self.intercepted_queries_count = 0
        self.recent_sinkholes: List[Dict[str, Any]] = []
        self._log("INFO", "DNS_SINKHOLE", "INIT", f"Motor ativado ({len(self.sinkholed_domains)} domínios C2 e detector de DGA).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calcula a entropia de Shannon para detectar domínios gerados por algoritmo (DGA)."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts = {}
        for c in text.lower():
            counts[c] = counts.get(c, 0) + 1
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return round(entropy, 3)

    def inspect_domain(self, domain: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Inspeciona uma requisição de domínio/FQDN.
        Avalia contra a base C2 e calcula pontuação de DGA.
        """
        if not domain:
            return {"status": "allowed", "domain": "", "is_malicious": False}

        d_clean = domain.lower().strip().rstrip(".")
        base_name = d_clean.split(".")[0] if "." in d_clean else d_clean
        entropy = self.calculate_entropy(base_name)

        C2_KEYWORDS = ["cobaltstrike", "evil-c2", "ransomware", "revil", "darkside", "emotet", "qakbot", "redline"]
        has_c2_keyword = any(kw in d_clean for kw in C2_KEYWORDS)
        is_c2 = d_clean in self.sinkholed_domains or any(d_clean.endswith("." + c2) for c2 in self.sinkholed_domains) or has_c2_keyword
        has_suspicious_tld = any(d_clean.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
        
        # Heurística DGA: Entropia alta (> 3.6), comprimento relevante (> 12) e TLD suspeito ou sem vogais comuns
        is_dga = (entropy >= 3.65 and len(base_name) >= 12) or (entropy >= 3.4 and has_suspicious_tld)

        if is_c2 or is_dga:
            reason = "C2_KNOWN_BLACKLIST" if is_c2 else f"DGA_ALGORITHM_DETECTED (Entropy: {entropy})"
            sinkhole_ip = "127.0.0.1"
            self.intercepted_queries_count += 1
            
            event = {
                "domain": d_clean,
                "reason": reason,
                "entropy": entropy,
                "redirect_ip": sinkhole_ip,
                "pid": pid,
                "action": "SINKHOLED"
            }
            self.recent_sinkholes.insert(0, event)
            if len(self.recent_sinkholes) > 50:
                self.recent_sinkholes.pop()

            self._log(
                "WARNING",
                "DNS_SINKHOLE",
                "BLOCKED_C2",
                f"Consulta maliciosa bloqueada! Domínio: '{d_clean}' Motivo: {reason} -> Desviado para {sinkhole_ip}"
            )

            return {
                "status": "sinkholed",
                "domain": d_clean,
                "is_malicious": True,
                "resolved_ip": sinkhole_ip,
                "reason": reason,
                "entropy": entropy
            }

        return {
            "status": "allowed",
            "domain": d_clean,
            "is_malicious": False,
            "entropy": entropy
        }

    def add_custom_sinkhole_domain(self, domain: str):
        """Adiciona um domínio personalizado à lista de sinkhole."""
        if domain:
            self.sinkholed_domains.add(domain.lower().strip())

    def check_domain(self, domain: str) -> bool:
        """Verifica se o domínio é malicioso/sinkholed (retorna True se malicioso, False se limpo)."""
        res = self.inspect_domain(domain)
        return bool(res.get("is_malicious", False))

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do módulo DNS Sinkhole."""
        return {
            "engine": "Sentinel DNS Sinkholing & DGA Armor",
            "active": True,
            "status": "ACTIVE",
            "sinkholed_rules_count": len(self.sinkholed_domains),
            "intercepted_queries_count": self.intercepted_queries_count,
            "recent_sinkholes": self.recent_sinkholes[:10]
        }

    status = get_status
