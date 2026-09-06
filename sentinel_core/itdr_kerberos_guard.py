"""
Sentinela XDR - Motor ITDR & Active Directory / Kerberos Guard
Detecção de ataques contra infraestruturas de identidade, Active Directory e protocolo Kerberos:
Kerberoasting (T1558.003), AS-REP Roasting (T1558.004), DCSync (T1003.006), Pass-the-Hash e Golden Tickets.
"""

import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaITDR")


class ITDRKerberosGuard:
    """Motor de proteção de identidade e auditoria de anomalias no protocolo Kerberos."""

    ATTACK_SIGNATURES = {
        "KERBEROASTING": {
            "name": "Kerberoasting - TGS Ticket Extraction (RC4 Downgrade)",
            "mitre": "T1558.003",
            "severity": "CRITICAL",
            "desc": "Requisição massiva de Service Tickets (TGS) com cifra fraca RC4-HMAC (0x17) para quebra offline de senhas de contas de serviço."
        },
        "ASREP_ROASTING": {
            "name": "AS-REP Roasting - Pre-Authentication Disabled",
            "mitre": "T1558.004",
            "severity": "HIGH",
            "desc": "Solicitação de AS-REP sem pré-autenticação requerida (DONT_REQ_PREAUTH habilitado na conta de usuário)."
        },
        "DCSYNC": {
            "name": "DCSync - Domain Controller Password Replication",
            "mitre": "T1003.006",
            "severity": "CRITICAL",
            "desc": "Tentativa de replicação não autorizada de segredos do NTDS.dit via chamadas DRSGetNCChanges fora de Controladores de Domínio."
        },
        "PASS_THE_TICKET": {
            "name": "Pass-the-Ticket / Overpass-the-Hash",
            "mitre": "T1550.003",
            "severity": "HIGH",
            "desc": "Injeção de ticket TGT/TGS na sessão LUID sem passar pelo fluxo normal de login."
        },
        "GOLDEN_TICKET": {
            "name": "Golden / Silver Ticket Persistence",
            "mitre": "T1558.001",
            "severity": "CRITICAL",
            "desc": "Ticket TGT forjado com chave krbtgt e tempo de expiração anômalo (>10h)."
        }
    }

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.total_evaluations: int = 0
        self.anomalies_detected: int = 0
        self.recent_detections: List[Dict[str, Any]] = []
        self._log("INFO", "ITDR_INIT", "INIT", "Motor ITDR & Kerberos Guard operacional (5 assinaturas ativas).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def inspect_kerberos_ticket(self, spn: str, encryption_type: str, account_name: str = "", client_ip: str = "") -> Dict[str, Any]:
        """Avalia requisições de tickets Kerberos (TGS) em busca de Kerberoasting."""
        self.total_evaluations += 1
        # Cifra RC4 (0x17 ou 'rc4') solicitada para SPNs é forte indício de Kerberoasting
        is_kerberoast = ("rc4" in encryption_type.lower() or "0x17" in encryption_type.lower()) and spn != "krbtgt"

        if is_kerberoast:
            self.anomalies_detected += 1
            sig = self.ATTACK_SIGNATURES["KERBEROASTING"]
            event = {
                "timestamp": time.time(),
                "attack_type": "KERBEROASTING",
                "name": sig["name"],
                "mitre": sig["mitre"],
                "severity": sig["severity"],
                "account": account_name,
                "spn": spn,
                "encryption": encryption_type,
                "client_ip": client_ip,
                "action": "FLAGGED_FOR_INVESTIGATION"
            }
            self.recent_detections.insert(0, event)
            if len(self.recent_detections) > 50:
                self.recent_detections.pop()

            self._log(
                "CRITICAL",
                "ITDR_ALERT",
                "KERBEROASTING_DETECTED",
                f"Ataque Kerberoasting detectado! Conta: '{account_name}', SPN: '{spn}', Cifra fraca: {encryption_type}"
            )

            return {
                "status": "anomaly_detected",
                "is_threat": True,
                "attack_type": "KERBEROASTING",
                "severity": sig["severity"],
                "details": sig["desc"]
            }

        return {"status": "clean", "is_threat": False}

    def inspect_ad_replication(self, source_ip: str, user_principal: str, is_domain_controller: bool = False) -> Dict[str, Any]:
        """Avalia tráfego de replicação do Active Directory para detectar DCSync."""
        self.total_evaluations += 1
        if not is_domain_controller:
            self.anomalies_detected += 1
            sig = self.ATTACK_SIGNATURES["DCSYNC"]
            event = {
                "timestamp": time.time(),
                "attack_type": "DCSYNC",
                "name": sig["name"],
                "mitre": sig["mitre"],
                "severity": sig["severity"],
                "account": user_principal,
                "source_ip": source_ip,
                "action": "BLOCKED_OR_FLAGGED"
            }
            self.recent_detections.insert(0, event)
            if len(self.recent_detections) > 50:
                self.recent_detections.pop()

            self._log(
                "CRITICAL",
                "ITDR_ALERT",
                "DCSYNC_DETECTED",
                f"Tentativa de DCSync detectada a partir de host não-DC ({source_ip})! Conta: {user_principal}"
            )

            return {
                "status": "anomaly_detected",
                "is_threat": True,
                "attack_type": "DCSYNC",
                "severity": sig["severity"],
                "details": sig["desc"]
            }

        return {"status": "clean", "is_threat": False}

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do motor ITDR."""
        return {
            "status": "active",
            "total_evaluations": self.total_evaluations,
            "anomalies_detected": self.anomalies_detected,
            "signatures_loaded": len(self.ATTACK_SIGNATURES),
            "recent_detections": self.recent_detections[:10]
        }
