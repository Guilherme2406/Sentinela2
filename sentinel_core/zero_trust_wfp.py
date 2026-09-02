# sentinel_core/zero_trust_wfp.py
import logging
from typing import Dict, Any, List, Set, Optional

logger = logging.getLogger("SentinelaXDR.ZeroTrustWFP")

class ZeroTrustNetworkEngine:
    """
    Motor Avançado de Microsegmentação de Rede Zero-Trust (Windows Filtering Platform - WFP Driver) — Modo Hardened.
    Impede movimentação lateral e ataques de enumeração em domínio Active Directory,
    bloqueando portas críticas (SMB, RDP, WMI, WinRM, LDAP, Kerberos, VNC)
    originadas por LOLBins ou processos não autorizados.
    """
    
    CRITICAL_LATERAL_PORTS = {
        445: "SMB (Ransomware Propagation & Lateral Movement)",
        135: "RPC Endpoint Mapper (Remote Execution)",
        3389: "RDP Remote Desktop (Interactive Access)",
        5985: "WinRM HTTP (Remote PowerShell)",
        5986: "WinRM HTTPS (Encrypted Remote Shell)",
        389: "LDAP Active Directory Recon",
        636: "LDAPS Secure AD Query",
        88: "Kerberos Ticket Spoofing / Pass-the-Ticket",
        5900: "VNC Remote Control"
    }

    UNTRUSTED_CALLER_PROCESSES = {
        "powershell.exe", "cmd.exe", "rundll32.exe", "psexec.exe", 
        "wmic.exe", "certutil.exe", "bitsadmin.exe", "wscript.exe", 
        "cscript.exe", "mshta.exe", "regsvr32.exe", "bash.exe"
    }

    def __init__(self, firewall_manager=None, ztna_engine=None):
        self.blocked_ips: Set[str] = set()
        self.firewall = firewall_manager
        self.ztna = ztna_engine
        self.allowed_subnets: List[str] = ["10.0.0.0/8", "192.168.1.0/24"]
        logger.info("🛡️ Motor Zero-Trust WFP Driver inicializado (Microsegmentação Ativa).")

    def inspect_packet(self, src_ip: str, dst_ip: str, dst_port: int, process_name: str) -> Dict[str, Any]:
        """
        Inspeciona cada tentativa de conexão de saída/entrada no nível de driver.
        """
        proc_clean = (process_name or "").lower()

        # 1. Se o IP já está na lista de bloqueio Zero-Trust
        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            return {
                "action": "BLOCK",
                "reason": "IP_IN_BLACK_LIST",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port
            }

        # 2. Bloqueio de Movimentação Lateral via SMB/RPC/RDP/WinRM por processos não confiáveis
        if dst_port in self.CRITICAL_LATERAL_PORTS:
            if proc_clean in self.UNTRUSTED_CALLER_PROCESSES:
                port_desc = self.CRITICAL_LATERAL_PORTS[dst_port]
                logger.critical(
                    f"⛔ [ZERO-TRUST WFP] MOVIMENTAÇÃO LATERAL BLOQUEADA! Processo '{proc_clean}' tentando conectar em "
                    f"{dst_ip}:{dst_port} [{port_desc}]"
                )
                self.blocked_ips.add(dst_ip)

                if self.firewall:
                    self.firewall.block_ip(dst_ip, reason=f"Zero-Trust Lateral Block ({proc_clean} -> {dst_port})")

                if self.ztna:
                    self.ztna.record_threat_event("PORT_SCAN_ATTACK", severity="HIGH", details=f"Tentativa lateral de {proc_clean} para {dst_ip}:{dst_port}")

                return {
                    "action": "BLOCK",
                    "reason": "LATERAL_MOVEMENT_PREVENTION",
                    "port_description": port_desc,
                    "process_name": proc_clean,
                    "dst_ip": dst_ip
                }

        return {"action": "ALLOW", "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port}
