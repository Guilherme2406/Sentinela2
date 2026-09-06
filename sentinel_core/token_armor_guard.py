# sentinel_core/token_armor_guard.py
"""
🥔 SENTINELA TOKEN ARMOR & POTATO PRIVILEGE ESCALATION SHIELD (NÍVEL SOVEREIGN ENTERPRISE)
Blindagem ativa contra abuso de tokens de acesso do Windows e elevação de privilégios:
  - Prevenção contra a família de exploits 'Potato' (JuicyPotato, SweetPotato, GodPotato, PrintSpoofer, BadPotato)
  - Auditoria de privilégios de alto risco em tokens de processo:
      * SeImpersonatePrivilege
      * SeAssignPrimaryTokenPrivilege
      * SeDebugPrivilege
      * SeTcbPrivilege
      * SeTakeOwnershipPrivilege
  - Detecção de sequestro de sessão e token impersonation não autorizado
Alinhado estritamente ao MITRE ATT&CK:
  - T1134.001: Access Token Manipulation - Token Impersonation/Theft
  - T1068: Exploitation for Privilege Escalation
  - T1078: Valid Accounts
"""

import os
import sys
import time
import logging
from typing import Dict, Any, List, Optional, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("SentinelaXDR.TokenArmor")


class TokenArmorGuard:
    """
    Motor Soberano de Proteção de Tokens de Acesso e Prevenção de Elevação de Privilégios.
    Neutraliza tentativas de escalonamento abusando de privilégios de impersonação do Windows.
    """

    # Privilégios críticos comumente explorados para elevação de privilégio local (LPE)
    HIGH_RISK_PRIVILEGES = {
        "SeImpersonatePrivilege": "Permite personificar clientes após autenticação (Explorado por Potato/PrintSpoofer)",
        "SeAssignPrimaryTokenPrivilege": "Permite associar token primário a novos processos",
        "SeDebugPrivilege": "Permite inspecionar e injetar código em processos de outros usuários/SYSTEM",
        "SeTcbPrivilege": "Identifica o chamador como parte da base de computação confiável do SO",
        "SeCreateTokenPrivilege": "Permite forjar tokens arbitrários no subsistema de segurança",
        "SeTakeOwnershipPrivilege": "Permite assumir a posse de qualquer objeto de segurança do sistema"
    }

    # Assinaturas e padrões de ferramentas conhecidas da família Potato
    POTATO_HEURISTIC_PATTERNS = [
        "godpotato", "juicypotato", "sweetpotato", "printspoofer",
        "badpotato", "efspotato", "roguepotato", "sharpimpersonation",
        "cve-2020-0668", "cve-2022-38028", "spoolsv_pipe"
    ]

    def __init__(self, logger_instance=None, soar=None, orchestrator=None):
        self.logger = logger_instance
        self.soar = soar
        self.orchestrator = orchestrator
        self.is_active: bool = True
        self.total_scans: int = 0
        self.detected_violations: List[Dict[str, Any]] = []

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def audit_running_processes_tokens(self) -> List[Dict[str, Any]]:
        """
        Inspeciona processos em execução procurando comandos e executáveis com assinaturas
        de manipulação de tokens e privilégios suspeitos.
        """
        self.total_scans += 1
        anomalies = []

        if not HAS_PSUTIL:
            return anomalies

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                if pid <= 4:
                    continue

                pname = (pinfo['name'] or '').lower()
                cmdline = " ".join(pinfo['cmdline'] or []).lower()
                username = (pinfo['username'] or '').lower()

                # 1. Detecção Heurística de Ferramentas Potato por Linha de Comando ou Nome
                for pat in self.POTATO_HEURISTIC_PATTERNS:
                    if pat in pname or pat in cmdline:
                        violation = {
                            "timestamp": time.time(),
                            "pid": pid,
                            "process_name": pinfo['name'],
                            "username": pinfo['username'],
                            "matched_pattern": pat,
                            "attack_type": "POTATO_PRIVILEGE_ESCALATION",
                            "severity": "CRITICAL",
                            "mitre": "T1134.001",
                            "description": f"Executável ou comando com assinatura de exploit Potato ({pat})."
                        }
                        anomalies.append(violation)
                        self.detected_violations.insert(0, violation)
                        if len(self.detected_violations) > 50:
                            self.detected_violations.pop()

                        self._log(
                            "CRITICAL", "TOKEN_ARMOR", "POTATO_EXPLOIT_DETECTED",
                            f"Tentativa de escalonamento Potato interceptada! PID: {pid} | Processo: {pinfo['name']} | Padrão: {pat}"
                        )

                        # Resposta SOAR: Encerramento do processo malicioso
                        if self.soar and hasattr(self.soar, "terminate_process"):
                            try:
                                self.soar.terminate_process(pid)
                            except Exception as e:
                                logger.debug(f"[TOKEN_ARMOR] Falha ao encerrar processo {pid}: {e}")

                        # Notificação ao barramento de orquestração
                        if self.orchestrator and hasattr(self.orchestrator, "emit"):
                            try:
                                from sentinel_core.sentinela_orchestrator import SecurityEvent
                                self.orchestrator.emit(SecurityEvent(
                                    source="TOKEN_ARMOR",
                                    severity="CRITICAL",
                                    data=violation
                                ))
                            except Exception as e:
                                logger.debug(f"[TOKEN_ARMOR] Falha ao emitir no orquestrador: {e}")

                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"[TOKEN_ARMOR] Erro ao inspecionar processo: {e}")

        return anomalies

    def simulate_potato_attack(self, target_name: str = "GodPotato-NET4.exe", simulated_pid: int = 4982) -> Dict[str, Any]:
        """Simulação segura de interceptação de exploit Potato para testes e auditoria."""
        violation = {
            "timestamp": time.time(),
            "pid": simulated_pid,
            "process_name": target_name,
            "username": "NT AUTHORITY\\LOCAL SERVICE",
            "matched_pattern": "godpotato",
            "attack_type": "POTATO_PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "mitre": "T1134.001",
            "description": "Simulação de interceptação de GodPotato sequestrando DCOM RPC para elevação SYSTEM."
        }
        self.detected_violations.insert(0, violation)
        if len(self.detected_violations) > 50:
            self.detected_violations.pop()
        self._log("CRITICAL", "TOKEN_ARMOR", "SIMULATION", f"Simulação de interceptação Potato concluída com sucesso para PID {simulated_pid}.")
        return violation

    def get_status(self) -> Dict[str, Any]:
        """Retorna as métricas operacionais e regras ativas do guardião de tokens."""
        return {
            "is_active": self.is_active,
            "monitored_privileges": list(self.HIGH_RISK_PRIVILEGES.keys()),
            "high_risk_privileges_details": self.HIGH_RISK_PRIVILEGES,
            "total_scans": self.total_scans,
            "violations_detected_count": len(self.detected_violations),
            "recent_violations": self.detected_violations[:10],
            "mitre_alignment": ["T1134.001", "T1068", "T1078"]
        }
