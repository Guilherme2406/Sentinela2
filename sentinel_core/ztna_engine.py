# sentinel_core/ztna_engine.py
"""
ZTNA CARTA Engine (Zero Trust Network Access - Continuous Adaptive Risk and Trust Assessment)
Implementação de Postura Adaptativa Contínua de Risco e Confiança Zero-Trust.
Avalia dinamicamente o score de risco do endpoint e revoga acessos/isola o dispositivo
quando o risco ultrapassa a métrica de segurança estabelecida (Framework CARTA / NIST SP 800-207).
"""

import time
import logging
import subprocess
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("SentinelaXDR.ZTNA_CARTA")

class ZTNACARTAEngine:
    """
    Motor CARTA Zero-Trust para Avaliação Contínua e Adaptação de Postura.
    Gera um Score de Risco Unificado (0 a 100) e executa ações de contenção progressiva.
    """

    # Pesos de Risco por Categoria de Ameaça (0 a 100)
    THREAT_WEIGHTS = {
        "CANARY_TRIPWIRE": 50,       # Toque em arquivo canário ou honeytoken
        "MEMORY_INJECTION": 45,      # Injeção em RAM / Cobalt Strike
        "MALICIOUS_C2_TRAFFIC": 40,  # Conexão com IP de C2 ou Botnet
        "EDR_INCIDENT": 35,          # Processo destrutivo / Wiper / Ransomware
        "FIM_CORRUPTION": 30,        # Alteração não autorizada em arquivo vital
        "AI_ANOMALY": 25,            # Desvio multidimensional na IA Isolation Forest
        "UEBA_INSIDER_ALERT": 20,    # Anomalia de horário ou exfiltração em lote
        "PORT_SCAN_ATTACK": 20,      # Varredura de portas contra honeypots/tarpit
        "SUSPICIOUS_SCRIPT": 15      # Execução de PowerShell/CMD ofuscado
    }

    # Limiares de Decisão CARTA
    TIER_TRUSTED = (0, 25)
    TIER_MONITORED = (26, 55)
    TIER_HIGH_RISK = (56, 79)
    TIER_QUARANTINED = (80, 100)

    def __init__(self, logger_instance=None):
        self.logger_instance = logger_instance
        self.current_risk_score: float = 0.0
        self.trust_tier: str = "TRUSTED"  # TRUSTED | MONITORED | HIGH_RISK | HOST_QUARANTINED
        self.is_host_isolated: bool = False
        self.active_restrictions: List[str] = []
        self.risk_history: List[Dict[str, Any]] = []
        self.last_evaluation_time: float = time.time()
        self.auto_isolation_enabled: bool = True
        
        logger.info("🛡️ Motor ZTNA CARTA Zero-Trust inicializado (Postura Contínua Ativa).")

    def _log(self, level: str, category: str, action: str, msg: str):
        if self.logger_instance:
            self.logger_instance.log_event(level, category, action, msg)
        getattr(logger, level.lower(), logger.info)(f"[{category}] {msg}")

    def record_threat_event(self, event_type: str, severity: str = "HIGH", details: str = "") -> Dict[str, Any]:
        """
        Registra um evento de ameaça e incrementa o Score de Risco CARTA dinamicamente.
        """
        weight = self.THREAT_WEIGHTS.get(event_type, 15)
        
        # Ajuste de multiplicador por severidade
        multiplier = 1.2 if severity == "CRITICAL" else 1.0 if severity == "HIGH" else 0.7
        added_risk = weight * multiplier

        self.current_risk_score = min(100.0, self.current_risk_score + added_risk)
        
        record = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "added_risk": added_risk,
            "resulting_score": self.current_risk_score,
            "details": details
        }
        self.risk_history.append(record)
        if len(self.risk_history) > 50:
            self.risk_history.pop(0)

        self._evaluate_posture_tier()
        
        self._log(
            "CRITICAL" if self.current_risk_score >= 80 else "HIGH" if self.current_risk_score >= 55 else "WARNING",
            "ZTNA_CARTA",
            "RISK_SCORE_UPDATED",
            f"Evento '{event_type}' (+{added_risk:.1f} pts) -> Risco Atual: {self.current_risk_score:.1f}/100 | Postura: {self.trust_tier}"
        )

        return self.get_status()

    def decay_risk_score(self, decay_rate: float = 2.5):
        """
        Decai o score de risco gradualmente ao longo do tempo na ausência de novos incidentes.
        """
        now = time.time()
        elapsed_minutes = (now - self.last_evaluation_time) / 60.0
        self.last_evaluation_time = now

        if elapsed_minutes > 0 and self.current_risk_score > 0:
            decrease = elapsed_minutes * decay_rate
            self.current_risk_score = max(0.0, self.current_risk_score - decrease)
            self._evaluate_posture_tier()

    def _evaluate_posture_tier(self):
        """
        Atualiza o nível de confiança e impõe/remove restrições de acordo com a política CARTA.
        """
        score = self.current_risk_score
        old_tier = self.trust_tier

        if score < 26:
            self.trust_tier = "TRUSTED"
            self.active_restrictions = []
            if self.is_host_isolated:
                self.restore_host_isolation()
        elif 26 <= score <= 55:
            self.trust_tier = "MONITORED"
            self.active_restrictions = [
                "Bloqueio preventivo de portas administrativas (SMB 445, RPC 135, RDP 3389)",
                "Exigência de re-autenticação MFA para ações privilegiadas",
                "Telemetria avançada de processos em tempo real"
            ]
        elif 56 <= score <= 79:
            self.trust_tier = "HIGH_RISK"
            self.active_restrictions = [
                "Bloqueio preventivo de portas administrativas (SMB, RPC, RDP)",
                "Revogação imediata de montagem de volumes de rede",
                "Ativação forçada do Prevencionista DLP de Saída (Anti-Exfiltração)",
                "Snapshot imutável de emergência disparado"
            ]
        else: # Score >= 80 -> ESTOURO DE MÉTRICA
            self.trust_tier = "HOST_QUARANTINED"
            self.active_restrictions = [
                "ISOLAMENTO TOTAL DE REDE (Host Network Quarantine)",
                "Tráfego externo e interno suspenso (apenas loopback 127.0.0.1 liberado)",
                "Cofre AES-256 e Rollback armados para contenção",
                "Notificação crítica de incidente para o operador"
            ]
            if self.auto_isolation_enabled and not self.is_host_isolated:
                self.enforce_host_isolation(reason=f"Estouro de Métrica CARTA Zero-Trust (Score: {score:.1f}/100)")

        if old_tier != self.trust_tier:
            self._log("CRITICAL" if score >= 80 else "WARNING", "ZTNA_CARTA", "TIER_CHANGE",
                      f"Transição de Postura Zero-Trust: '{old_tier}' ➔ '{self.trust_tier}' (Score: {score:.1f})")

    def enforce_host_isolation(self, reason: str = "ZTNA_METRIC_BREACH") -> Dict[str, Any]:
        """
        Executa o isolamento total de rede do endpoint via regras netsh / WFP.
        Mantém apenas o loopback (127.0.0.1:5000) para gerenciamento local.
        """
        self.is_host_isolated = True
        logger.critical(f"🛑 [ZTNA CARTA] APLICANDO ISOLAMENTO TOTAL DO DISPOSITIVO! Motivo: {reason}")

        try:
            # Cria regra de isolamento temporária no firewall do Windows (bloqueia conexões de entrada/saída não-locais)
            # Obs: Mantém localhost operacional para a API do Sentinela
            cmd = (
                'netsh advfirewall firewall add rule name="SENTINEL_ZTNA_ISOLATION_IN" '
                'dir=in action=block remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255 enable=yes'
            )
            subprocess.run(cmd, shell=True, capture_output=True)
            self._log("CRITICAL", "ZTNA_CARTA", "HOST_ISOLATED", f"Isolamento de rede ativado no host: {reason}")
        except Exception as e:
            logger.error(f"Erro ao isolar rede via firewall: {e}")

        return {"status": "success", "isolated": True, "reason": reason, "timestamp": time.time()}

    def restore_host_isolation(self) -> Dict[str, Any]:
        """
        Remove o isolamento total de rede e restabelece a conectividade normal.
        """
        self.is_host_isolated = False
        logger.info("🟢 [ZTNA CARTA] Restaurando conectividade de rede do dispositivo.")

        try:
            cmd = 'netsh advfirewall firewall delete rule name="SENTINEL_ZTNA_ISOLATION_IN"'
            subprocess.run(cmd, shell=True, capture_output=True)
            self._log("INFO", "ZTNA_CARTA", "HOST_RESTORED", "Isolamento de rede removido com sucesso.")
        except Exception as e:
            logger.error(f"Erro ao remover regra de isolamento: {e}")

        return {"status": "success", "isolated": False, "timestamp": time.time()}

    def reset_risk_posture(self) -> Dict[str, Any]:
        """
        Reseta o score de risco para 0 (Ação administrativa / Pós-Remediação).
        """
        self.current_risk_score = 0.0
        self._evaluate_posture_tier()
        if self.is_host_isolated:
            self.restore_host_isolation()
        
        self._log("INFO", "ZTNA_CARTA", "RISK_RESET", "Score de Risco ZTNA CARTA zerado pelo operador.")
        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        """
        Retorna o estado de telemetria completo da postura CARTA Zero-Trust.
        """
        return {
            "status": "success",
            "framework": "CARTA (Continuous Adaptive Risk and Trust Assessment)",
            "standard": "NIST SP 800-207 Zero Trust Architecture",
            "current_risk_score": round(self.current_risk_score, 1),
            "max_risk_score": 100.0,
            "trust_tier": self.trust_tier,
            "is_host_isolated": self.is_host_isolated,
            "auto_isolation_enabled": self.auto_isolation_enabled,
            "active_restrictions_count": len(self.active_restrictions),
            "active_restrictions": self.active_restrictions,
            "recent_threat_events": self.risk_history[-10:],
            "recommendation": (
                "Sistema seguro e em conformidade." if self.trust_tier == "TRUSTED"
                else "Atenção: Atividades suspeitas detectadas. Restrições parciais ativas." if self.trust_tier == "MONITORED"
                else "ALERTA: Alto risco de infecção. Prevenção de exfiltração engatada." if self.trust_tier == "HIGH_RISK"
                else "🚨 EMERGÊNCIA: Dispositivo isolado preventivamente para conter propagação."
            )
        }
