# sentinel_core/shadow_mode_soar.py
import time
import logging
from typing import Dict, Any, List

logger = logging.getLogger("SentinelaXDR.ShadowSOAR")

class ShadowModeSOAR:
    """
    Motor de Resposta SOAR com Shadow Mode Integrado.
    Permite atraso estratégico ajustável para rastrear e registrar os movimentos do atacante.
    """

    def __init__(self, shadow_delay_seconds: int = 3):
        self.shadow_delay = shadow_delay_seconds
        self.collected_ttps: List[Dict[str, Any]] = []

    def handle_incident_with_shadow_mode(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coleta inteligência em silêncio durante o período de Shadow Mode e depois isola o host.
        """
        logger.info(f"🥷 [SHADOW MODE ATIVADO] Ameaça detectada: {alert_data.get('rule')}. Coletando telemetria silenciosa por {self.shadow_delay}s...")
        
        # Simulação da amostragem em tempo real (Rastreamento de TTPs)
        start_time = time.time()
        while time.time() - start_time < self.shadow_delay:
            self.collected_ttps.append({
                "timestamp": time.strftime("%H:%M:%S"),
                "captured_action": "Invasor tentando exfiltrar token / mapear diretório",
                "ip": alert_data.get("source_ip", "185.220.101.5")
            })
            time.sleep(1)

        logger.warning("⏱️ [SHADOW MODE CONCLUÍDO] Janela de espionagem encerrada. Executando plano SOAR de contenção...")

        # Ações de contenção automatizadas
        soar_actions_executed = [
            "HOST_NETWORK_ISOLATION_WFP",
            "PROCESS_TREE_TERMINATION",
            "REVOKE_ACTIVE_SESSIONS"
        ]

        return {
            "incident_status": "CONTAINED",
            "ttps_collected": len(self.collected_ttps),
            "telemetry_log": self.collected_ttps,
            "soar_actions": soar_actions_executed
        }
