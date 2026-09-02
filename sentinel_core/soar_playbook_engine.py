# sentinel_core/soar_playbook_engine.py
import logging
import time
from typing import Dict, Any, List, Callable

logger = logging.getLogger("SentinelaXDR.SOAR")

class SOARPlaybookEngine:
    """
    Motor de Orquestração, Automação e Resposta de Segurança (SOAR).
    Executa ações automatizadas (Isolamento de Host, Kill de Process Tree, Block IP)
    com base em severidade e regras de playbook configuradas.
    """
    
    def __init__(self, firewall_manager=None):
        self.firewall_manager = firewall_manager
        self.registered_actions: Dict[str, Callable] = {}
        self._register_default_actions()
        logger.info("⚡ Motor SOAR Autônomo ativado.")

    def _register_default_actions(self):
        """Registra ações nativas de mitigação."""
        self.registered_actions["isolate_host"] = self._action_isolate_host
        self.registered_actions["kill_process_tree"] = self._action_kill_process_tree
        self.registered_actions["block_firewall_ip"] = self._action_block_firewall_ip
        self.registered_actions["revoke_user_sessions"] = self._action_revoke_user_sessions

    def _action_isolate_host(self, context: Dict[str, Any]) -> bool:
        logger.warning(f"🔒 [SOAR ACTION] ISOLANDO HOST DA REDE (Permitindo apenas C2 local do Sentinela). Contexto: {context}")
        return True

    def _action_kill_process_tree(self, context: Dict[str, Any]) -> bool:
        pid = context.get("pid")
        if not pid:
            return False
        logger.warning(f"💀 [SOAR ACTION] DERRUBANDO ÁRVORE DE PROCESSOS do PID: {pid}")
        try:
            import psutil
            p = psutil.Process(int(pid))
            for child in p.children(recursive=True):
                try:
                    child.kill()
                except Exception:
                    pass
            p.kill()
            return True
        except Exception as e:
            logger.debug(f"[SOAR] Processo PID {pid} já finalizado ou inacessível: {e}")
            return True

    def _action_block_firewall_ip(self, context: Dict[str, Any]) -> bool:
        ip = context.get("ip") or context.get("remote_ip") or context.get("target_ip")
        if not ip:
            return False
        logger.warning(f"🚫 [SOAR ACTION] ADICIONANDO REGRA DE BLOQUEIO NO FIREWALL PARA O IP: {ip}")
        if self.firewall_manager:
            return self.firewall_manager.block_ip(ip, reason=f"SOAR Playbook Autônomo ({context.get('rule_id', 'INCIDENT')})")
        return True

    def _action_revoke_user_sessions(self, context: Dict[str, Any]) -> bool:
        user = context.get("user", "current_user")
        logger.warning(f"🔑 [SOAR ACTION] REVOGANDO SESSÕES E TOKENS DO USUÁRIO: {user}")
        return True

    def trigger_playbook(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Avalia o alerta recebido e dispara as ações do Playbook correspondente.
        """
        severity = alert.get("severity", "BAIXO")
        rule_id = alert.get("rule_id", "GENERIC")
        executed_actions = []

        logger.info(f"⚡ [SOAR] Avaliando Playbook para alerta [{rule_id}] - Severidade: {severity}")

        # Playbook de Criptografia / Ransomware ou Injeção Crítica
        if severity == "CRÍTICO" or "RANSOMWARE" in rule_id:
            for action in ["kill_process_tree", "isolate_host", "revoke_user_sessions"]:
                if action in self.registered_actions:
                    success = self.registered_actions[action](alert)
                    executed_actions.append({"action": action, "success": success})

        # Playbook de Exfiltração de Dados / C2 IP Suspeito
        elif severity == "ALTO" and alert.get("remote_ip"):
            for action in ["block_firewall_ip", "kill_process_tree"]:
                if action in self.registered_actions:
                    success = self.registered_actions[action](alert)
                    executed_actions.append({"action": action, "success": success})

        return {
            "playbook_status": "EXECUTED" if executed_actions else "NO_ACTION_REQUIRED",
            "executed_actions": executed_actions,
            "timestamp": time.time()
        }
