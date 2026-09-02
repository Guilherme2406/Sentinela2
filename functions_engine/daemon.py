# functions_engine/daemon.py
"""Daemon de Monitoramento Contínuo e Gestão de Alarmes (Trigger Watcher).

Executa varreduras em segundo plano sobre o buffer de telemetria do Functions Engine,
avaliando triggers contínuas, gerenciando transições de estado (OK <-> PROBLEM),
suprimindo flapping e disparando contramedidas auditadas no Sentinela XDR.
"""
from __future__ import annotations

import time
import uuid
import logging
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

from functions_engine.core import SecurityItem


@dataclass
class TriggerRule:
    """Representa uma regra de trigger contínua registrada no motor."""

    id: str
    name: str
    expression: str
    severity: str = "HIGH"  # INFO, WARNING, HIGH, DISASTER
    description: str = ""
    enabled: bool = True
    status: str = "OK"  # OK ou PROBLEM
    last_eval_time: float = 0.0
    last_fired_time: float = 0.0
    fire_count: int = 0
    consecutive_fires: int = 0
    required_consecutive: int = 1  # Histerese: ciclos consecutivos necessários para virar PROBLEM
    last_value: Any = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "expression": self.expression,
            "severity": self.severity,
            "description": self.description,
            "enabled": self.enabled,
            "status": self.status,
            "last_eval_time": self.last_eval_time,
            "last_fired_time": self.last_fired_time,
            "fire_count": self.fire_count,
            "consecutive_fires": self.consecutive_fires,
            "last_value": self.last_value,
            "created_at": self.created_at,
        }


class TriggerWatchDaemon:
    """Observador contínuo em background para avaliação autônoma de triggers e emissão de alarmes."""

    DEFAULT_PRESETS = [
        {
            "id": "PRESET_ZTNA_RISK",
            "name": "Risco Crítico CARTA ZTNA",
            "expression": "last(\"sentinel.ztna.risk_score\") >= 75",
            "severity": "DISASTER",
            "description": "Dispara quando a postura de risco adaptativo CARTA ultrapassa o limiar tolerável.",
            "required_consecutive": 1,
        },
        {
            "id": "PRESET_POSTURE_DEGRADED",
            "name": "Degradação de Hardening CIS",
            "expression": "last(\"sentinel.posture.hardening_score\") < 80",
            "severity": "HIGH",
            "description": "Alerta sobre desativação indevida de UAC, Defender ou credenciais RDP NLA.",
            "required_consecutive": 1,
        },
        {
            "id": "PRESET_MASS_BRUTEFORCE",
            "name": "Ataque Massivo / Força Bruta",
            "expression": "change(\"sentinel.banned_ips.count\") >= 3",
            "severity": "HIGH",
            "description": "Detecta súbito aumento de IPs invasores banidos no Firewall em janela curta.",
            "required_consecutive": 1,
        },
        {
            "id": "PRESET_HOST_EXHAUSTION",
            "name": "Esgotamento Crítico de Recursos Host",
            "expression": "last(\"system.cpu.util\") > 90 and last(\"system.memory.util\") > 85",
            "severity": "WARNING",
            "description": "Identifica pressão combinada severa sobre a CPU e memória RAM do computador.",
            "required_consecutive": 2,
        },
        {
            "id": "PRESET_CONN_BURST",
            "name": "Surto Anômalo de Conexões de Rede",
            "expression": "last(\"system.net.connections\") > 500",
            "severity": "HIGH",
            "description": "Alerta de pico anômalo de conexões simultâneas (possível DDoS ou C2 exfiltration).",
            "required_consecutive": 1,
        },
    ]

    def __init__(
        self,
        engine: Any,
        logger: Optional[Any] = None,
        soar: Optional[Any] = None,
        eval_interval: float = 5.0,
    ):
        self.engine = engine
        self.logger = logger
        self.soar = soar
        self.eval_interval = eval_interval
        self._rules: Dict[str, TriggerRule] = {}
        self._alarm_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # Registra presets recomendados por padrão
        self._load_default_presets()

    def _load_default_presets(self) -> None:
        """Carrega os presets padrão no inicializar."""
        for p in self.DEFAULT_PRESETS:
            rule = TriggerRule(
                id=p["id"],
                name=p["name"],
                expression=p["expression"],
                severity=p["severity"],
                description=p["description"],
                required_consecutive=p.get("required_consecutive", 1),
            )
            self._rules[rule.id] = rule

    # ------------------------------------------------------------------
    # Gerenciamento de Regras
    # ------------------------------------------------------------------
    def register_rule(
        self,
        name: str,
        expression: str,
        severity: str = "HIGH",
        description: str = "",
        required_consecutive: int = 1,
        rule_id: Optional[str] = None,
    ) -> TriggerRule:
        """Cadastra uma nova regra de trigger persistente para monitoramento contínuo."""
        rid = rule_id or f"rule_{uuid.uuid4().hex[:8]}"
        rule = TriggerRule(
            id=rid,
            name=name,
            expression=expression,
            severity=severity,
            description=description,
            required_consecutive=max(1, required_consecutive),
        )
        with self._lock:
            self._rules[rid] = rule
        logging.info(f"📊 [FUNCTIONS-DAEMON] Nova regra registrada: '{name}' [{expression}]")
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove uma regra cadastrada."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                return True
        return False

    def list_rules(self) -> List[Dict[str, Any]]:
        """Retorna todas as regras cadastradas e seus estados."""
        with self._lock:
            return [r.to_dict() for r in self._rules.values()]

    def get_active_problems(self) -> List[Dict[str, Any]]:
        """Retorna apenas as regras que estão disparadas no momento (status PROBLEM)."""
        with self._lock:
            return [r.to_dict() for r in self._rules.values() if r.status == "PROBLEM"]

    def get_alarm_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retorna o histórico recente de transições de alarme."""
        with self._lock:
            return list(reversed(self._alarm_history[-limit:]))

    # ------------------------------------------------------------------
    # Ciclo de Avaliação
    # ------------------------------------------------------------------
    def run_cycle(self) -> Dict[str, Any]:
        """Executa um ciclo completo de avaliação sobre todas as regras ativas."""
        now = time.time()
        evaluated = 0
        problems_count = 0

        with self._lock:
            rules_to_eval = list(self._rules.values())

        for rule in rules_to_eval:
            if not rule.enabled:
                continue

            evaluated += 1
            rule.last_eval_time = now
            fired = False
            try:
                fired = bool(self.engine.evaluate_trigger(rule.expression))
            except Exception as e:
                logging.debug(f"[FUNCTIONS-DAEMON] Erro ao avaliar regra '{rule.name}': {e}")
                fired = False

            old_status = rule.status

            if fired:
                rule.consecutive_fires += 1
                rule.fire_count += 1
                rule.last_fired_time = now

                # Aplica histerese: requer N ciclos consecutivos verdadeiros
                if rule.consecutive_fires >= rule.required_consecutive:
                    rule.status = "PROBLEM"
                    problems_count += 1

                    # Se transitou de OK para PROBLEM, registra o incidente
                    if old_status != "PROBLEM":
                        event_record = {
                            "timestamp": now,
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "expression": rule.expression,
                            "severity": rule.severity,
                            "transition": "OK_TO_PROBLEM",
                            "message": f"🚨 ALARME DISPARADO: {rule.name} [{rule.expression}]",
                        }
                        self._record_alarm_event(event_record)
                else:
                    if rule.status == "PROBLEM":
                        problems_count += 1
            else:
                rule.consecutive_fires = 0
                rule.status = "OK"

                # Se transitou de PROBLEM para OK, registra a resolução
                if old_status == "PROBLEM":
                    event_record = {
                        "timestamp": now,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "expression": rule.expression,
                        "severity": rule.severity,
                        "transition": "PROBLEM_TO_RESOLVED",
                        "message": f"🟢 ALARME RESOLVIDO: {rule.name} normalizado.",
                    }
                    self._record_alarm_event(event_record)

        return {
            "status": "success",
            "timestamp": now,
            "evaluated": evaluated,
            "active_problems": problems_count,
        }

    def _record_alarm_event(self, event: Dict[str, Any]) -> None:
        """Armazena o evento de alarme e notifica o logger central de segurança."""
        with self._lock:
            self._alarm_history.append(event)
            if len(self._alarm_history) > 200:
                self._alarm_history.pop(0)

        if self.logger and hasattr(self.logger, "log_event"):
            try:
                sev = "CRITICAL" if event["severity"] == "DISASTER" else ("WARNING" if event["severity"] == "HIGH" else "INFO")
                self.logger.log_event(
                    sev,
                    "TELEMETRY_ALARM",
                    event["rule_name"],
                    event["message"],
                )
            except Exception as e:
                logging.debug(f"[FUNCTIONS-DAEMON] Erro ao registrar log de segurança: {e}")

    # ------------------------------------------------------------------
    # Controle de Vida do Daemon
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Inicia a thread de monitoramento contínuo em segundo plano."""
        if self._running:
            return
        self._running = True

        def _loop():
            logging.info("⚡ [FUNCTIONS-DAEMON] Observador contínuo de triggers ativado.")
            while self._running:
                try:
                    self.run_cycle()
                except Exception as e:
                    logging.debug(f"[FUNCTIONS-DAEMON] Erro no loop de avaliação: {e}")
                time.sleep(self.eval_interval)

        self._thread = threading.Thread(target=_loop, daemon=True, name="TriggerWatchDaemon")
        self._thread.start()

    def stop(self) -> None:
        """Para a thread de monitoramento contínuo."""
        self._running = False
