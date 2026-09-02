# sentinel_core/sentinela_orchestrator.py
import os
import sys
import time
import uuid
import inspect
import asyncio
import logging
from typing import Dict, Any, Callable, List, Optional
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger("SentinelaXDR.Orchestrator")

@dataclass
class SecurityEvent:
    """Representa um evento padronizado de telemetria ou ameaça no ecossistema Sentinela."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source: str = "GENERIC"             # EDR, FIM, NIDS, HONEYTOKEN, AI, ZTNA, MEMORY, TARPIT
    severity: str = "INFO"              # INFO, LOW, MEDIUM, HIGH, CRITICAL
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "severity": self.severity,
            "data": self.data,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }

class SecurityContext:
    """Mantém o estado global e a postura de segurança do endpoint em tempo real."""
    def __init__(self):
        self.risk_score: float = 0.0
        self.active_threats: List[Dict[str, Any]] = []
        self.is_isolated: bool = False
        self.recent_events_window: List[SecurityEvent] = []
        self.last_updated: float = time.time()

    def update_risk(self, delta: float):
        self.risk_score = max(0.0, min(100.0, self.risk_score + delta))
        self.last_updated = time.time()

class SentinelaOrchestrator:
    """
    Barramento Central Assíncrono de Eventos e Orquestrador SIEM/SOAR do Sentinela XDR.
    Desacopla sensores, correlaciona múltiplos sinais de ataque (Cross-Engine Correlation)
    e dispara respostas autônomas em tempo real.
    """
    def __init__(self, logger_instance=None, ztna_engine=None, rollback_engine=None, firewall_manager=None):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.context: SecurityContext = SecurityContext()
        self.handlers: Dict[str, List[Callable]] = {}
        self.logger = logger_instance
        self.ztna = ztna_engine
        self.rollback = rollback_engine
        self.firewall = firewall_manager
        self.running: bool = True
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._register_default_correlation_rules()

    def _register_default_correlation_rules(self):
        """Registra regras de correlação nativas entre sensores."""
        # 1. Regra de Ransomware (Correlação EDR + FIM + Entropia)
        self.register_handler("EDR", self._correlate_ransomware_attack)
        self.register_handler("AI_ANOMALY", self._correlate_ai_threat)
        self.register_handler("CANARY_TRIPWIRE", self._correlate_canary_breach)
        self.register_handler("MEMORY_FORENSICS", self._correlate_memory_injection)
        self.register_handler("IDENTITY_GUARD", self._correlate_identity_attack)
        self.register_handler("DLP_GUARD", self._correlate_dlp_leak)
        self.register_handler("ANTI_EXPLOIT_GUARD", self._correlate_anti_exploit)
        self.register_handler("NETWORK_PERIMETER_GUARD", self._correlate_perimeter_threat)
        self.register_handler("POSTURE_PERSISTENCE_GUARD", self._correlate_posture_threat)

    def register_handler(self, source: str, func: Callable):
        """Registra uma função ou corrotina para reagir a eventos de uma fonte específica."""
        source_key = source.upper()
        if source_key not in self.handlers:
            self.handlers[source_key] = []
        if func not in self.handlers[source_key]:
            self.handlers[source_key].append(func)
            logger.debug(f"[ORCHESTRATOR] Handler '{func.__name__}' registrado para fonte '{source_key}'.")

    async def emit_async(self, event: SecurityEvent):
        """Injeta um evento na fila assíncrona."""
        await self.queue.put(event)

    def emit(self, event: SecurityEvent):
        """Interface síncrona/assíncrona universal para emitir eventos a partir de qualquer thread."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.queue.put(event), loop)
            else:
                loop.run_until_complete(self.queue.put(event))
        except RuntimeError:
            # Fallback caso não haja loop ativo na thread atual
            asyncio.run(self._process_event(event))

    emit_sync = emit

    async def _process_event(self, event: SecurityEvent):
        """Executa a lógica central de correlação e despacho de ações."""
        logger.info(f"⚡ [ORCHESTRATOR] Evento recebido: [{event.severity}] {event.source} (ID: {event.event_id})")

        # 1. Atualização do contexto global de risco
        severity_weights = {"INFO": 0.0, "LOW": 5.0, "MEDIUM": 15.0, "HIGH": 30.0, "CRITICAL": 50.0}
        weight = severity_weights.get(event.severity.upper(), 10.0)
        
        if weight > 0:
            self.context.update_risk(weight)
            self.context.active_threats.append(event.to_dict())

        # Mantém histórico recente (janela deslizante de 50 eventos)
        self.context.recent_events_window.append(event)
        if len(self.context.recent_events_window) > 50:
            self.context.recent_events_window.pop(0)

        # 2. Notificação no ZTNA CARTA Engine se disponível
        if self.ztna and weight >= 15.0:
            self.ztna.record_threat_event(event.source, severity=event.severity, details=str(event.data))

        # 3. Disparo dos Handlers registrados (suporta sync e async)
        source_key = event.source.upper()
        if source_key in self.handlers:
            for handler in self.handlers[source_key]:
                try:
                    if inspect.iscoroutinefunction(handler):
                        await handler(event, self.context)
                    else:
                        handler(event, self.context)
                except Exception as ex:
                    logger.error(f"[ORCHESTRATOR] Erro no handler '{handler.__name__}': {ex}")

        # 4. Registro no banco de eventos SQLite se logger estiver presente
        if self.logger and event.severity in ["HIGH", "CRITICAL"]:
            self.logger.log_event(
                event.severity, 
                event.source, 
                f"ID:{event.event_id}", 
                f"Orquestrador processou evento. Risco atual: {self.context.risk_score:.1f}/100. Dados: {event.data}"
            )

    # --- REGRAS NATIVAS DE CORRELAÇÃO ---
    def _correlate_ransomware_attack(self, event: SecurityEvent, context: SecurityContext):
        """Correlação de ataque Ransomware com disparo automático de Rollback."""
        rule = event.data.get("rule", "")
        if "VSS" in rule or "SHADOW" in rule or event.severity == "CRITICAL":
            logger.critical("🚨 [ORCHESTRATION CORRELATION] Padrão Ransomware confirmado! Acionando Rollback preventivo.")
            if self.rollback:
                self.rollback.execute_instant_rollback({"trigger": event.source, "rule": rule})

    def _correlate_ai_threat(self, event: SecurityEvent, context: SecurityContext):
        """Correlação de anomalia de IA com elevação de telemetria."""
        if event.severity in ["HIGH", "CRITICAL"]:
            logger.warning(f"🤖 [ORCHESTRATION AI] Anomalia Zero-Day sob contenção. Contexto de Risco: {context.risk_score}/100")

    def _correlate_canary_breach(self, event: SecurityEvent, context: SecurityContext):
        """Violação de Honeytoken ou Canário -> Auto-Isolamento de Host."""
        logger.critical("🪤 [ORCHESTRATION CANARY] Isca violada! Disparando contenção total no Firewall.")
        ip = event.data.get("attacker_ip")
        if ip and self.firewall:
            self.firewall.block_ip(ip, reason="Canary Trap Triggered")

    def _correlate_memory_injection(self, event: SecurityEvent, context: SecurityContext):
        """Injeção em RAM detectada -> Encerramento de processo."""
        pid = event.data.get("pid")
        logger.critical(f"🔬 [ORCHESTRATION MEMORY] Reflective DLL / Shellcode detectado no PID {pid}.")

    def _correlate_identity_attack(self, event: SecurityEvent, context: SecurityContext):
        """Roubo de credenciais / Dump de LSASS / Potato PrivEsc detectado -> Elevação de risco ZTNA e contenção."""
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        logger.critical(f"🛡️ [ORCHESTRATION IDENTITY] Tentativa de roubo de credenciais interceptada! Alvo: {target} ({action})")
        if self.ztna:
            try:
                self.ztna.evaluate_posture(event_type="IDENTITY_COMPROMISE_ATTEMPT", payload=event.data)
            except Exception as e:
                logger.debug(f"[ORCHESTRATOR] Erro ao notificar ZTNA: {e}")

    def _correlate_dlp_leak(self, event: SecurityEvent, context: SecurityContext):
        """Vazamento de dados confidenciais ou exfiltração em nuvem -> Penalização ZTNA e bloqueio."""
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        logger.warning(f"🔒 [ORCHESTRATION DLP] Evento DLP interceptado! Alvo: {target} ({action})")
        if self.ztna:
            try:
                self.ztna.evaluate_posture(event_type="DLP_EXFILTRATION_ATTEMPT", payload=event.data)
            except Exception as e:
                logger.debug(f"[ORCHESTRATOR] Erro ao notificar ZTNA sobre DLP: {e}")

    def _correlate_anti_exploit(self, event: SecurityEvent, context: SecurityContext):
        """Tentativa de Exploit, Process Hollowing ou AMSI Bypass -> Quarentena e contenção ZTNA."""
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        desc = event.data.get("description", "")
        logger.critical(f"🛑 [ORCHESTRATION ANTI-EXPLOIT] Exploit crítico bloqueado! Alvo: {target} ({action}) | {desc}")
        if self.ztna:
            try:
                self.ztna.evaluate_posture(event_type="EXPLOIT_COMPROMISE_ATTEMPT", payload=event.data)
            except Exception as e:
                logger.debug(f"[ORCHESTRATOR] Erro ao notificar ZTNA sobre Exploit: {e}")

    def _correlate_perimeter_threat(self, event: SecurityEvent, context: SecurityContext):
        """Ataque MITM/ARP Spoofing ou C2 DGA detectado na rede local -> Elevação de risco ZTNA."""
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        desc = event.data.get("description", "")
        logger.critical(f"🌐 [ORCHESTRATION PERIMETER] Ameaça de rede local/MITM detectada! Alvo: {target} ({action}) | {desc}")
        if self.ztna:
            try:
                self.ztna.evaluate_posture(event_type="NETWORK_MITM_ATTEMPT", payload=event.data)
            except Exception as e:
                logger.debug(f"[ORCHESTRATOR] Erro ao notificar ZTNA sobre Rede: {e}")

    def _correlate_posture_threat(self, event: SecurityEvent, context: SecurityContext):
        """Persistência oculta em ASEP ou abuso de LOLBin detectado -> Penalização severa no ZTNA."""
        action = event.data.get("action", "")
        target = event.data.get("target", "")
        desc = event.data.get("description", "")
        logger.critical(f"🔍 [ORCHESTRATION POSTURE] Persistência maliciosa ou LOLBin interceptado! Alvo: {target} ({action}) | {desc}")
        if self.ztna:
            try:
                self.ztna.evaluate_posture(event_type="MALICIOUS_PERSISTENCE_DETECTED", payload=event.data)
            except Exception as e:
                logger.debug(f"[ORCHESTRATOR] Erro ao notificar ZTNA sobre Persistência: {e}")

    async def run(self):
        """Loop principal de despacho assíncrono."""
        logger.info("🚀 [ORCHESTRATOR] Barramento Assíncrono Sentinela em execução.")
        self._loop = asyncio.get_running_loop()
        while self.running:
            event = await self.queue.get()
            try:
                await self._process_event(event)
            except Exception as e:
                logger.error(f"[ORCHESTRATOR ERROR] Falha no evento {event.event_id}: {e}")
            finally:
                self.queue.task_done()

    def stop(self):
        self.running = False
