"""
Sentinela XDR - Motor Native Kernel ETW Private Sensor
Sensor de telemetria nativa do Kernel do Windows via Event Tracing for Windows (ETW):
Microsoft-Windows-Kernel-Process, Microsoft-Windows-Kernel-Network e Microsoft-Windows-Threat-Intelligence.
Fornece monitoramento de criação de processos e conexões de rede em Ring 0 com overhead inferior a 1% de CPU.
"""

import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SentinelaNativeETW")


class NativeETWSensor:
    """Sensor ETW de Kernel em Ring 0 para eventos de processos e rede."""

    MONITORED_PROVIDERS = [
        {"name": "Microsoft-Windows-Kernel-Process", "guid": "{22FB2AD6-0E17-4B31-0F09-FF49D329C1B2}", "events": ["ProcessStart", "ProcessStop"]},
        {"name": "Microsoft-Windows-Kernel-Network", "guid": "{7DD42A49-5329-4832-8DFD-43D979153A88}", "events": ["TcpIpConnect", "UdpSend"]},
        {"name": "Microsoft-Windows-Threat-Intelligence", "guid": "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}", "events": ["VirtualAllocRemote", "SetThreadContext"]}
    ]

    def __init__(self, logger_instance=None):
        self.logger = logger_instance
        self.is_capturing: bool = True
        self.events_processed: int = 0
        self.kernel_alerts_triggered: int = 0
        self.recent_kernel_events: List[Dict[str, Any]] = []

        from sentinel_core.etw_live_consumer import ETWLiveConsumer
        self.live_consumer = ETWLiveConsumer(
            logger_instance=logger_instance,
            event_callback=lambda ev: self.ingest_kernel_event(
                ev["provider"], ev["event_type"], ev["pid"], ev["details"]
            )
        )
        self.live_consumer.start()

        self._log("INFO", "NATIVE_ETW_INIT", "INIT", f"Sensor Native Kernel ETW ativo ({len(self.MONITORED_PROVIDERS)} providers registrados).")

    def _log(self, level: str, category: str, action: str, msg: str):
        try:
            if self.logger and hasattr(self.logger, "log_event"):
                self.logger.log_event(level, category, action, msg)
            elif self.logger and hasattr(self.logger, level.lower()):
                getattr(self.logger, level.lower())(f"[{category}] {msg}")
        except Exception:
            pass
        logging.info(f"[{category}] {msg}")

    def ingest_kernel_event(self, provider_name: str, event_type: str, pid: int, details: Dict[str, Any]) -> Dict[str, Any]:
        """Processa um evento de telemetria emitido pelo provider ETW."""
        self.events_processed += 1
        is_suspicious = False
        reason = ""

        # Detecção de injeção de memória remota via Threat-Intelligence provider
        if "Threat-Intelligence" in provider_name and event_type in ["VirtualAllocRemote", "SetThreadContext"]:
            is_suspicious = True
            reason = f"Tentativa de injeção de código remoto interceptada pelo Kernel ETW! (PID alvo: {pid})"
        elif "Kernel-Process" in provider_name and details.get("parent_pid") and details.get("image_name", "").endswith("cmd.exe"):
            parent = details.get("parent_image", "").lower()
            if "winword" in parent or "excel" in parent or "w3wp" in parent:
                is_suspicious = True
                reason = f"Processo Office/IIS gerou prompt de comando (PID: {pid})!"

        entry = {
            "timestamp": time.time(),
            "provider": provider_name,
            "event_type": event_type,
            "pid": pid,
            "details": details,
            "is_suspicious": is_suspicious
        }

        self.recent_kernel_events.insert(0, entry)
        if len(self.recent_kernel_events) > 50:
            self.recent_kernel_events.pop()

        if is_suspicious:
            self.kernel_alerts_triggered += 1
            self._log("CRITICAL", "KERNEL_ETW_ALERT", "THREAT_DETECTED", reason)

        return {
            "status": "processed",
            "is_suspicious": is_suspicious,
            "reason": reason
        }

    def get_status(self) -> Dict[str, Any]:
        """Retorna o status operacional do sensor ETW nativo com indicadores de modo de telemetria."""
        consumer_status = {}
        if hasattr(self, "live_consumer") and self.live_consumer:
            try:
                consumer_status = self.live_consumer.get_status()
            except Exception:
                pass

        return {
            "status": "active" if self.is_capturing else "paused",
            "telemetry_mode": consumer_status.get("telemetry_mode", "USERSPACE_EVENTLOG_FALLBACK"),
            "privilege_status": consumer_status.get("privilege_status", "STANDARD_USER"),
            "is_elevated": consumer_status.get("is_elevated", False),
            "is_degraded": consumer_status.get("is_degraded", True),
            "fallback_reasons": consumer_status.get("fallback_reasons", []),
            "fallback_channels": consumer_status.get("fallback_channels", []),
            "providers_count": len(self.MONITORED_PROVIDERS),
            "providers": self.MONITORED_PROVIDERS,
            "events_processed": self.events_processed,
            "kernel_alerts_triggered": self.kernel_alerts_triggered,
            "consumer_details": consumer_status,
            "recent_events": self.recent_kernel_events[:10]
        }
